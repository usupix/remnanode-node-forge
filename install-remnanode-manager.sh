#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 python3-yaml nginx certbot openssl ca-certificates curl

if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends docker-compose-v2
  else
    apt-get install -y --no-install-recommends docker-compose-plugin
  fi
fi
systemctl enable --now docker nginx

install -d -m 0750 /opt/remnanode-manager
install -d -m 0700 /var/lib/remnanode-manager/backups /var/lib/remnanode-manager/generated
install -d -m 0755 /var/www/remnanode-manager-acme/.well-known/acme-challenge
install -d -m 0755 /var/www/remnanode-decoy
install -d -m 0755 /var/lib/remnawave/configs/xray/ssl

cat > /opt/remnanode-manager/app.py <<'PY'
#!/usr/bin/env python3
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

APP_DIR = Path("/opt/remnanode-manager")
STATE_DIR = Path("/var/lib/remnanode-manager")
BACKUP_DIR = STATE_DIR / "backups"
GENERATED_DIR = STATE_DIR / "generated"
COMPOSE_DIR = Path("/opt/remnanode")
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"
SSL_DIR = Path("/var/lib/remnawave/configs/xray/ssl")
SYSCTL_BBR = Path("/etc/sysctl.d/99-vpn-bbr.conf")
SYSCTL_TUNE = Path("/etc/sysctl.d/99-remnanode-manager-network.conf")
ADMIN_PASSWORD = os.environ["RNM_ADMIN_PASSWORD"]
SESSION_SECRET = os.environ["RNM_SESSION_SECRET"].encode()
BIND = os.getenv("RNM_BIND", "127.0.0.1")
PORT = int(os.getenv("RNM_PORT", "8765"))
DOMAIN_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
TAG_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}$")
attempts = {}


def run(args, *, cwd=None, timeout=300, check=True):
    result = subprocess.run(
        args, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=timeout, check=False,
    )
    if check and result.returncode:
        raise RuntimeError(result.stdout.strip()[-4000:] or f"Command failed: {args[0]}")
    return result.stdout.strip()


def atomic_write(path: Path, data: str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(data, encoding="utf-8")
    os.chmod(temp, mode)
    os.replace(temp, path)


def backup(paths, label):
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target = BACKUP_DIR / f"{stamp}-{label}"
    target.mkdir(parents=True, exist_ok=False)
    os.chmod(target, 0o700)
    for path in paths:
        path = Path(path)
        if path.exists():
            shutil.copy2(path, target / path.name)
    return target


def session_token():
    return hmac.new(SESSION_SECRET, b"admin-session-v1", hashlib.sha256).hexdigest()


def csrf_token():
    return hmac.new(SESSION_SECRET, (session_token() + ":csrf").encode(), hashlib.sha256).hexdigest()


def redact(text):
    text = re.sub(r'(?im)(SECRET_KEY\s*[=:]\s*)["\']?[^"\'\s]+', r'\1[hidden]', text)
    text = re.sub(r'(?i)(token=)[A-Za-z0-9_-]+', r'\1[hidden]', text)
    return text


def status_data():
    docker_version = run(["docker", "version", "--format", "{{.Server.Version}}"], check=False, timeout=15) or "not installed"
    compose_version = run(["docker", "compose", "version", "--short"], check=False, timeout=15) or "not installed"
    state = "not created"
    image = "—"
    restarts = "0"
    inspect = run([
        "docker", "inspect", "remnanode", "--format",
        "{{.State.Status}}|{{.Config.Image}}|{{.RestartCount}}"
    ], check=False, timeout=15)
    if inspect and "|" in inspect:
        state, image, restarts = inspect.split("|", 2)
    bbr = run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"], check=False, timeout=10) or "unknown"
    qdisc = run(["sysctl", "-n", "net.core.default_qdisc"], check=False, timeout=10) or "unknown"
    public_ip = "unknown"
    try:
        public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=4).read().decode().strip()
    except Exception:
        pass
    compose_hash = "—"
    if COMPOSE_FILE.exists():
        compose_hash = hashlib.sha256(COMPOSE_FILE.read_bytes()).hexdigest()[:12]
    certs = sorted(p.stem for p in SSL_DIR.glob("*.pem"))
    logs = run(["docker", "logs", "--tail", "35", "remnanode"], check=False, timeout=15)
    return {
        "docker": docker_version, "compose": compose_version, "state": state,
        "image": image, "restarts": restarts, "bbr": bbr, "qdisc": qdisc,
        "public_ip": public_ip, "compose_hash": compose_hash, "certs": certs,
        "logs": redact(logs[-7000:]),
    }


def apply_compose(form):
    raw = form.get("compose", [""])[0].strip()
    if not raw:
        raise ValueError("Paste docker-compose.yml first.")
    if len(raw.encode()) > 900_000:
        raise ValueError("Compose file is too large.")
    config = yaml.safe_load(raw)
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("Compose must contain a services object.")
    service = config["services"].get("remnanode")
    if not isinstance(service, dict):
        raise ValueError("Service remnanode was not found.")
    if form.get("cert_volume") == ["1"]:
        volumes = service.setdefault("volumes", [])
        if not isinstance(volumes, list):
            raise ValueError("remnanode.volumes must be a list.")
        mount = "/var/lib/remnawave/configs/xray/ssl:/var/lib/remnawave/configs/xray/ssl:ro"
        if not any(str(item).split(":", 1)[0] == str(SSL_DIR) for item in volumes):
            volumes.append(mount)
    rendered = yaml.safe_dump(config, sort_keys=False, allow_unicode=True, width=4096)
    COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = COMPOSE_DIR / ".docker-compose.candidate.yml"
    atomic_write(tmp, rendered)
    run(["docker", "compose", "-f", str(tmp), "config", "-q"], timeout=30)
    saved = backup([COMPOSE_FILE], "compose")
    os.replace(tmp, COMPOSE_FILE)
    os.chmod(COMPOSE_FILE, 0o600)
    if form.get("pull") == ["1"]:
        run(["docker", "compose", "pull"], cwd=COMPOSE_DIR, timeout=900)
    run(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR, timeout=300)
    return f"Compose applied. Backup: {saved}"


def nginx_http_config(domain):
    return f'''server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    root /var/www/remnanode-decoy/{domain};
    index index.html;

    location ^~ /.well-known/acme-challenge/ {{
        root /var/www/remnanode-manager-acme;
        default_type text/plain;
        try_files $uri =404;
    }}
    location / {{ try_files $uri $uri/ /index.html; }}
}}
'''


def nginx_tls_config(domain):
    return nginx_http_config(domain) + f'''
server {{
    listen 127.0.0.1:8443 ssl;
    server_name {domain};
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:RNMSSL:10m;
    ssl_session_timeout 1d;
    root /var/www/remnanode-decoy/{domain};
    index index.html;
    location / {{ try_files $uri $uri/ /index.html; }}
}}
'''


def sync_certificate(domain):
    lineage = Path("/etc/letsencrypt/live") / domain
    if not (lineage / "fullchain.pem").exists():
        raise RuntimeError("Let's Encrypt files were not created.")
    shutil.copyfile(lineage / "fullchain.pem", SSL_DIR / f"{domain}.pem", follow_symlinks=True)
    shutil.copyfile(lineage / "privkey.pem", SSL_DIR / f"{domain}.key", follow_symlinks=True)
    os.chmod(SSL_DIR / f"{domain}.pem", 0o644)
    os.chmod(SSL_DIR / f"{domain}.key", 0o600)


def issue_certificate(form):
    domain = form.get("domain", [""])[0].strip().lower().rstrip(".")
    email = form.get("email", [""])[0].strip()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Enter a valid public domain name.")
    if "@" not in email or len(email) > 254:
        raise ValueError("Enter a valid email address.")
    addresses = {row[4][0] for row in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)}
    public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode().strip()
    if public_ip not in addresses and form.get("force_dns") != ["1"]:
        raise ValueError(f"DNS points to {', '.join(sorted(addresses)) or 'nothing'}, server IP is {public_ip}.")
    site_root = Path("/var/www/remnanode-decoy") / domain
    site_root.mkdir(parents=True, exist_ok=True)
    atomic_write(site_root / "index.html", f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Control center</title><style>body{{margin:0;background:#0b1320;color:#dce8f4;font:16px system-ui;display:grid;place-items:center;min-height:100vh}}main{{max-width:560px;padding:48px;border:1px solid #294156;background:#101d2c}}small{{color:#6fc9c2}}h1{{font-weight:650;letter-spacing:-.03em}}</style><main><small>SYSTEM ACCESS</small><h1>Administrative gateway</h1><p>The requested service is available to authorized operators.</p></main></html>''', 0o644)
    available = Path("/etc/nginx/sites-available") / f"rnm-{domain}.conf"
    enabled = Path("/etc/nginx/sites-enabled") / available.name
    backup([available], f"nginx-{domain}")
    atomic_write(available, nginx_http_config(domain), 0o644)
    if not enabled.exists():
        enabled.symlink_to(available)
    run(["nginx", "-t"], timeout=20)
    run(["systemctl", "reload", "nginx"], timeout=20)
    run([
        "certbot", "certonly", "--webroot", "-w", "/var/www/remnanode-manager-acme",
        "-d", domain, "--agree-tos", "--email", email, "--non-interactive",
        "--keep-until-expiring",
    ], timeout=600)
    sync_certificate(domain)
    atomic_write(available, nginx_tls_config(domain), 0o644)
    run(["nginx", "-t"], timeout=20)
    run(["systemctl", "reload", "nginx"], timeout=20)
    run(["systemctl", "enable", "--now", "certbot.timer"], check=False, timeout=20)
    if form.get("restart_node") == ["1"] and run(["docker", "inspect", "remnanode"], check=False):
        run(["docker", "restart", "remnanode"], timeout=120)
    return f"Certificate issued: {SSL_DIR}/{domain}.pem and {domain}.key"


def reality_keys():
    output = run(["docker", "exec", "remnanode", "/usr/local/bin/xray", "x25519"], timeout=30)
    private = public = ""
    for line in output.splitlines():
        key = line.split(":", 1)[-1].strip()
        low = line.lower().replace(" ", "")
        if "privatekey:" in low or "privatekey" in low and ":" in line:
            private = key
        if "publickey:" in low or "publickey" in low and ":" in line:
            public = key
        if low.startswith("privatekey:"):
            private = key
        if low.startswith("publickey:"):
            public = key
    if not private or not public:
        tokens = re.findall(r"[A-Za-z0-9_-]{40,48}", output)
        if len(tokens) >= 2:
            private, public = tokens[0], tokens[1]
    if not private or not public:
        raise RuntimeError("Could not parse X25519 keys: " + output[-1000:])
    return private, public


def generate_inbound(form):
    kind = form.get("kind", ["reality"])[0]
    tag = form.get("tag", ["VLESS_REALITY"])[0].strip()
    domain = form.get("inbound_domain", [""])[0].strip().lower()
    port = int(form.get("inbound_port", ["2053"])[0])
    if not TAG_RE.fullmatch(tag) or not DOMAIN_RE.fullmatch(domain) or not 1 <= port <= 65535:
        raise ValueError("Check tag, domain and port.")
    meta = {}
    if kind == "reality":
        private, public = reality_keys()
        short_id = secrets.token_hex(8)
        inbound = {
            "tag": tag, "port": port, "listen": "0.0.0.0", "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "sockopt": {"reusePort": True, "tcpNoDelay": True, "tcpFastOpen": True, "tcpKeepAliveIdle": 60},
                "tcpSettings": {"header": {"type": "none"}, "acceptProxyProtocol": False},
                "realitySettings": {
                    "show": False, "target": "127.0.0.1:8443", "xver": 0,
                    "shortIds": [short_id], "privateKey": private,
                    "serverNames": [domain], "minClientVer": "1.8.2",
                },
            },
        }
        meta = {"publicKey": public, "shortId": short_id}
    elif kind == "hysteria":
        cert = SSL_DIR / f"{domain}.pem"
        key = SSL_DIR / f"{domain}.key"
        if not cert.exists() or not key.exists():
            raise ValueError("Issue the certificate before generating Hysteria.")
        inbound = {
            "tag": tag, "port": port, "listen": "0.0.0.0", "protocol": "hysteria",
            "settings": {"clients": [], "version": 2},
            "streamSettings": {
                "network": "hysteria", "security": "tls",
                "finalmask": {"quicParams": {"debug": False, "congestion": "bbr"}},
                "tlsSettings": {
                    "alpn": ["h3"], "serverName": domain,
                    "certificates": [{"keyFile": str(key), "certificateFile": str(cert)}],
                },
                "hysteriaSettings": {"version": 2},
            },
        }
    else:
        raise ValueError("Unknown inbound type.")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = GENERATED_DIR / f"{stamp}-{tag}.json"
    payload = json.dumps(inbound, ensure_ascii=False, indent=2) + "\n"
    atomic_write(path, payload, 0o600)
    atomic_write(STATE_DIR / "last-inbound.json", payload, 0o600)
    atomic_write(STATE_DIR / "last-meta.json", json.dumps(meta), 0o600)
    return f"Inbound generated: {path}"


def apply_network(form):
    profile = form.get("profile", ["bbr"])[0]
    saved = backup([SYSCTL_BBR, SYSCTL_TUNE], "network")
    atomic_write(SYSCTL_BBR, "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n", 0o644)
    if profile == "balanced":
        atomic_write(SYSCTL_TUNE, """# Conservative VPN transport profile
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.netdev_max_backlog=8192
net.core.somaxconn=8192
net.core.optmem_max=65536
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=262144
net.ipv4.ip_local_port_range=10240 65535
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
""", 0o644)
    elif profile == "bbr":
        atomic_write(SYSCTL_TUNE, "# BBR-only profile selected in RemnaNode Manager.\n", 0o644)
    else:
        raise ValueError("Unknown network profile.")
    run(["modprobe", "tcp_bbr"], timeout=20)
    run(["sysctl", "--system"], timeout=60)
    return f"Network profile {profile} applied. Backup: {saved}"


def node_action(form):
    action = form.get("action", [""])[0]
    if action == "restart":
        run(["docker", "restart", "remnanode"], timeout=120)
        return "RemnaNode restarted."
    if action == "start":
        run(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR, timeout=300)
        return "RemnaNode started."
    if action == "pull":
        run(["docker", "compose", "pull"], cwd=COMPOSE_DIR, timeout=900)
        run(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR, timeout=300)
        return "Image updated and container recreated."
    raise ValueError("Unknown action.")


CSS = r'''
:root{--ink:#07111d;--panel:#0d1d2b;--panel2:#112638;--line:#274359;--text:#dceaf5;--muted:#88a4b8;--cyan:#55d6cf;--amber:#ffb65c;--red:#ff6d78;--mono:ui-monospace,SFMono-Regular,Consolas,monospace;--sans:"Segoe UI Variable",Tahoma,sans-serif}*{box-sizing:border-box}body{margin:0;background:var(--ink);color:var(--text);font:15px/1.5 var(--sans);min-height:100vh}body:before{content:"";position:fixed;inset:0;background:linear-gradient(90deg,transparent 49.8%,rgba(85,214,207,.035) 50%,transparent 50.2%),linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px);background-size:180px 100%,100% 36px;pointer-events:none}.shell{max-width:1220px;margin:auto;padding:28px 24px 80px}.mast{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:24px}.eyebrow,.label{font:700 11px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--cyan)}h1{font-size:clamp(34px,7vw,70px);line-height:.92;letter-spacing:-.055em;margin:10px 0 0;max-width:760px}.rail{display:flex;gap:8px;align-items:center;font-family:var(--mono);font-size:12px;color:var(--muted)}.pulse{width:10px;height:10px;border-radius:50%;background:var(--cyan);box-shadow:0 0 0 6px rgba(85,214,207,.08)}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{grid-column:span 4;background:rgba(13,29,43,.93);border:1px solid var(--line);padding:20px;min-width:0}.card.wide{grid-column:span 8}.card.full{grid-column:1/-1}.card h2{font-size:19px;margin:8px 0 16px;letter-spacing:-.02em}.metric{display:flex;justify-content:space-between;gap:16px;padding:9px 0;border-top:1px solid rgba(39,67,89,.65)}.metric b,.mono,code,pre{font-family:var(--mono)}.ok{color:var(--cyan)}.warn{color:var(--amber)}.error{color:var(--red)}label{display:block;margin:12px 0 6px;color:var(--muted);font-size:13px}input,select,textarea{width:100%;background:#07131f;color:var(--text);border:1px solid #31516a;padding:11px 12px;border-radius:2px;font:14px var(--mono);outline:none}input:focus,select:focus,textarea:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(85,214,207,.09)}textarea{min-height:220px;resize:vertical}.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1 1 180px}.check{display:flex;gap:9px;align-items:center;color:var(--text)}.check input{width:auto}button,.button{background:var(--cyan);color:#061218;border:0;padding:11px 15px;font-weight:750;cursor:pointer;text-decoration:none;display:inline-block}.secondary{background:#173149;color:var(--text);border:1px solid #31516a}.danger{background:var(--red)}button:hover{filter:brightness(1.08)}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}.flash{border-left:4px solid var(--cyan);background:#102a31;padding:12px 15px;margin-bottom:14px}.flash.error{border-color:var(--red);background:#2b1720}.certs{display:flex;gap:7px;flex-wrap:wrap}.pill{font:12px var(--mono);border:1px solid var(--line);padding:5px 8px;color:var(--muted)}pre{white-space:pre-wrap;word-break:break-word;background:#050c13;border:1px solid #20394e;padding:14px;max-height:360px;overflow:auto;color:#b9d3e5}.copybox{position:relative}.copybox button{position:absolute;right:8px;top:8px;padding:6px 9px}.muted{color:var(--muted)}footer{margin-top:26px;color:var(--muted);font:12px var(--mono)}@media(max-width:850px){.card,.card.wide{grid-column:1/-1}.mast{grid-template-columns:1fr}.rail{justify-content:flex-start}}@media(prefers-reduced-motion:no-preference){.pulse{animation:pulse 2.2s infinite}@keyframes pulse{50%{box-shadow:0 0 0 12px rgba(85,214,207,0)}}}
'''


def render_login(error=""):
    return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Node Forge login</title><style>{CSS}.login{{max-width:460px;margin:12vh auto;padding:28px;background:var(--panel);border:1px solid var(--line)}}.login h1{{font-size:48px}}</style><div class="login"><div class="eyebrow">Meltun infrastructure</div><h1>Node<br>Forge</h1>{f'<p class="error">{html.escape(error)}</p>' if error else ''}<form method="post" action="/login"><label>Пароль администратора</label><input autofocus type="password" name="password" autocomplete="current-password"><button style="margin-top:16px">Открыть панель</button></form><p class="muted">Интерфейс доступен только через защищённый SSH-туннель.</p></div></html>'''


def render_dashboard(message="", error=""):
    s = status_data()
    last = (STATE_DIR / "last-inbound.json").read_text(encoding="utf-8") if (STATE_DIR / "last-inbound.json").exists() else ""
    meta = json.loads((STATE_DIR / "last-meta.json").read_text()) if (STATE_DIR / "last-meta.json").exists() else {}
    certs = "".join(f'<span class="pill">{html.escape(x)}</span>' for x in s["certs"]) or '<span class="muted">Пока нет</span>'
    flash = f'<div class="flash">{html.escape(message)}</div>' if message else ""
    flash += f'<div class="flash error">{html.escape(error)}</div>' if error else ""
    inbound = f'''<div class="copybox"><button class="secondary" onclick="copyInbound();return false">Копировать</button><pre id="inbound">{html.escape(last)}</pre></div><p class="mono muted">Public key: {html.escape(meta.get('publicKey','—'))} · Short ID: {html.escape(meta.get('shortId','—'))}</p>''' if last else '<p class="muted">Сгенерированный inbound появится здесь.</p>'
    return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Node Forge</title><style>{CSS}</style><div class="shell"><header class="mast"><div><div class="eyebrow">Meltun infrastructure / privileged console</div><h1>Node Forge</h1></div><div class="rail"><span class="pulse"></span>{html.escape(s['public_ip'])} · local control</div></header>{flash}<main class="grid">
<section class="card"><div class="label">Runtime</div><h2>Состояние узла</h2><div class="metric"><span>RemnaNode</span><b class="{'ok' if s['state']=='running' else 'warn'}">{html.escape(s['state'])}</b></div><div class="metric"><span>Перезапуски</span><b>{html.escape(s['restarts'])}</b></div><div class="metric"><span>Docker</span><b>{html.escape(s['docker'])}</b></div><div class="metric"><span>Compose</span><b>{html.escape(s['compose'])}</b></div><div class="actions"><form method="post" action="/action"><input type="hidden" name="csrf" value="{csrf_token()}"><button name="action" value="start">Запустить</button><button class="secondary" name="action" value="restart">Перезапустить</button><button class="secondary" name="action" value="pull">Обновить</button></form></div></section>
<section class="card"><div class="label">Kernel</div><h2>Сеть</h2><div class="metric"><span>Congestion</span><b class="ok">{html.escape(s['bbr'])}</b></div><div class="metric"><span>Queue</span><b>{html.escape(s['qdisc'])}</b></div><form method="post" action="/network"><input type="hidden" name="csrf" value="{csrf_token()}"><label>Профиль</label><select name="profile"><option value="bbr">Только BBR + fq</option><option value="balanced">BBR + безопасные VPN-буферы</option></select><button style="margin-top:16px">Применить сеть</button></form></section>
<section class="card"><div class="label">Certificates</div><h2>Хранилище TLS</h2><div class="certs">{certs}</div><p class="muted">Файлы копируются в каталог Xray и обновляются deploy-hook’ом Certbot.</p></section>
<section class="card wide"><div class="label">01 / Node deployment</div><h2>Docker Compose RemnaNode</h2><form method="post" action="/compose"><input type="hidden" name="csrf" value="{csrf_token()}"><textarea name="compose" spellcheck="false" placeholder="Вставь полный docker-compose.yml"></textarea><div class="row"><label class="check"><input type="checkbox" name="cert_volume" value="1" checked> Добавить volume сертификатов</label><label class="check"><input type="checkbox" name="pull" value="1" checked> Скачать свежий образ</label></div><button>Проверить и запустить</button></form><p class="mono muted">Текущий SHA-256: {html.escape(s['compose_hash'])}. Перед каждой заменой создаётся резервная копия.</p></section>
<section class="card"><div class="label">02 / Certificate</div><h2>Выпустить сертификат</h2><form method="post" action="/cert"><input type="hidden" name="csrf" value="{csrf_token()}"><label>Домен</label><input name="domain" placeholder="node.example.com" required><label>Email Let's Encrypt</label><input type="email" name="email" required><label class="check"><input type="checkbox" name="restart_node" value="1"> Перезапустить ноду после выпуска</label><label class="check"><input type="checkbox" name="force_dns" value="1"> Игнорировать несовпадение DNS</label><button>Проверить DNS и выпустить</button></form></section>
<section class="card full"><div class="label">03 / Profile builder</div><h2>Сгенерировать inbound</h2><form method="post" action="/inbound"><input type="hidden" name="csrf" value="{csrf_token()}"><div class="row"><div><label>Тип</label><select name="kind"><option value="reality">VLESS TCP Reality + self-steal</option><option value="hysteria">Hysteria 2 TLS</option></select></div><div><label>Tag</label><input name="tag" value="VLESS_REALITY"></div><div><label>Порт</label><input type="number" min="1" max="65535" name="inbound_port" value="2053"></div><div><label>Домен</label><input name="inbound_domain" placeholder="node.example.com" required></div></div><button>Сгенерировать inbound</button></form>{inbound}</section>
<section class="card full"><div class="label">Live tail</div><h2>Последние события RemnaNode</h2><pre>{html.escape(s['logs'] or 'Контейнер ещё не запускался.')}</pre></section>
</main><footer>Node Forge binds to {html.escape(BIND)}:{PORT} · <a class="muted" href="/logout">Выйти</a></footer></div><script>function copyInbound(){{navigator.clipboard.writeText(document.getElementById('inbound').innerText)}}</script></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "NodeForge/1.0"
    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)
    def send_html(self, body, code=200, headers=None):
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(payload)
    def authed(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return "rnm_session" in jar and hmac.compare_digest(jar["rnm_session"].value, session_token())
    def form(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000: raise ValueError("Request is too large.")
        return urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
    def redirect(self, message="", error=""):
        query = urllib.parse.urlencode({"ok": message, "error": error})
        self.send_response(303); self.send_header("Location", "/?" + query); self.end_headers()
    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/logout":
            return self.send_html(render_login(), headers={"Set-Cookie": "rnm_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"})
        if not self.authed(): return self.send_html(render_login(), 401)
        args = urllib.parse.parse_qs(query)
        return self.send_html(render_dashboard(args.get("ok", [""])[0], args.get("error", [""])[0]))
    def do_POST(self):
        try: form = self.form()
        except Exception as exc: return self.send_html(render_login(str(exc)), 400)
        if self.path == "/login":
            ip = self.client_address[0]; now = time.time(); record = attempts.get(ip, [])
            record = [x for x in record if now - x < 60]; attempts[ip] = record
            if len(record) >= 5: return self.send_html(render_login("Too many attempts. Wait one minute."), 429)
            if hmac.compare_digest(form.get("password", [""])[0], ADMIN_PASSWORD):
                attempts.pop(ip, None)
                self.send_response(303); self.send_header("Location", "/")
                self.send_header("Set-Cookie", f"rnm_session={session_token()}; HttpOnly; SameSite=Strict; Path=/")
                return self.end_headers()
            record.append(now); return self.send_html(render_login("Wrong password."), 401)
        if not self.authed(): return self.send_html(render_login(), 401)
        if not hmac.compare_digest(form.get("csrf", [""])[0], csrf_token()): return self.redirect(error="CSRF validation failed.")
        try:
            if self.path == "/compose": message = apply_compose(form)
            elif self.path == "/cert": message = issue_certificate(form)
            elif self.path == "/network": message = apply_network(form)
            elif self.path == "/inbound": message = generate_inbound(form)
            elif self.path == "/action": message = node_action(form)
            else: raise ValueError("Unknown action.")
            self.redirect(message=message)
        except Exception as exc:
            self.redirect(error=str(exc)[-4000:])


if __name__ == "__main__":
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
PY
chmod 0750 /opt/remnanode-manager/app.py

cat > /usr/local/sbin/remnanode-sync-certs <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
install -d -m 0755 /var/lib/remnawave/configs/xray/ssl
for lineage in /etc/letsencrypt/live/*; do
  [[ -d "$lineage" && -e "$lineage/fullchain.pem" && -e "$lineage/privkey.pem" ]] || continue
  domain=$(basename "$lineage")
  install -m 0644 "$lineage/fullchain.pem" "/var/lib/remnawave/configs/xray/ssl/$domain.pem"
  install -m 0600 "$lineage/privkey.pem" "/var/lib/remnawave/configs/xray/ssl/$domain.key"
done
if docker inspect remnanode >/dev/null 2>&1; then
  docker restart remnanode >/dev/null
fi
SH
chmod 0750 /usr/local/sbin/remnanode-sync-certs
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
ln -sfn /usr/local/sbin/remnanode-sync-certs /etc/letsencrypt/renewal-hooks/deploy/remnanode-sync-certs

if [[ ! -e /etc/remnanode-manager.env ]]; then
  admin_password=$(openssl rand -base64 18 | tr -d '\n=/+' | head -c 22)
  session_secret=$(openssl rand -hex 32)
  cat > /etc/remnanode-manager.env <<EOF
RNM_ADMIN_PASSWORD=$admin_password
RNM_SESSION_SECRET=$session_secret
RNM_BIND=127.0.0.1
RNM_PORT=8765
EOF
  chmod 0600 /etc/remnanode-manager.env
fi

cat > /etc/systemd/system/remnanode-manager.service <<'UNIT'
[Unit]
Description=RemnaNode Node Forge
After=network-online.target docker.service nginx.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/remnanode-manager.env
ExecStart=/usr/bin/python3 /opt/remnanode-manager/app.py
Restart=on-failure
RestartSec=3
User=root
Group=root
UMask=0077
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
ProtectSystem=false

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now remnanode-manager.service

public_ip=$(curl -4fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
admin_password=$(sed -n 's/^RNM_ADMIN_PASSWORD=//p' /etc/remnanode-manager.env)
cat > /root/remnanode-manager-access.txt <<EOF
RemnaNode Node Forge
SSH tunnel: ssh -L 8765:127.0.0.1:8765 root@$public_ip
Open: http://127.0.0.1:8765
Password: $admin_password
EOF
chmod 0600 /root/remnanode-manager-access.txt

systemctl --no-pager --full status remnanode-manager.service | head -n 20
echo
cat /root/remnanode-manager-access.txt
