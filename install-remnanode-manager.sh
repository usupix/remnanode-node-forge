#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 python3-yaml nginx certbot openssl ca-certificates curl

# Remnawave's official node guide uses get.docker.com. Download first so a
# failed transfer can never be piped into a privileged shell.
if ! command -v docker >/dev/null 2>&1; then
  docker_installer=$(mktemp)
  curl -fsSL https://get.docker.com -o "$docker_installer"
  sh "$docker_installer"
  rm -f -- "$docker_installer"
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends docker-compose-plugin
fi
systemctl enable --now docker nginx

install -d -m 0750 /opt/remnanode-manager
install -d -m 0750 /opt/remnanode
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
import selectors
import shutil
import socket
import subprocess
import threading
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
NETWORK_BASELINE = STATE_DIR / "network-baseline.json"
INSTALL_STATE_FILE = STATE_DIR / "install-state.json"
ADMIN_PASSWORD = os.environ["RNM_ADMIN_PASSWORD"]
SESSION_SECRET = os.environ["RNM_SESSION_SECRET"].encode()
BIND = os.getenv("RNM_BIND", "127.0.0.1")
PORT = int(os.getenv("RNM_PORT", "8765"))
BASE_PATH = "/" + os.environ["RNM_BASE_PATH"].strip("/")
DOMAIN_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
TAG_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}$")
attempts = {}
install_guard = threading.Lock()
install_state_guard = threading.Lock()
install_state = {
    "phase": "idle", "message": "Installation has not started.",
    "tag": "", "started": 0, "finished": 0, "log": "",
}

NETWORK_KEYS = [
    "net.core.default_qdisc", "net.ipv4.tcp_congestion_control",
    "net.ipv4.tcp_fastopen", "net.ipv4.tcp_mtu_probing",
    "net.core.rmem_max", "net.core.wmem_max", "net.core.netdev_max_backlog",
    "net.core.somaxconn", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem",
]


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


def save_install_state(**updates):
    with install_state_guard:
        install_state.update(updates)
        snapshot = dict(install_state)
        atomic_write(INSTALL_STATE_FILE, json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", 0o600)
    return snapshot


def install_snapshot():
    with install_state_guard:
        return dict(install_state)


def install_log(line):
    clean = redact(str(line).rstrip())
    if not clean:
        return
    with install_state_guard:
        current = install_state.get("log", "")
        install_state["log"] = (current + clean + "\n")[-30000:]
        snapshot = dict(install_state)
        atomic_write(INSTALL_STATE_FILE, json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", 0o600)


def run_live(args, *, cwd=None, timeout=1200):
    install_log("$ " + " ".join(args))
    process = subprocess.Popen(
        args, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=1,
    )
    started = time.monotonic()
    try:
        for line in iter(process.stdout.readline, ""):
            install_log(line)
            if time.monotonic() - started > timeout:
                process.kill()
                raise RuntimeError(f"Command timed out: {args[0]}")
        code = process.wait(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
    if code:
        raise RuntimeError(f"Command failed with exit code {code}: {' '.join(args)}")


def backup(paths, label):
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(2)
    target = BACKUP_DIR / f"{stamp}-{label}"
    target.mkdir(parents=True, exist_ok=False)
    os.chmod(target, 0o700)
    for path in paths:
        path = Path(path)
        if path.exists():
            shutil.copy2(path, target / path.name)
    return target


def read_sysctl(key):
    return run(["sysctl", "-n", key], check=False, timeout=10).strip()


def network_baseline():
    if not NETWORK_BASELINE.exists():
        values = {key: read_sysctl(key) for key in NETWORK_KEYS}
        atomic_write(NETWORK_BASELINE, json.dumps(values, indent=2) + "\n", 0o600)
    return json.loads(NETWORK_BASELINE.read_text(encoding="utf-8"))


def web_path(suffix=""):
    suffix = suffix.lstrip("/")
    return BASE_PATH + "/" + suffix


def session_token():
    return hmac.new(SESSION_SECRET, b"admin-session-v1", hashlib.sha256).hexdigest()


def csrf_token():
    return hmac.new(SESSION_SECRET, (session_token() + ":csrf").encode(), hashlib.sha256).hexdigest()


def redact(text):
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r'(?im)(SECRET_KEY\s*[=:]\s*)["\']?[^"\'\s]+', r'\1[hidden]', text)
    text = re.sub(r'(?i)(token=)[A-Za-z0-9_-]+', r'\1[hidden]', text)
    return text


def load_install_state():
    if not INSTALL_STATE_FILE.exists():
        return
    try:
        previous = json.loads(INSTALL_STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(previous, dict):
            install_state.update(previous)
            if install_state.get("phase") in {"queued", "pulling", "starting", "verifying"}:
                install_state.update({
                    "phase": "interrupted",
                    "message": "The manager restarted while installation was running. Start it again.",
                    "finished": int(time.time()),
                })
    except Exception:
        pass


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
    fastopen = read_sysctl("net.ipv4.tcp_fastopen") or "unknown"
    mtu_probing = read_sysctl("net.ipv4.tcp_mtu_probing") or "unknown"
    rmem_max = read_sysctl("net.core.rmem_max") or "unknown"
    backlog = read_sysctl("net.core.netdev_max_backlog") or "unknown"
    public_ip = "unknown"
    try:
        public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=4).read().decode().strip()
    except Exception:
        pass
    compose_hash = "—"
    if COMPOSE_FILE.exists():
        compose_hash = hashlib.sha256(COMPOSE_FILE.read_bytes()).hexdigest()[:12]
    certs = sorted(p.stem for p in SSL_DIR.glob("*.pem"))
    return {
        "docker": docker_version, "compose": compose_version, "state": state,
        "image": image, "restarts": restarts, "bbr": bbr, "qdisc": qdisc,
        "fastopen": fastopen, "mtu_probing": mtu_probing, "rmem_max": rmem_max,
        "backlog": backlog,
        "public_ip": public_ip, "compose_hash": compose_hash, "certs": certs,
    }


def image_tags():
    tags = ["latest"]
    try:
        request = urllib.request.Request(
            "https://hub.docker.com/v2/repositories/remnawave/node/tags?page_size=50&ordering=last_updated",
            headers={"User-Agent": "RemnaNode-Node-Forge/1.1"},
        )
        payload = json.loads(urllib.request.urlopen(request, timeout=6).read().decode())
        names = [item.get("name", "") for item in payload.get("results", [])]
        stable = [name for name in names if re.fullmatch(r"\d+(?:\.\d+){1,3}", name)]
        stable.sort(key=lambda value: tuple(int(x) for x in value.split(".")), reverse=True)
        tags.extend(stable)
        if "dev" in names:
            tags.append("dev")
    except Exception:
        tags.extend(["3.4.1", "dev"])
    return list(dict.fromkeys(tags))


def ensure_cert_volume(config):
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("Compose must contain a services object.")
    service = config["services"].get("remnanode")
    if not isinstance(service, dict):
        raise ValueError("Service remnanode was not found.")
    volumes = service.setdefault("volumes", [])
    if not isinstance(volumes, list):
        raise ValueError("remnanode.volumes must be a list.")
    mount = "/var/lib/remnawave/configs/xray/ssl:/var/lib/remnawave/configs/xray/ssl:ro"
    host_ssl_dir = str(SSL_DIR).replace("\\", "/")
    if not any(isinstance(item, str) and item.split(":", 1)[0] == host_ssl_dir for item in volumes):
        volumes.append(mount)
        return True
    return False


def write_compose(config, label):
    rendered = yaml.safe_dump(config, sort_keys=False, allow_unicode=True, width=4096)
    COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = COMPOSE_DIR / ".docker-compose.candidate.yml"
    atomic_write(tmp, rendered)
    run(["docker", "compose", "-f", str(tmp), "config", "-q"], timeout=30)
    saved = backup([COMPOSE_FILE], label)
    os.replace(tmp, COMPOSE_FILE)
    os.chmod(COMPOSE_FILE, 0o600)
    return saved


def apply_compose(form):
    raw = form.get("compose", [""])[0].strip()
    if not raw:
        raise ValueError("Paste docker-compose.yml first.")
    if len(raw.encode()) > 900_000:
        raise ValueError("Compose file is too large.")
    config = yaml.safe_load(raw)
    if form.get("cert_volume") == ["1"]:
        ensure_cert_volume(config)
    else:
        if not isinstance(config, dict) or not isinstance(config.get("services"), dict) or not isinstance(config["services"].get("remnanode"), dict):
            raise ValueError("Compose must contain services.remnanode.")
    saved = write_compose(config, "compose")
    return f"Compose validated and saved. Choose a RemnaNode version, then start installation. Backup: {saved}"


def install_worker(tag):
    try:
        with install_guard:
            save_install_state(
                phase="pulling", message=f"Downloading remnawave/node:{tag}",
                started=int(time.time()), finished=0, tag=tag, log="",
            )
            install_log(f"Selected image: remnawave/node:{tag}")
            run_live(["docker", "pull", f"remnawave/node:{tag}"], timeout=1200)
            save_install_state(phase="starting", message="Creating and starting the RemnaNode container.")
            run_live(
                ["docker", "compose", "up", "-d", "--force-recreate", "remnanode"],
                cwd=COMPOSE_DIR, timeout=600,
            )
            save_install_state(phase="verifying", message="Waiting for the container to enter running state.")
            deadline = time.monotonic() + 90
            state = "unknown"
            while time.monotonic() < deadline:
                state = run(
                    ["docker", "inspect", "remnanode", "--format", "{{.State.Status}}"],
                    check=False, timeout=15,
                ).strip()
                if state == "running":
                    break
                time.sleep(2)
            if state != "running":
                tail = run(["docker", "logs", "--tail", "80", "remnanode"], check=False, timeout=20)
                install_log(tail)
                raise RuntimeError(f"Container did not reach running state (current state: {state or 'missing'}).")
            image = run(
                ["docker", "inspect", "remnanode", "--format", "{{.Config.Image}}"],
                check=False, timeout=15,
            ).strip()
            install_log(f"RemnaNode is running with image {image or f'remnawave/node:{tag}'}.")
            save_install_state(
                phase="installed", message=f"RemnaNode {tag} is installed and running.",
                finished=int(time.time()),
            )
    except Exception as exc:
        install_log(f"ERROR: {exc}")
        save_install_state(
            phase="failed", message=str(exc)[-1000:], finished=int(time.time()),
        )


def start_install(form):
    tag = form.get("version", ["latest"])[0].strip()
    if not TAG_RE.fullmatch(tag):
        raise ValueError("Invalid image tag.")
    if not COMPOSE_FILE.exists():
        raise ValueError("Save Docker Compose before starting installation.")
    if install_guard.locked() or install_snapshot().get("phase") in {"queued", "pulling", "starting", "verifying"}:
        raise ValueError("Installation is already running.")
    config = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("Compose must contain services.remnanode.")
    service = config["services"].get("remnanode")
    if not isinstance(service, dict):
        raise ValueError("Service remnanode was not found.")
    service["image"] = f"remnawave/node:{tag}"
    write_compose(config, f"version-{tag}")
    save_install_state(
        phase="queued", message=f"Installation of remnawave/node:{tag} is queued.",
        tag=tag, started=int(time.time()), finished=0, log="",
    )
    threading.Thread(target=install_worker, args=(tag,), daemon=True, name="remnanode-install").start()
    return install_snapshot()


def runtime_status():
    state = "not created"
    image = "—"
    restarts = "0"
    inspect = run([
        "docker", "inspect", "remnanode", "--format",
        "{{.State.Status}}|{{.Config.Image}}|{{.RestartCount}}",
    ], check=False, timeout=15)
    if inspect and "|" in inspect:
        state, image, restarts = inspect.split("|", 2)
    return {
        "state": state,
        "image": image,
        "restarts": restarts,
        "composeSaved": COMPOSE_FILE.exists(),
        "job": install_snapshot(),
    }


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
    location / {{ try_files /index.html =404; }}
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
    location / {{ try_files /index.html =404; }}
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
    # The manager runs with UMask=0077. Make the decoy document root
    # traversable by the unprivileged nginx worker explicitly.
    os.chmod(site_root, 0o755)
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
    volume_note = ""
    if form.get("cert_volume") == ["1"] and COMPOSE_FILE.exists():
        config = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        if ensure_cert_volume(config):
            write_compose(config, "certificate-volume")
            run(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR, timeout=300)
            volume_note = " Certificate volume added to Compose."
    elif form.get("cert_volume") == ["1"]:
        volume_note = " Compose is not installed yet; keep the certificate-volume option enabled when applying it."
    containers = run(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False).splitlines()
    if form.get("restart_node") == ["1"] and "remnanode" in containers:
        run(["docker", "restart", "remnanode"], timeout=120)
    return f"Certificate issued: {SSL_DIR}/{domain}.pem and {domain}.key.{volume_note}"


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
    saved = backup([SYSCTL_BBR, SYSCTL_TUNE], "network")
    base = network_baseline()
    bbr = form.get("bbr") == ["1"]
    fastopen = form.get("fastopen") == ["1"]
    mtu = form.get("mtu") == ["1"]
    buffers = form.get("buffers") == ["1"]
    backlog = form.get("backlog") == ["1"]
    if bbr:
        run(["modprobe", "tcp_bbr"], timeout=20)
    values = {
        "net.core.default_qdisc": "fq" if bbr else base["net.core.default_qdisc"],
        "net.ipv4.tcp_congestion_control": "bbr" if bbr else base["net.ipv4.tcp_congestion_control"],
        "net.ipv4.tcp_fastopen": "3" if fastopen else base["net.ipv4.tcp_fastopen"],
        "net.ipv4.tcp_mtu_probing": "1" if mtu else base["net.ipv4.tcp_mtu_probing"],
        "net.core.rmem_max": "16777216" if buffers else base["net.core.rmem_max"],
        "net.core.wmem_max": "16777216" if buffers else base["net.core.wmem_max"],
        "net.ipv4.tcp_rmem": "4096 131072 16777216" if buffers else base["net.ipv4.tcp_rmem"],
        "net.ipv4.tcp_wmem": "4096 65536 16777216" if buffers else base["net.ipv4.tcp_wmem"],
        "net.core.netdev_max_backlog": "8192" if backlog else base["net.core.netdev_max_backlog"],
        "net.core.somaxconn": "8192" if backlog else base["net.core.somaxconn"],
    }
    body = "# Managed by RemnaNode Node Forge. Unchecked controls restore install-time values.\n"
    body += "".join(f"{key}={value}\n" for key, value in values.items())
    atomic_write(SYSCTL_BBR, "# Compatibility marker; settings are stored in 99-remnanode-manager-network.conf.\n", 0o644)
    atomic_write(SYSCTL_TUNE, body, 0o644)
    run(["sysctl", "-p", str(SYSCTL_TUNE)], timeout=60)
    enabled = [name for name, on in (("BBR", bbr), ("Fast Open", fastopen), ("MTU probing", mtu), ("buffers", buffers), ("backlog", backlog)) if on]
    return f"Network settings applied: {', '.join(enabled) or 'baseline restored'}. Backup: {saved}"


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
.pipeline{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);margin:16px 0}.stage{background:#091621;padding:12px;min-height:76px}.stage small{display:block;color:var(--muted);font:10px var(--mono);text-transform:uppercase;letter-spacing:.1em}.stage b{display:block;margin-top:7px;font:13px var(--mono)}.terminal{min-height:330px;max-height:520px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:#03090e;color:#b9d3e5;border:1px solid #20394e;padding:14px;font:12px/1.55 var(--mono)}.logbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:10px 0}.tabs{display:flex;gap:7px;flex-wrap:wrap}.tabs button.active{background:var(--amber);color:#1d1307}.stream-state{font:11px var(--mono);color:var(--muted)}.stream-state.live{color:var(--cyan)}.spinner{display:inline-block;width:9px;height:9px;border:2px solid rgba(85,214,207,.25);border-top-color:var(--cyan);border-radius:50%;margin-right:7px;vertical-align:-1px;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}@media(max-width:850px){.pipeline{grid-template-columns:1fr 1fr}}@media(prefers-reduced-motion:reduce){.spinner{animation:none}}
'''


def render_login(error=""):
    return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Node Forge login</title><style>{CSS}.login{{max-width:460px;margin:12vh auto;padding:28px;background:var(--panel);border:1px solid var(--line)}}.login h1{{font-size:48px}}</style><div class="login"><div class="eyebrow">Meltun infrastructure</div><h1>Node<br>Forge</h1>{f'<p class="error">{html.escape(error)}</p>' if error else ''}<form method="post" action="{web_path('login')}"><label>Пароль администратора</label><input autofocus type="password" name="password" autocomplete="current-password"><button style="margin-top:16px">Открыть панель</button></form><p class="muted">Панель защищена секретным URL и отдельным паролем. Пока используется HTTP, не открывай её в чужой сети.</p></div></html>'''


def render_dashboard(message="", error=""):
    s = status_data()
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8") if COMPOSE_FILE.exists() else ""
    tags = image_tags()
    selected_tag = s["image"].rsplit(":", 1)[-1] if s["image"].startswith("remnawave/node:") else "latest"
    tag_options = "".join(
        f'<option value="{html.escape(tag)}" {"selected" if tag == selected_tag else ""}>{html.escape(tag)}{" · latest" if tag == "latest" else ""}</option>'
        for tag in tags
    )
    job = install_snapshot()
    last = (STATE_DIR / "last-inbound.json").read_text(encoding="utf-8") if (STATE_DIR / "last-inbound.json").exists() else ""
    meta = json.loads((STATE_DIR / "last-meta.json").read_text()) if (STATE_DIR / "last-meta.json").exists() else {}
    certs = "".join(f'<span class="pill">{html.escape(x)}</span>' for x in s["certs"]) or '<span class="muted">Пока нет</span>'
    flash = f'<div class="flash">{html.escape(message)}</div>' if message else ""
    flash += f'<div class="flash error">{html.escape(error)}</div>' if error else ""
    inbound = f'''<div class="copybox"><button class="secondary" onclick="copyInbound();return false">Копировать</button><pre id="inbound">{html.escape(last)}</pre></div><p class="mono muted">Public key: {html.escape(meta.get('publicKey','—'))} · Short ID: {html.escape(meta.get('shortId','—'))}</p>''' if last else '<p class="muted">Сгенерированный inbound появится здесь.</p>'
    return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Node Forge</title><style>{CSS}</style><div class="shell"><header class="mast"><div><div class="eyebrow">Meltun infrastructure / node workshop</div><h1>Node Forge</h1></div><div class="rail"><span class="pulse"></span>{html.escape(s['public_ip'])} · secret path</div></header>{flash}<main class="grid">
<section class="card"><div class="label">Runtime</div><h2>Состояние узла</h2><div class="metric"><span>RemnaNode</span><b id="node-state" class="{'ok' if s['state']=='running' else 'warn'}">{html.escape(s['state'])}</b></div><div class="metric"><span>Образ</span><b id="node-image">{html.escape(s['image'])}</b></div><div class="metric"><span>Перезапуски</span><b id="node-restarts">{html.escape(s['restarts'])}</b></div><div class="metric"><span>Docker / Compose</span><b>{html.escape(s['docker'])} / {html.escape(s['compose'])}</b></div><div class="actions"><form method="post" action="{web_path('action')}"><input type="hidden" name="csrf" value="{csrf_token()}"><button name="action" value="start">Запустить</button><button class="secondary" name="action" value="restart">Перезапустить</button><button class="secondary" name="action" value="pull">Обновить</button></form></div></section>
<section class="card"><div class="label">Kernel controls</div><h2>Сеть</h2><div class="metric"><span>Congestion</span><b class="ok">{html.escape(s['bbr'])}</b></div><div class="metric"><span>Queue</span><b>{html.escape(s['qdisc'])}</b></div><div class="metric"><span>Fast Open / MTU</span><b>{html.escape(s['fastopen'])} / {html.escape(s['mtu_probing'])}</b></div><form method="post" action="{web_path('network')}"><input type="hidden" name="csrf" value="{csrf_token()}"><label class="check"><input type="checkbox" name="bbr" value="1" {'checked' if s['bbr']=='bbr' else ''}> BBR + fq</label><label class="check"><input type="checkbox" name="fastopen" value="1" {'checked' if s['fastopen']=='3' else ''}> TCP Fast Open</label><label class="check"><input type="checkbox" name="mtu" value="1" {'checked' if s['mtu_probing']=='1' else ''}> MTU probing</label><label class="check"><input type="checkbox" name="buffers" value="1" {'checked' if s['rmem_max']=='16777216' else ''}> VPN-буферы 16 MiB</label><label class="check"><input type="checkbox" name="backlog" value="1" {'checked' if s['backlog']=='8192' else ''}> Очереди 8192</label><button style="margin-top:16px">Применить переключатели</button></form><p class="muted">Снятый флажок возвращает значение, которое было до установки панели.</p></section>
<section class="card"><div class="label">Certificates</div><h2>Хранилище TLS</h2><div class="certs">{certs}</div><p class="muted">Файлы копируются в каталог Xray и обновляются deploy-hook’ом Certbot.</p></section>
<section class="card wide"><div class="label">01 / Configuration</div><h2>Сохранить Docker Compose</h2><form method="post" action="{web_path('compose')}"><input type="hidden" name="csrf" value="{csrf_token()}"><textarea id="compose-editor" name="compose" spellcheck="false" placeholder="Вставь полный docker-compose.yml из Remnawave">{html.escape(compose_text)}</textarea><label class="check"><input type="checkbox" name="cert_volume" value="1" checked> Подключить каталог сертификатов к контейнеру</label><button>Проверить и сохранить</button></form><p class="mono muted">Каталог: /opt/remnanode · SHA-256: {html.escape(s['compose_hash'])}. Сохранение ещё не запускает контейнер.</p></section>
<section class="card"><div class="label">02 / Certificate · optional</div><h2>Выпустить сертификат</h2><form method="post" action="{web_path('cert')}"><input type="hidden" name="csrf" value="{csrf_token()}"><label>Домен</label><input name="domain" placeholder="node.example.com" required><label>Email Let's Encrypt</label><input type="email" name="email" required><label class="check"><input type="checkbox" name="cert_volume" value="1" checked> Добавить volume в сохранённый Compose</label><label class="check"><input type="checkbox" name="restart_node" value="1"> Перезапустить уже работающую ноду</label><label class="check"><input type="checkbox" name="force_dns" value="1"> Игнорировать несовпадение DNS</label><button>Проверить DNS и выпустить</button></form></section>
<section class="card full"><div class="label">03 / Installation</div><h2>Выбрать версию и установить</h2><form id="install-form" action="{web_path('api/install')}" method="post"><input type="hidden" name="csrf" value="{csrf_token()}"><div class="row"><div><label>Версия образа</label><select name="version">{tag_options}</select></div><div style="align-self:end"><button id="install-button">Начать установку</button></div></div></form><div class="pipeline"><div class="stage"><small>01 Compose</small><b id="step-compose">{'готов' if COMPOSE_FILE.exists() else 'не сохранён'}</b></div><div class="stage"><small>02 Image</small><b id="step-image">{html.escape(job.get('tag') or selected_tag)}</b></div><div class="stage"><small>03 Deploy</small><b id="step-deploy">{html.escape(job.get('phase','idle'))}</b></div><div class="stage"><small>04 Runtime</small><b id="step-runtime">{html.escape(s['state'])}</b></div></div><p id="install-message" class="mono muted">{html.escape(job.get('message','Installation has not started.'))}</p><pre id="install-log">{html.escape(job.get('log','') or 'Здесь появится ход загрузки образа и запуска контейнера.')}</pre></section>
<section class="card full"><div class="label">04 / Profile builder</div><h2>Сгенерировать inbound</h2><form method="post" action="{web_path('inbound')}"><input type="hidden" name="csrf" value="{csrf_token()}"><div class="row"><div><label>Тип</label><select name="kind"><option value="reality">VLESS TCP Reality + self-steal</option><option value="hysteria">Hysteria 2 TLS</option></select></div><div><label>Tag</label><input name="tag" value="VLESS_REALITY"></div><div><label>Порт</label><input type="number" min="1" max="65535" name="inbound_port" value="2053"></div><div><label>Домен</label><input name="inbound_domain" placeholder="node.example.com" required></div></div><button>Сгенерировать inbound</button></form>{inbound}</section>
<section class="card full"><div class="label">Live console</div><h2>Логи без обновления страницы</h2><div class="logbar"><div class="tabs"><button type="button" class="secondary active" data-stream="container">Docker logs</button><button type="button" class="secondary" data-stream="xray">Xray · xlogs</button><button type="button" class="secondary" id="clear-log">Очистить экран</button></div><span id="stream-state" class="stream-state">подключение…</span></div><div id="live-log" class="terminal">Подключаю поток логов…</div></section>
</main><footer>Node Forge backend: {html.escape(BIND)}:{PORT} · public route: {html.escape(BASE_PATH)}/ · <a class="muted" href="{web_path('logout')}">Выйти</a></footer></div><script>
function copyInbound(){{navigator.clipboard.writeText(document.getElementById('inbound').innerText)}}
const base={json.dumps(BASE_PATH)};
const composeEditor=document.getElementById('compose-editor');if(composeEditor){{const saved=sessionStorage.getItem('node-forge-compose-draft');if(!composeEditor.value&&saved)composeEditor.value=saved;composeEditor.addEventListener('input',()=>sessionStorage.setItem('node-forge-compose-draft',composeEditor.value));}}
const installForm=document.getElementById('install-form');installForm.addEventListener('submit',async(e)=>{{e.preventDefault();const button=document.getElementById('install-button');button.disabled=true;try{{const response=await fetch(installForm.action,{{method:'POST',body:new FormData(installForm)}});const data=await response.json();if(!response.ok)throw new Error(data.error||'Не удалось начать установку');renderStatus(data.status||data);}}catch(error){{document.getElementById('install-message').textContent=error.message;}}finally{{button.disabled=false;}}}});
function escapeHtml(value){{const node=document.createElement('span');node.textContent=value;return node.innerHTML;}}
function renderStatus(data){{if(!data)return;document.getElementById('node-state').textContent=data.state;document.getElementById('node-image').textContent=data.image;document.getElementById('node-restarts').textContent=data.restarts;document.getElementById('step-compose').textContent=data.composeSaved?'готов':'не сохранён';document.getElementById('step-runtime').textContent=data.state;const job=data.job||data;document.getElementById('step-image').textContent=job.tag||'latest';document.getElementById('step-deploy').textContent=job.phase||'idle';document.getElementById('install-message').innerHTML=['queued','pulling','starting','verifying'].includes(job.phase)?'<span class="spinner"></span>'+escapeHtml(job.message||''):escapeHtml(job.message||'');const log=document.getElementById('install-log');if(job.log!==undefined&&log.textContent!==job.log){{const bottom=log.scrollHeight-log.scrollTop-log.clientHeight<50;log.textContent=job.log||'Ожидание запуска…';if(bottom)log.scrollTop=log.scrollHeight;}}}}
async function pollStatus(){{try{{const response=await fetch(base+'/api/status',{{cache:'no-store'}});if(response.ok)renderStatus(await response.json());}}catch(_error){{}}}}setInterval(pollStatus,1500);pollStatus();
let stream=null;const live=document.getElementById('live-log');const streamState=document.getElementById('stream-state');function appendLine(line){{const bottom=live.scrollHeight-live.scrollTop-live.clientHeight<60;live.textContent+=(live.textContent?'\\n':'')+line;const lines=live.textContent.split('\\n');if(lines.length>600)live.textContent=lines.slice(-500).join('\\n');if(bottom)live.scrollTop=live.scrollHeight;}}
function openStream(name){{if(stream)stream.close();live.textContent='';streamState.textContent='подключение…';streamState.className='stream-state';document.querySelectorAll('[data-stream]').forEach(b=>b.classList.toggle('active',b.dataset.stream===name));stream=new EventSource(base+'/stream?source='+encodeURIComponent(name));stream.addEventListener('ready',()=>{{streamState.textContent='● в реальном времени';streamState.className='stream-state live';}});stream.addEventListener('line',event=>{{try{{appendLine(JSON.parse(event.data));}}catch(_error){{appendLine(event.data);}}}});stream.addEventListener('terminal',event=>{{try{{appendLine(JSON.parse(event.data));}}catch(_error){{}}streamState.textContent='поток остановлен';streamState.className='stream-state';stream.close();}});stream.onerror=()=>{{streamState.textContent='переподключение…';streamState.className='stream-state';}};}}
document.querySelectorAll('[data-stream]').forEach(button=>button.addEventListener('click',()=>openStream(button.dataset.stream)));document.getElementById('clear-log').addEventListener('click',()=>{{live.textContent='';}});openStream('container');
</script></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "NodeForge/1.0"
    protocol_version = "HTTP/1.1"
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
    def send_json(self, body, code=200):
        payload = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers(); self.wfile.write(payload)
    def stream_logs(self, source):
        commands = {
            "container": ["docker", "logs", "--follow", "--tail", "120", "--timestamps", "remnanode"],
            "xray": ["docker", "exec", "remnanode", "xlogs"],
        }
        if source not in commands:
            return self.send_json({"error": "Unknown log source."}, 400)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        process = subprocess.Popen(
            commands[source], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1, text=True,
        )
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            ready = f"event: ready\ndata: {json.dumps(source)}\n\n".encode()
            self.wfile.write(ready); self.wfile.flush()
            while True:
                events = selector.select(timeout=10)
                if events:
                    line = process.stdout.readline()
                    if line:
                        data = json.dumps(redact(line.rstrip()), ensure_ascii=False)
                        self.wfile.write(f"event: line\ndata: {data}\n\n".encode())
                        self.wfile.flush()
                        continue
                    if process.poll() is not None:
                        break
                else:
                    if process.poll() is not None:
                        break
                    self.wfile.write(b": keepalive\n\n"); self.wfile.flush()
            message = f"Log command stopped with exit code {process.poll()}."
            self.wfile.write(f"event: terminal\ndata: {json.dumps(message)}\n\n".encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            selector.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill()
    def authed(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return "rnm_session" in jar and hmac.compare_digest(jar["rnm_session"].value, session_token())
    def routed(self):
        path, _, query = self.path.partition("?")
        if path == BASE_PATH: return "/", query
        if not path.startswith(BASE_PATH + "/"): return None, query
        return path[len(BASE_PATH):] or "/", query
    def form(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000: raise ValueError("Request is too large.")
        return urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
    def redirect(self, message="", error=""):
        query = urllib.parse.urlencode({"ok": message, "error": error})
        self.send_response(303); self.send_header("Location", web_path() + "?" + query)
        self.send_header("Content-Length", "0"); self.end_headers()
    def do_GET(self):
        path, query = self.routed()
        if path is None: return self.send_html("Not found", 404)
        if path == "/logout":
            return self.send_html(render_login(), headers={"Set-Cookie": f"rnm_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path={web_path()}"})
        if not self.authed(): return self.send_html(render_login(), 401)
        args = urllib.parse.parse_qs(query)
        if path == "/api/status": return self.send_json(runtime_status())
        if path == "/stream": return self.stream_logs(args.get("source", ["container"])[0])
        if path != "/": return self.send_html("Not found", 404)
        return self.send_html(render_dashboard(args.get("ok", [""])[0], args.get("error", [""])[0]))
    def do_POST(self):
        path, _ = self.routed()
        if path is None: return self.send_html("Not found", 404)
        try: form = self.form()
        except Exception as exc: return self.send_html(render_login(str(exc)), 400)
        if path == "/login":
            ip = self.client_address[0]; now = time.time(); record = attempts.get(ip, [])
            record = [x for x in record if now - x < 60]; attempts[ip] = record
            if len(record) >= 5: return self.send_html(render_login("Too many attempts. Wait one minute."), 429)
            if hmac.compare_digest(form.get("password", [""])[0], ADMIN_PASSWORD):
                attempts.pop(ip, None)
                self.send_response(303); self.send_header("Location", web_path())
                self.send_header("Set-Cookie", f"rnm_session={session_token()}; HttpOnly; SameSite=Strict; Path={web_path()}")
                self.send_header("Content-Length", "0")
                return self.end_headers()
            record.append(now); return self.send_html(render_login("Wrong password."), 401)
        is_api = path.startswith("/api/")
        if not self.authed():
            return self.send_json({"error": "Authentication required."}, 401) if is_api else self.send_html(render_login(), 401)
        if not hmac.compare_digest(form.get("csrf", [""])[0], csrf_token()):
            return self.send_json({"error": "CSRF validation failed."}, 403) if is_api else self.redirect(error="CSRF validation failed.")
        try:
            if path == "/compose": message = apply_compose(form)
            elif path == "/cert": message = issue_certificate(form)
            elif path == "/network": message = apply_network(form)
            elif path == "/inbound": message = generate_inbound(form)
            elif path == "/action": message = node_action(form)
            elif path == "/api/install":
                start_install(form)
                return self.send_json({"ok": True, "status": runtime_status()})
            else: raise ValueError("Unknown action.")
            self.redirect(message=message)
        except Exception as exc:
            if is_api: return self.send_json({"error": str(exc)[-4000:]}, 400)
            self.redirect(error=str(exc)[-4000:])


if __name__ == "__main__":
    network_baseline()
    load_install_state()
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

public_ip=$(curl -4fsS --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')

if [[ ! -e /etc/remnanode-manager.env ]]; then
  admin_password=$(openssl rand -base64 18 | tr -d '\n=/+' | head -c 22)
  session_secret=$(openssl rand -hex 32)
  manager_path=$(openssl rand -hex 8)
  cat > /etc/remnanode-manager.env <<EOF
RNM_ADMIN_PASSWORD=$admin_password
RNM_SESSION_SECRET=$session_secret
RNM_BIND=127.0.0.1
RNM_PORT=8765
RNM_BASE_PATH=$manager_path
EOF
  chmod 0600 /etc/remnanode-manager.env
fi
if ! grep -q '^RNM_BASE_PATH=' /etc/remnanode-manager.env; then
  printf 'RNM_BASE_PATH=%s\n' "$(openssl rand -hex 8)" >> /etc/remnanode-manager.env
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
systemctl enable remnanode-manager.service
systemctl restart remnanode-manager.service

admin_password=$(sed -n 's/^RNM_ADMIN_PASSWORD=//p' /etc/remnanode-manager.env)
manager_path=$(sed -n 's/^RNM_BASE_PATH=//p' /etc/remnanode-manager.env)

cat > /etc/nginx/sites-available/remnanode-manager <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $public_ip;
    server_tokens off;

    location = /$manager_path {
        return 302 /$manager_path/;
    }

    location ^~ /$manager_path/ {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 1200s;
        proxy_send_timeout 1200s;
        proxy_buffering off;
        proxy_cache off;
        client_max_body_size 1m;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        add_header Cache-Control no-store always;
    }

    location / {
        return 404;
    }
}
EOF
ln -sfn /etc/nginx/sites-available/remnanode-manager /etc/nginx/sites-enabled/remnanode-manager
nginx -t
systemctl reload nginx

cat > /root/remnanode-manager-access.txt <<EOF
RemnaNode Node Forge
Open: http://$public_ip/$manager_path/
Password: $admin_password
Backend: 127.0.0.1:8765
EOF
chmod 0600 /root/remnanode-manager-access.txt

if ! systemctl is-active --quiet remnanode-manager.service; then
  journalctl -u remnanode-manager.service --no-pager -n 40
  exit 1
fi
printf 'Service: %s\n\n' "$(systemctl is-active remnanode-manager.service)"
cat /root/remnanode-manager-access.txt
