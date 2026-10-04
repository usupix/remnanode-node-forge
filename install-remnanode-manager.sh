#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 python3-yaml nginx certbot openssh-server openssl ca-certificates curl

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
install -d -o root -g root -m 0755 /run/sshd
install -d -m 0755 /var/www/remnanode-manager-acme/.well-known/acme-challenge
install -d -m 0755 /var/www/remnanode-decoy
install -d -m 0755 /var/lib/remnawave/configs/xray/ssl
install -d -m 0755 /var/log/remnanode

cat > /opt/remnanode-manager/app.py <<'PY'
#!/usr/bin/env python3
import calendar
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import selectors
import shutil
import socket
import stat
import subprocess
import threading
import time
import urllib.parse
import urllib.error
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
XRAY_LOG_DIR = Path("/var/log/remnanode")
ACCESS_FORWARDER_CONFIG = Path("/etc/remnanode-access-forwarder.json")
SYSCTL_BBR = Path("/etc/sysctl.d/99-vpn-bbr.conf")
SYSCTL_TUNE = Path("/etc/sysctl.d/99-remnanode-manager-network.conf")
NETWORK_BASELINE = STATE_DIR / "network-baseline.json"
INSTALL_STATE_FILE = STATE_DIR / "install-state.json"
SSH_STATE_FILE = STATE_DIR / "ssh-state.json"
SSH_MANAGED_CONFIG = Path("/etc/ssh/sshd_config.d/00-remnanode-manager.conf")
SSH_SOCKET_OVERRIDE = Path("/etc/systemd/system/ssh.socket.d/90-remnanode-manager.conf")
MANAGED_ROOT_AUTHORIZED_KEYS = STATE_DIR / "root-authorized_keys"
ROOT_AUTHORIZED_KEYS = Path("/root/.ssh/authorized_keys")
ADMIN_PASSWORD = os.environ["RNM_ADMIN_PASSWORD"]
BIND = os.getenv("RNM_BIND", "127.0.0.1")
PORT = int(os.getenv("RNM_PORT", "8765"))
BASE_PATH = "/" + os.environ["RNM_BASE_PATH"].strip("/")
DOMAIN_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
TAG_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}$")
SSH_KEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+([A-Za-z0-9+/]+={0,3})(?:\s+.*)?$")
SESSION_TTL = 12 * 3600
LOGIN_LIMIT = 5
attempts = {}
attempts_guard = threading.Lock()
sessions = {}
sessions_guard = threading.Lock()
cache = {}
cache_guard = threading.Lock()
install_guard = threading.Lock()
install_state_guard = threading.Lock()
install_state = {
    "phase": "idle", "message": "Установка ещё не запускалась.",
    "tag": "", "started": 0, "finished": 0, "log": "", "failed_phase": "",
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
        raise RuntimeError(result.stdout.strip()[-4000:] or f"Команда завершилась с ошибкой: {args[0]}")
    return result.stdout.strip()


def cached(key, ttl, producer):
    """Return a memoised value; ttl may be a callable that inspects the value."""
    now = time.monotonic()
    with cache_guard:
        item = cache.get(key)
        if item and now < item[0]:
            return item[1]
    value = producer()
    lifetime = ttl(value) if callable(ttl) else ttl
    with cache_guard:
        cache[key] = (time.monotonic() + lifetime, value)
    return value


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip().split("%", 1)[0]))
    except (TypeError, ValueError):
        return ""


def fetch_public_ip(timeout=4):
    try:
        return normalize_ip(
            urllib.request.urlopen("https://api.ipify.org", timeout=timeout).read().decode()
        ) or "unknown"
    except Exception:
        return "unknown"


def public_egress_ip():
    return cached("public_ip", lambda value: 60 if value == "unknown" else 900, fetch_public_ip)


def server_addresses(include_public=True, public_ip=None):
    entries = []
    seen = set()
    try:
        interfaces = json.loads(run(
            ["ip", "-j", "address", "show", "scope", "global"],
            check=False, timeout=10,
        ) or "[]")
    except (json.JSONDecodeError, TypeError):
        interfaces = []
    for interface in interfaces:
        name = str(interface.get("ifname") or "interface")
        for address in interface.get("addr_info") or []:
            value = normalize_ip(address.get("local", ""))
            if not value or value in seen:
                continue
            parsed = ipaddress.ip_address(value)
            if not parsed.is_global:
                continue
            seen.add(value)
            entries.append({
                "value": value,
                "family": f"IPv{parsed.version}",
                "source": name,
            })
    if include_public:
        public_ip = normalize_ip(public_ip) if public_ip else public_egress_ip()
        if public_ip and public_ip != "unknown" and public_ip not in seen:
            parsed = ipaddress.ip_address(public_ip)
            entries.append({
                "value": public_ip,
                "family": f"IPv{parsed.version}",
                "source": "public egress / NAT",
            })
    return entries


def resolve_domain_addresses(domain):
    addresses = set()
    try:
        answers = socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Не удалось получить DNS-записи {domain}: {exc}.") from exc
    for answer in answers:
        value = normalize_ip(answer[4][0])
        if value:
            addresses.add(value)
    return sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))


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
                raise RuntimeError(f"Превышено время ожидания команды: {args[0]}")
        code = process.wait(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
    if code:
        raise RuntimeError(f"Команда завершилась с кодом {code}: {' '.join(args)}")


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


def command_ok(args, timeout=20):
    try:
        return subprocess.run(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def load_ssh_state():
    if not SSH_STATE_FILE.exists():
        return {}
    try:
        value = json.loads(SSH_STATE_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def save_ssh_state(value):
    atomic_write(SSH_STATE_FILE, json.dumps(value, ensure_ascii=False, indent=2) + "\n", 0o600)


def ssh_config_files():
    files = [Path("/etc/ssh/sshd_config")]
    dropin = Path("/etc/ssh/sshd_config.d")
    if dropin.exists():
        files.extend(sorted(dropin.glob("*.conf")))
    return [path for path in files if path.exists() and path != SSH_MANAGED_CONFIG]


def ensure_sshd_runtime():
    runtime = Path("/run/sshd")
    if runtime.exists() and not runtime.is_dir():
        raise RuntimeError("/run/sshd существует, но это не каталог.")
    runtime.mkdir(parents=True, exist_ok=True)
    os.chown(runtime, 0, 0)
    os.chmod(runtime, 0o755)


def backup_ssh_configuration(label):
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(2)
    target = BACKUP_DIR / f"{stamp}-{label}"
    target.mkdir(parents=True, exist_ok=False)
    os.chmod(target, 0o700)
    paths = ssh_config_files()
    if SSH_MANAGED_CONFIG.exists():
        paths.append(SSH_MANAGED_CONFIG)
    if SSH_SOCKET_OVERRIDE.exists():
        paths.append(SSH_SOCKET_OVERRIDE)
    if MANAGED_ROOT_AUTHORIZED_KEYS.exists():
        paths.append(MANAGED_ROOT_AUTHORIZED_KEYS)
    manifest = []
    for source in paths:
        relative = str(source).lstrip("/")
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        manifest.append(str(source))
    payload = {
        "files": manifest,
        "managed": [str(SSH_MANAGED_CONFIG), str(SSH_SOCKET_OVERRIDE), str(MANAGED_ROOT_AUTHORIZED_KEYS)],
    }
    atomic_write(target / "manifest.json", json.dumps(payload, indent=2) + "\n", 0o600)
    return target


def restore_ssh_configuration(target):
    target = Path(target)
    manifest_file = target / "manifest.json"
    if not manifest_file.exists() or BACKUP_DIR not in target.parents:
        raise ValueError("Резервная копия SSH не найдена или повреждена.")
    payload = json.loads(manifest_file.read_text(encoding="utf-8"))
    manifest = payload.get("files", []) if isinstance(payload, dict) else payload
    for destination in (SSH_MANAGED_CONFIG, SSH_SOCKET_OVERRIDE, MANAGED_ROOT_AUTHORIZED_KEYS):
        destination.unlink(missing_ok=True)
    for name in manifest:
        destination = Path(name)
        if destination == ROOT_AUTHORIZED_KEYS:
            continue
        source = target / str(destination).lstrip("/")
        if not source.exists():
            raise RuntimeError(f"В резервной копии нет файла: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def sshd_settings():
    ensure_sshd_runtime()
    output = run([
        "sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1",
    ], check=False, timeout=20)
    values = {}
    ports = []
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        value = value.strip()
        if not key:
            continue
        if key == "port" and value.isdigit():
            ports.append(int(value))
        elif key not in values:
            values[key] = value
    values["ports"] = sorted(set(ports)) or [22]
    return values


def authorized_key_fingerprints():
    fingerprints = []
    for path in (MANAGED_ROOT_AUTHORIZED_KEYS, ROOT_AUTHORIZED_KEYS):
        try:
            if not path.exists():
                continue
        except OSError:
            continue
        output = run(["ssh-keygen", "-lf", str(path)], check=False, timeout=20)
        fingerprints.extend(
            line.strip() for line in output.splitlines()
            if re.match(r"^\d+\s+(?:SHA256:|MD5:)", line.strip())
        )
    return list(dict.fromkeys(fingerprints))


def local_port_ready(port):
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=2):
            return True
    except OSError:
        return False


def ssh_socket_available():
    return command_ok(["systemctl", "cat", "ssh.socket"])


def ssh_service_name():
    if command_ok(["systemctl", "cat", "ssh.service"]):
        return "ssh.service"
    return "sshd.service"


def write_ssh_managed_config(ports, password_auth):
    unique_ports = sorted({int(port) for port in ports})
    if not unique_ports or any(not 1 <= port <= 65535 for port in unique_ports):
        raise ValueError("SSH-порт должен быть в диапазоне 1–65535.")
    auth = "yes" if password_auth else "no"
    root_login = "yes" if password_auth else "prohibit-password"
    body = "# Managed by RemnaNode Node Forge.\n"
    body += "".join(f"Port {port}\n" for port in unique_ports)
    body += "PubkeyAuthentication yes\n"
    body += f"AuthorizedKeysFile {MANAGED_ROOT_AUTHORIZED_KEYS} .ssh/authorized_keys\n"
    body += f"PasswordAuthentication {auth}\n"
    body += f"KbdInteractiveAuthentication {auth}\n"
    body += f"PermitRootLogin {root_login}\n"
    atomic_write(SSH_MANAGED_CONFIG, body, 0o600)
    if ssh_socket_available():
        socket_body = "[Socket]\nListenStream=\n"
        socket_body += "".join(f"ListenStream={port}\n" for port in unique_ports)
        atomic_write(SSH_SOCKET_OVERRIDE, socket_body, 0o644)


def verify_ssh_auth_settings(password_auth):
    effective = sshd_settings()
    expected = "yes" if password_auth else "no"
    expected_root = "yes" if password_auth else "prohibit-password"
    mismatches = []
    for key in ("passwordauthentication", "kbdinteractiveauthentication"):
        if effective.get(key) != expected:
            mismatches.append(f"{key}={effective.get(key, 'missing')}")
    if effective.get("permitrootlogin") != expected_root:
        mismatches.append(f"permitrootlogin={effective.get('permitrootlogin', 'missing')}")
    if effective.get("pubkeyauthentication") != "yes":
        mismatches.append(f"pubkeyauthentication={effective.get('pubkeyauthentication', 'missing')}")
    authorized_files = effective.get("authorizedkeysfile", "").split()
    if str(MANAGED_ROOT_AUTHORIZED_KEYS) not in authorized_files or ".ssh/authorized_keys" not in authorized_files:
        mismatches.append(f"authorizedkeysfile={effective.get('authorizedkeysfile', 'missing')}")
    if mismatches:
        raise RuntimeError("OpenSSH не применил настройки входа: " + ", ".join(mismatches))


def reload_ssh_stack():
    ensure_sshd_runtime()
    run(["sshd", "-t"], timeout=20)
    run(["systemctl", "daemon-reload"], timeout=30)
    if ssh_socket_available() and (
        command_ok(["systemctl", "is-active", "--quiet", "ssh.socket"])
        or command_ok(["systemctl", "is-enabled", "--quiet", "ssh.socket"])
    ):
        run(["systemctl", "restart", "ssh.socket"], timeout=30)
    else:
        service = ssh_service_name()
        if not command_ok(["systemctl", "reload", service]):
            run(["systemctl", "restart", service], timeout=30)


def validate_public_key(value):
    value = " ".join(value.strip().split())
    if not value:
        return ""
    if len(value) > 16384 or not SSH_KEY_RE.fullmatch(value):
        raise ValueError("Вставьте один полный публичный ключ OpenSSH, например ssh-ed25519 AAAA... comment.")
    probe = Path("/run") / f"node-forge-key-{secrets.token_hex(6)}"
    try:
        atomic_write(probe, value + "\n", 0o600)
        if not command_ok(["ssh-keygen", "-lf", str(probe)]):
            raise ValueError("ssh-keygen не принял этот публичный ключ.")
    finally:
        probe.unlink(missing_ok=True)
    return value


def install_root_public_key(value):
    value = validate_public_key(value)
    if not value:
        return False
    MANAGED_ROOT_AUTHORIZED_KEYS.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(MANAGED_ROOT_AUTHORIZED_KEYS.parent, 0o700)
    current = MANAGED_ROOT_AUTHORIZED_KEYS.read_text(encoding="utf-8", errors="replace").splitlines() if MANAGED_ROOT_AUTHORIZED_KEYS.exists() else []
    identity = tuple(value.split()[:2])
    if any(tuple(line.strip().split()[:2]) == identity for line in current if line.strip() and not line.lstrip().startswith("#")):
        return False
    with MANAGED_ROOT_AUTHORIZED_KEYS.open("a", encoding="utf-8") as handle:
        if current and current[-1].strip():
            handle.write("\n")
        handle.write(value + "\n")
    os.chmod(MANAGED_ROOT_AUTHORIZED_KEYS, 0o600)
    return True


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


def create_session():
    """Issue a random per-login session; each one carries its own CSRF token."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    with sessions_guard:
        for key in [key for key, value in sessions.items() if value["expires"] < now]:
            sessions.pop(key, None)
        sessions[token] = {"expires": now + SESSION_TTL, "csrf": secrets.token_urlsafe(32)}
    return token


def get_session(token):
    if not token:
        return None
    now = time.time()
    with sessions_guard:
        session = sessions.get(token)
        if not session:
            return None
        if session["expires"] < now:
            sessions.pop(token, None)
            return None
        session["expires"] = now + SESSION_TTL
        return dict(session)


def drop_session(token):
    with sessions_guard:
        sessions.pop(token, None)


def login_allowed(ip, now=None):
    now = time.time() if now is None else now
    with attempts_guard:
        for key in list(attempts):
            attempts[key] = [stamp for stamp in attempts[key] if now - stamp < 60]
            if not attempts[key]:
                del attempts[key]
        return len(attempts.get(ip, [])) < LOGIN_LIMIT


def record_login_failure(ip, now=None):
    with attempts_guard:
        attempts.setdefault(ip, []).append(time.time() if now is None else now)


def reset_login_failures(ip):
    with attempts_guard:
        attempts.pop(ip, None)


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
                    "failed_phase": install_state.get("phase"),
                    "message": "Панель перезапустилась во время установки. Запустите установку ещё раз.",
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
    public_ip = public_egress_ip()
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
        "ssh": ssh_status(),
    }


def fetch_image_tags():
    """Return (tags, fetched_from_docker_hub)."""
    tags = ["latest"]
    try:
        request = urllib.request.Request(
            "https://hub.docker.com/v2/repositories/remnawave/node/tags?page_size=50&ordering=last_updated",
            headers={"User-Agent": "RemnaNode-Node-Forge/2.0"},
        )
        payload = json.loads(urllib.request.urlopen(request, timeout=6).read().decode())
        names = [item.get("name", "") for item in payload.get("results", [])]
        stable = [name for name in names if re.fullmatch(r"\d+(?:\.\d+){1,3}", name)]
        stable.sort(key=lambda value: tuple(int(x) for x in value.split(".")), reverse=True)
        tags.extend(stable)
        if "dev" in names:
            tags.append("dev")
        return list(dict.fromkeys(tags)), True
    except Exception:
        tags.extend(["3.4.1", "dev"])
        return list(dict.fromkeys(tags)), False


def image_tags():
    tags, _fresh = cached("image_tags", lambda value: 1800 if value[1] else 120, fetch_image_tags)
    return tags


def warm_caches():
    for producer in (public_egress_ip, image_tags):
        try:
            producer()
        except Exception:
            pass


def ensure_cert_volume(config):
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("В Compose должен быть раздел services.")
    service = config["services"].get("remnanode")
    if not isinstance(service, dict):
        raise ValueError("Сервис remnanode не найден.")
    volumes = service.setdefault("volumes", [])
    if not isinstance(volumes, list):
        raise ValueError("remnanode.volumes должен быть списком.")
    mount = "/var/lib/remnawave/configs/xray/ssl:/var/lib/remnawave/configs/xray/ssl:ro"
    host_ssl_dir = str(SSL_DIR).replace("\\", "/")
    if not any(isinstance(item, str) and item.split(":", 1)[0] == host_ssl_dir for item in volumes):
        volumes.append(mount)
        return True
    return False


def ensure_log_volume(config):
    service = config.get("services", {}).get("remnanode") if isinstance(config, dict) else None
    if not isinstance(service, dict):
        raise ValueError("Сервис remnanode не найден.")
    volumes = service.setdefault("volumes", [])
    if not isinstance(volumes, list):
        raise ValueError("remnanode.volumes должен быть списком.")
    host_dir = str(XRAY_LOG_DIR)
    mount = f"{host_dir}:{host_dir}"
    if not any(isinstance(item, str) and item.split(":", 1)[0] == host_dir for item in volumes):
        volumes.append(mount)
        return True
    return False


def write_compose(config, label):
    ensure_log_volume(config)
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
        raise ValueError("Сначала вставьте docker-compose.yml.")
    if len(raw.encode()) > 900_000:
        raise ValueError("Файл Compose слишком большой.")
    config = yaml.safe_load(raw)
    if form.get("cert_volume") == ["1"]:
        ensure_cert_volume(config)
    else:
        if not isinstance(config, dict) or not isinstance(config.get("services"), dict) or not isinstance(config["services"].get("remnanode"), dict):
            raise ValueError("В Compose должен быть сервис services.remnanode.")
    saved = write_compose(config, "compose")
    return f"Compose проверен и сохранён. Теперь выберите версию RemnaNode и запустите установку. Резервная копия: {saved}"


def redeem_pair_code(node_id, code):
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", code):
        raise ValueError("Введите корректный одноразовый код подключения.")
    request = urllib.request.Request(
        "https://meltun.org/api/admin/node-logs/pair",
        data=json.dumps({"node_id": node_id, "code": code}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 401, 404, 410, 422):
            try:
                detail = json.loads(exc.read(2048)).get("detail", "")
            except (ValueError, AttributeError):
                detail = ""
            raise ValueError(str(detail)[:300] or "Проверьте ID ноды, код и публичный IP в MelTun.") from exc
        raise RuntimeError(f"MelTun не подключил ноду (HTTP {exc.code}).") from exc
    token = payload.get("token", "")
    if not re.fullmatch(r"[a-zA-Z0-9_-]{40,128}", token):
        raise RuntimeError("MelTun вернул некорректный токен ноды.")
    return token


def configure_access_forwarder(form):
    endpoint = form.get("endpoint", [""])[0].strip()
    node_id = form.get("node_id", [""])[0].strip()
    token = form.get("token", [""])[0].strip()
    pair_code = form.get("pair_code", [""])[0].strip()
    log_timezone = form.get("log_timezone", ["UTC"])[0].strip()
    if endpoint != "https://meltun.org/api/admin/node-logs/ingest":
        raise ValueError("Адрес приёма должен быть https://meltun.org/api/admin/node-logs/ingest")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", node_id):
        raise ValueError("ID ноды может содержать только латинские буквы, цифры, точки, подчёркивания и дефисы.")
    if log_timezone not in ("UTC", "Europe/Moscow"):
        raise ValueError("Неподдерживаемый часовой пояс логов Xray.")
    if pair_code:
        token = redeem_pair_code(node_id, pair_code)
    elif not re.fullmatch(r"[a-zA-Z0-9_-]{40,128}", token):
        raise ValueError("Введите одноразовый код из веб-админки MelTun.")
    atomic_write(ACCESS_FORWARDER_CONFIG, json.dumps({"endpoint": endpoint, "node_id": node_id, "token": token, "log_timezone": log_timezone}), mode=0o600)
    run(["systemctl", "enable", "--now", "remnanode-access-forwarder.service"])
    run(["systemctl", "restart", "remnanode-access-forwarder.service"])
    return "Нода подключена, передача access log Xray настроена. Проверьте «Последний пакет» в веб-админке MelTun."


def install_worker(tag):
    try:
        with install_guard:
            save_install_state(
                phase="pulling", message=f"Загружаю образ remnawave/node:{tag}",
                started=int(time.time()), finished=0, tag=tag, log="", failed_phase="",
            )
            install_log(f"Выбран образ: remnawave/node:{tag}")
            if any(site["public_https"] for site in managed_sites()):
                install_log(
                    "ВНИМАНИЕ: nginx держит публичный TCP 443 для HTTPS-сайта. Если inbound Xray "
                    "слушает 443, отключите публичный 443 в разделе «Сертификаты», иначе нода не запустится."
                )
            run_live(["docker", "pull", f"remnawave/node:{tag}"], timeout=1200)
            save_install_state(phase="starting", message="Создаю и запускаю контейнер RemnaNode.")
            run_live(
                ["docker", "compose", "up", "-d", "--force-recreate", "remnanode"],
                cwd=COMPOSE_DIR, timeout=600,
            )
            save_install_state(phase="verifying", message="Жду, пока контейнер перейдёт в состояние running.")
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
                raise RuntimeError(f"Контейнер не перешёл в состояние running (сейчас: {state or 'отсутствует'}).")
            image = run(
                ["docker", "inspect", "remnanode", "--format", "{{.Config.Image}}"],
                check=False, timeout=15,
            ).strip()
            install_log(f"RemnaNode работает на образе {image or f'remnawave/node:{tag}'}.")
            save_install_state(
                phase="installed", message=f"RemnaNode {tag} установлена и работает.",
                finished=int(time.time()),
            )
    except Exception as exc:
        install_log(f"ОШИБКА: {exc}")
        save_install_state(
            phase="failed", failed_phase=install_snapshot().get("phase", ""),
            message=str(exc)[-1000:], finished=int(time.time()),
        )


def start_install(form):
    tag = form.get("version", ["latest"])[0].strip()
    if not TAG_RE.fullmatch(tag):
        raise ValueError("Некорректный тег образа.")
    if not COMPOSE_FILE.exists():
        raise ValueError("Сначала сохраните Docker Compose.")
    if install_guard.locked() or install_snapshot().get("phase") in {"queued", "pulling", "starting", "verifying"}:
        raise ValueError("Установка уже выполняется.")
    config = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("В Compose должен быть сервис services.remnanode.")
    service = config["services"].get("remnanode")
    if not isinstance(service, dict):
        raise ValueError("Сервис remnanode не найден.")
    service["image"] = f"remnawave/node:{tag}"
    write_compose(config, f"version-{tag}")
    save_install_state(
        phase="queued", message=f"Установка remnawave/node:{tag} поставлена в очередь.",
        tag=tag, started=int(time.time()), finished=0, log="", failed_phase="",
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
    location / {{ try_files $uri $uri/ =404; }}
}}
'''


def parse_port_owners(output):
    owners = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        names = re.findall(r'"([^"]+)",pid=', line)
        owners.update(names or ["unknown"])
    return owners


def port_owners(port):
    """Process names listening on TCP port, e.g. {"nginx"} or {"xray"}."""
    return parse_port_owners(run(["ss", "-H", "-lntp", f"sport = :{int(port)}"], check=False, timeout=10))


def nginx_can_serve_public_https():
    owners = port_owners(443)
    return not owners or owners == {"nginx"}


def set_public_https(current, enabled):
    """Add or remove the public 443 listeners of a Node Forge TLS site."""
    listeners = "    listen 443 ssl;\n    listen [::]:443 ssl;\n"
    marker = "    # Internal endpoint used as the REALITY self-steal target.\n"
    if marker not in current:
        raise RuntimeError("Сайт не похож на TLS-сайт Node Forge.")
    without = current.replace(listeners + marker, marker)
    return without.replace(marker, listeners + marker, 1) if enabled else without


def certificate_days_left(domain):
    path = SSL_DIR / f"{domain}.pem"
    if not path.exists():
        return None
    output = run(["openssl", "x509", "-enddate", "-noout", "-in", str(path)], check=False, timeout=10)
    value = output.partition("=")[2].strip()
    try:
        expires = calendar.timegm(time.strptime(value, "%b %d %H:%M:%S %Y %Z"))
    except ValueError:
        return None
    return int((expires - time.time()) // 86400)


def managed_sites():
    sites = []
    for available in sorted(Path("/etc/nginx/sites-available").glob("rnm-*.conf")):
        domain = available.name[4:-5]
        if not DOMAIN_RE.fullmatch(domain):
            continue
        try:
            text = available.read_text(encoding="utf-8")
        except OSError:
            continue
        tls = "# Internal endpoint used as the REALITY self-steal target." in text
        sites.append({
            "domain": domain, "tls": tls,
            "public_https": tls and "listen 443 ssl;" in text,
            "days_left": certificate_days_left(domain),
        })
    return sites


def toggle_public_https(form):
    domain = form.get("domain", [""])[0].strip().lower()
    enabled = form.get("enabled") == ["1"]
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Некорректный домен.")
    available = Path("/etc/nginx/sites-available") / f"rnm-{domain}.conf"
    if not available.exists():
        raise ValueError(f"Сайт {domain} не создан Node Forge.")
    if enabled:
        owners = port_owners(443) - {"nginx"}
        if owners:
            raise ValueError(f"TCP 443 уже занят: {', '.join(sorted(owners))}. Сначала уберите inbound с порта 443.")
    current = available.read_text(encoding="utf-8")
    candidate = set_public_https(current, enabled)
    if candidate == current:
        return f"Публичный HTTPS для {domain} уже {'включён' if enabled else 'выключен'}."
    backup([available], f"public-https-{domain}")
    try:
        atomic_write(available, candidate, 0o644)
        run(["nginx", "-t"], timeout=20)
        run(["systemctl", "reload", "nginx"], timeout=20)
    except Exception:
        atomic_write(available, current, 0o644)
        run(["systemctl", "reload", "nginx"], check=False, timeout=20)
        raise
    if enabled:
        return f"Сайт {domain} и панель доступны по HTTPS на TCP 443."
    return f"nginx освободил публичный TCP 443 для {domain}; TLS-заглушка Reality осталась на 127.0.0.1:8443."


def nginx_manager_location():
    return f'''    location = {BASE_PATH} {{ return 302 {BASE_PATH}/; }}
    location ^~ {BASE_PATH}/ {{
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
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
    }}
'''


def nginx_tls_config(domain, public_https=True):
    public_listeners = "    listen 443 ssl;\n    listen [::]:443 ssl;\n" if public_https else ""
    manager_location = nginx_manager_location()
    return nginx_http_config(domain) + f'''
server {{
{public_listeners}    # Internal endpoint used as the REALITY self-steal target.
    listen 127.0.0.1:8443 ssl;
    server_name {domain};
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:RNMSSL:10m;
    ssl_session_timeout 1d;
    root /var/www/remnanode-decoy/{domain};
    index index.html;
{manager_location}
    location / {{ try_files $uri $uri/ =404; }}
}}
'''


def add_manager_location(current):
    if f"location ^~ {BASE_PATH}/" in current:
        return current
    marker = "    location / { try_files $uri $uri/ =404; }"
    tls_start = current.index("# Internal endpoint used as the REALITY self-steal target.")
    insert_at = current.find(marker, tls_start)
    if insert_at < 0:
        raise RuntimeError("Не найден location TLS-заглушки в управляемом сайте")
    return current[:insert_at] + nginx_manager_location() + current[insert_at:]


def refresh_https_manager_routes():
    """Upgrade only Node Forge-owned TLS sites, preserving a rollback copy."""
    updated = []
    for available in Path("/etc/nginx/sites-available").glob("rnm-*.conf"):
        domain = available.name[4:-5]
        if not DOMAIN_RE.fullmatch(domain):
            continue
        current = available.read_text(encoding="utf-8")
        if "# Internal endpoint used as the REALITY self-steal target." not in current:
            continue
        if not (Path("/etc/letsencrypt/live") / domain / "fullchain.pem").exists():
            continue
        candidate = add_manager_location(current)
        if candidate != current:
            updated.append((available, current, candidate))
    if not updated:
        return []
    backup([item[0] for item in updated], "manager-https")
    try:
        for available, _, candidate in updated:
            atomic_write(available, candidate, 0o644)
        run(["nginx", "-t"], timeout=20)
        run(["systemctl", "reload", "nginx"], timeout=20)
    except Exception:
        for available, original, _ in updated:
            atomic_write(available, original, 0o644)
        run(["systemctl", "reload", "nginx"], check=False, timeout=20)
        raise
    return [available.name[4:-5] for available, _, _ in updated]


def create_decoy_site(domain):
    site_root = Path("/var/www/remnanode-decoy") / domain
    site_root.mkdir(parents=True, exist_ok=True)
    # The manager runs with UMask=0077. Nginx needs to traverse the directory
    # and read the generated public assets explicitly.
    os.chmod(site_root, 0o755)

    brands = [
        ("Northline", "Infrastructure services", "#55d6be", "#122a3a"),
        ("LumaGrid", "Connected workspace", "#7bc6ff", "#16263f"),
        ("Cedar Cloud", "Managed edge platform", "#9dd67d", "#183027"),
        ("Harbor Stack", "Reliable application delivery", "#f2b66d", "#352719"),
        ("Vertex Lane", "Distributed systems", "#b9a3ff", "#282044"),
    ]
    summaries = [
        "Service availability and scheduled maintenance information.",
        "A lightweight gateway for regional application services.",
        "Operational status for the public delivery platform.",
        "Connectivity, storage and API service overview.",
    ]
    locations = ["Central Europe", "Northern Europe", "European edge", "Regional network"]
    brand, product, accent, panel = secrets.choice(brands)
    summary = secrets.choice(summaries)
    location = secrets.choice(locations)
    deployment = secrets.token_hex(4).upper()
    updated = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    safe_domain = html.escape(domain)
    safe_brand = html.escape(brand)
    safe_product = html.escape(product)
    safe_summary = html.escape(summary)
    safe_location = html.escape(location)

    page = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{safe_summary}">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <title>{safe_brand} — Service status</title>
  <style>
    :root {{ color-scheme: dark; --accent:{accent}; --panel:{panel}; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:#09131d; color:#e8f1f7; font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif; }}
    header,main,footer {{ width:min(920px,calc(100% - 40px)); margin:auto; }}
    header {{ display:flex; align-items:center; justify-content:space-between; padding:28px 0; border-bottom:1px solid #263746; }}
    .brand {{ font-size:19px; font-weight:750; letter-spacing:-.02em; }}
    .brand span,.muted {{ color:#91a8b8; }}
    .pill {{ display:inline-flex; align-items:center; gap:8px; padding:7px 11px; border:1px solid #315061; border-radius:999px; color:#cfe4ec; }}
    .dot {{ width:8px; height:8px; border-radius:50%; background:var(--accent); box-shadow:0 0 14px var(--accent); }}
    main {{ padding:72px 0 64px; }}
    h1 {{ max-width:680px; margin:0 0 16px; font-size:clamp(36px,7vw,64px); line-height:1.03; letter-spacing:-.055em; }}
    .lead {{ max-width:620px; margin:0 0 38px; color:#a9becb; font-size:18px; }}
    .grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }}
    .card {{ padding:22px; border:1px solid #294253; border-radius:14px; background:linear-gradient(145deg,var(--panel),#0d1b27); }}
    .card strong {{ display:block; margin-bottom:18px; font-size:16px; }}
    .ok {{ color:var(--accent); font-weight:700; }}
    footer {{ display:flex; justify-content:space-between; gap:20px; padding:24px 0 36px; border-top:1px solid #263746; color:#78909f; font-size:13px; }}
    @media (max-width:680px) {{ .grid {{ grid-template-columns:1fr; }} header,footer {{ align-items:flex-start; flex-direction:column; }} main {{ padding-top:48px; }} }}
  </style>
</head>
<body>
  <header><div class="brand">{safe_brand} <span>/ {safe_product}</span></div><div class="pill"><i class="dot"></i>All systems operational</div></header>
  <main>
    <p class="muted">{safe_location} · {safe_domain}</p>
    <h1>Services are operating normally.</h1>
    <p class="lead">{safe_summary}</p>
    <section class="grid" aria-label="Service health">
      <article class="card"><strong>Edge gateway</strong><span class="ok">Operational</span></article>
      <article class="card"><strong>Application API</strong><span class="ok">Operational</span></article>
      <article class="card"><strong>Object storage</strong><span class="ok">Operational</span></article>
    </section>
  </main>
  <footer><span>Last checked {updated}</span><span>Deployment {deployment}</span></footer>
</body>
</html>
'''
    favicon = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="{panel}"/><path d="M17 42V22h8l7 10 7-10h8v20h-7V31l-8 11-8-11v11z" fill="{accent}"/></svg>'''
    status = {
        "status": "operational",
        "region": location,
        "updated": updated,
        "deployment": deployment.lower(),
    }
    atomic_write(site_root / "index.html", page, 0o644)
    atomic_write(site_root / "favicon.svg", favicon + "\n", 0o644)
    atomic_write(site_root / "robots.txt", "User-agent: *\nAllow: /\n", 0o644)
    atomic_write(site_root / "status.json", json.dumps(status, ensure_ascii=False, indent=2) + "\n", 0o644)
    return site_root


def sync_certificate(domain):
    lineage = Path("/etc/letsencrypt/live") / domain
    if not (lineage / "fullchain.pem").exists():
        raise RuntimeError("Let's Encrypt не создал файлы сертификата.")
    shutil.copyfile(lineage / "fullchain.pem", SSL_DIR / f"{domain}.pem", follow_symlinks=True)
    shutil.copyfile(lineage / "privkey.pem", SSL_DIR / f"{domain}.key", follow_symlinks=True)
    os.chmod(SSL_DIR / f"{domain}.pem", 0o644)
    os.chmod(SSL_DIR / f"{domain}.key", 0o600)


def issue_certificate(form):
    domain = form.get("domain", [""])[0].strip().lower().rstrip(".")
    email = form.get("email", [""])[0].strip()
    selected_ip = normalize_ip(form.get("expected_ip", [""])[0])
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Введите корректный публичный домен.")
    if "@" not in email or len(email) > 254:
        raise ValueError("Введите корректный email.")
    available_ips = {entry["value"] for entry in server_addresses()}
    if not selected_ip:
        raise ValueError("Выберите IP сервера, на который должен указывать домен.")
    if selected_ip not in available_ips:
        raise ValueError("Выбранного IP больше нет на сервере. Обновите страницу и выберите снова.")
    addresses = resolve_domain_addresses(domain)
    dns_forced = form.get("force_dns") == ["1"]
    if selected_ip not in addresses and not dns_forced:
        resolved = ", ".join(addresses) or "пустоту"
        raise ValueError(f"DNS {domain} указывает на {resolved}, а выбран IP сервера {selected_ip}.")
    create_decoy_site(domain)
    available = Path("/etc/nginx/sites-available") / f"rnm-{domain}.conf"
    enabled = Path("/etc/nginx/sites-enabled") / available.name
    backup([available], f"nginx-{domain}")
    current = available.read_text(encoding="utf-8") if available.exists() else ""
    marker = "# Internal endpoint used as the REALITY self-steal target."
    has_live_tls = marker in current and (Path("/etc/letsencrypt/live") / domain / "fullchain.pem").exists()
    previous_public = has_live_tls and "listen 443 ssl;" in current
    # An existing TLS site already answers ACME on port 80; keep it so the
    # REALITY fallback on 127.0.0.1:8443 stays up while certbot runs.
    if not has_live_tls:
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
    requested_public = form.get("public_https") == ["1"] or previous_public
    public_https = requested_public and nginx_can_serve_public_https()
    atomic_write(available, nginx_tls_config(domain, public_https), 0o644)
    run(["nginx", "-t"], timeout=20)
    run(["systemctl", "reload", "nginx"], timeout=20)
    run(["systemctl", "enable", "--now", "certbot.timer"], check=False, timeout=20)
    volume_note = ""
    if form.get("cert_volume") == ["1"] and COMPOSE_FILE.exists():
        config = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        if ensure_cert_volume(config):
            write_compose(config, "certificate-volume")
            run(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR, timeout=300)
            volume_note = " Volume сертификатов добавлен в Compose."
    elif form.get("cert_volume") == ["1"]:
        volume_note = " Compose ещё не сохранён — оставьте флажок volume сертификатов включённым при его сохранении."
    containers = run(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False).splitlines()
    if form.get("restart_node") == ["1"] and "remnanode" in containers:
        run(["docker", "restart", "remnanode"], timeout=120)
    dns_note = (
        f" DNS совпадает с выбранным IP {selected_ip}."
        if selected_ip in addresses else
        f" Несовпадение DNS с IP {selected_ip} проигнорировано по вашему выбору."
    )
    if public_https:
        https_note = " Сайт и панель доступны по HTTPS на TCP 443."
    elif requested_public:
        https_note = " TCP 443 занят другим процессом, поэтому публичный HTTPS не включён; TLS-заглушка Reality работает на 127.0.0.1:8443."
    else:
        https_note = " TLS-заглушка Reality работает на 127.0.0.1:8443, публичный 443 свободен для Xray."
    return f"Сертификат выпущен: {SSL_DIR}/{domain}.pem и {domain}.key.{dns_note}{https_note}{volume_note}"


def parse_x25519(output):
    """Parse `xray x25519` output.

    Older Xray prints "Private key / Public key"; newer releases print
    "PrivateKey / Password / Hash32", where Password is the public key.
    """
    private = public = ""
    for line in output.splitlines():
        label, separator, value = line.partition(":")
        if not separator:
            continue
        label = re.sub(r"[^a-z0-9]", "", label.lower())
        value = value.strip()
        if label == "privatekey":
            private = value
        elif label in ("publickey", "password"):
            public = value
    key_re = re.compile(r"[A-Za-z0-9_-]{42,44}={0,1}")
    if not (key_re.fullmatch(private or "") and key_re.fullmatch(public or "")):
        raise RuntimeError("Не удалось разобрать ключи X25519 из вывода Xray: " + output[-1000:])
    return private, public


def reality_keys():
    output = run(["docker", "exec", "remnanode", "/usr/local/bin/xray", "x25519"], timeout=30)
    return parse_x25519(output)


def generate_inbound(form):
    kind = form.get("kind", ["reality"])[0]
    tag = form.get("tag", ["VLESS_REALITY"])[0].strip()
    domain = form.get("inbound_domain", [""])[0].strip().lower()
    try:
        port = int(form.get("inbound_port", ["2053"])[0])
    except ValueError as exc:
        raise ValueError("Порт должен быть числом.") from exc
    if not TAG_RE.fullmatch(tag) or not DOMAIN_RE.fullmatch(domain) or not 1 <= port <= 65535:
        raise ValueError("Проверьте tag, домен и порт.")
    meta = {}
    if kind == "reality":
        reserved = {80: "nginx (HTTP и ACME)", 8443: "TLS-заглушка Reality nginx", PORT: "панель Node Forge"}
        reserved.update({ssh_port: "SSH" for ssh_port in current_ssh_ports()})
        if port in reserved:
            raise ValueError(f"TCP {port} занят: {reserved[port]}. Выберите другой порт.")
        if port == 443 and "nginx" in port_owners(443):
            raise ValueError("TCP 443 сейчас занят nginx (публичный HTTPS-сайт). Отключите публичный 443 в разделе «Сертификаты» или выберите другой порт.")
        if not (SSL_DIR / f"{domain}.pem").exists() or not (Path("/etc/nginx/sites-available") / f"rnm-{domain}.conf").exists():
            raise ValueError(f"Для self-steal нужен TLS-сайт {domain} на 127.0.0.1:8443. Сначала выпустите сертификат для этого домена.")
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
            raise ValueError("Сначала выпустите сертификат для этого домена — без него Hysteria не сгенерировать.")
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
        raise ValueError("Неизвестный тип inbound.")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = GENERATED_DIR / f"{stamp}-{tag}.json"
    payload = json.dumps(inbound, ensure_ascii=False, indent=2) + "\n"
    atomic_write(path, payload, 0o600)
    atomic_write(STATE_DIR / "last-inbound.json", payload, 0o600)
    atomic_write(STATE_DIR / "last-meta.json", json.dumps(meta), 0o600)
    return f"Inbound сгенерирован: {path}"


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
    return f"Сетевые настройки применены: {', '.join(enabled) or 'возвращены исходные значения'}. Резервная копия: {saved}"


def ssh_socket_ports():
    if not ssh_socket_available():
        return []
    output = run(
        ["systemctl", "show", "ssh.socket", "--property=Listen", "--value"],
        check=False, timeout=20,
    )
    ports = []
    for line in output.splitlines():
        match = re.search(r"(?::|^)(\d{1,5})(?:\s+|$)", line.strip())
        if match and 1 <= int(match.group(1)) <= 65535:
            ports.append(int(match.group(1)))
    return sorted(set(ports))


def current_ssh_ports():
    state = load_ssh_state()
    ports = set(sshd_settings().get("ports", []))
    ports.update(ssh_socket_ports())
    ports.update(int(port) for port in state.get("active_ports", []) if str(port).isdigit())
    return sorted(port for port in ports if 1 <= port <= 65535)


def ssh_status():
    settings = sshd_settings()
    state = load_ssh_state()
    fingerprints = authorized_key_fingerprints()
    return {
        "ports": current_ssh_ports(),
        "password_auth": settings.get("passwordauthentication", "unknown"),
        "kbd_auth": settings.get("kbdinteractiveauthentication", "unknown"),
        "root_login": settings.get("permitrootlogin", "unknown"),
        "key_count": len(fingerprints),
        "fingerprints": fingerprints[:4],
        "phase": state.get("phase", "unmanaged"),
        "desired_port": state.get("desired_port", ""),
        "backup": state.get("backup", ""),
    }


def port_in_use_by_other_service(port, allowed_ports):
    output = run(["ss", "-H", "-ltnp", f"sport = :{port}"], check=False, timeout=20)
    if not output:
        return False
    if port in allowed_ports:
        return False
    return "sshd" not in output.lower() and "ssh.socket" not in output.lower()


def disable_other_port_directives():
    changed = []
    visited = set()
    for config in ssh_config_files():
        target = config.resolve() if config.is_symlink() else config
        if target in visited or target == SSH_MANAGED_CONFIG or not target.exists():
            continue
        visited.add(target)
        original = target.read_text(encoding="utf-8", errors="replace")
        lines = []
        updated = False
        for line in original.splitlines(keepends=True):
            if re.match(r"^[ \t]*Port[ \t]+\d{1,5}(?:[ \t]*(?:#.*)?)?(?:\r?\n)?$", line, re.IGNORECASE):
                newline = "\n" if line.endswith("\n") else ""
                lines.append("# Node Forge disabled previous: " + line.rstrip("\r\n") + newline)
                updated = True
            else:
                lines.append(line)
        if updated:
            mode = stat.S_IMODE(target.stat().st_mode)
            atomic_write(target, "".join(lines), mode)
            changed.append(str(config))
    return changed


def apply_ssh_access(form):
    try:
        desired_port = int(form.get("ssh_port", [""])[0])
    except ValueError as exc:
        raise ValueError("Введите корректный SSH-порт.") from exc
    if not 1 <= desired_port <= 65535:
        raise ValueError("SSH-порт должен быть в диапазоне 1–65535.")
    if desired_port in {PORT, 80, 443}:
        raise ValueError(f"Порт {desired_port} занят панелью или веб-сервисами.")
    password_auth = form.get("password_auth") == ["1"]
    public_key = form.get("public_key", [""])[0]
    active_ports = current_ssh_ports()
    if port_in_use_by_other_service(desired_port, active_ports):
        raise ValueError(f"Порт {desired_port} уже занят другим сервисом.")
    saved = backup_ssh_configuration("ssh-stage")
    try:
        key_added = install_root_public_key(public_key)
        if not password_auth and not authorized_key_fingerprints():
            raise ValueError("Нельзя выключить вход по паролю, пока у root нет ни одного корректного публичного ключа.")
        staged_ports = sorted(set(active_ports + [desired_port]))
        write_ssh_managed_config(staged_ports, password_auth)
        reload_ssh_stack()
        verify_ssh_auth_settings(password_auth)
        if not local_port_ready(desired_port):
            raise RuntimeError(f"SSH не начал слушать порт {desired_port}.")
        state = {
            "phase": "staged",
            "desired_port": desired_port,
            "active_ports": staged_ports,
            "password_auth": password_auth,
            "backup": str(saved),
            "updated": int(time.time()),
        }
        save_ssh_state(state)
    except Exception:
        restore_ssh_configuration(saved)
        reload_ssh_stack()
        raise
    key_note = " Публичный ключ добавлен." if key_added else " Публичный ключ уже был установлен или не указан."
    password_note = "включён" if password_auth else "выключен"
    return f"SSH подготовлен на портах {', '.join(map(str, staged_ports))}; вход по паролю {password_note}.{key_note} Проверьте вход на порт {desired_port}, затем подтвердите его ниже. Резервная копия: {saved}"


def finalize_ssh_access(form):
    state = load_ssh_state()
    if state.get("phase") != "staged":
        raise ValueError("Нет подготовленного SSH-порта для подтверждения.")
    desired_port = int(state["desired_port"])
    confirm = form.get("confirm_port", [""])[0].strip()
    if confirm != str(desired_port):
        raise ValueError(f"Введите {desired_port}, чтобы подтвердить, что новый порт проверен.")
    password_auth = bool(state.get("password_auth"))
    if not password_auth and not authorized_key_fingerprints():
        raise ValueError("У root нет корректного публичного ключа — старый порт не отключён.")
    if not local_port_ready(desired_port):
        raise RuntimeError(f"Порт {desired_port} не принимает подключения — старый порт оставлен.")
    saved = backup_ssh_configuration("ssh-finalize")
    try:
        changed = disable_other_port_directives()
        write_ssh_managed_config([desired_port], password_auth)
        reload_ssh_stack()
        verify_ssh_auth_settings(password_auth)
        if not local_port_ready(desired_port):
            raise RuntimeError(f"После подтверждения SSH перестал слушать порт {desired_port}.")
        state.update({
            "phase": "finalized", "active_ports": [desired_port],
            "finalize_backup": str(saved), "updated": int(time.time()),
        })
        save_ssh_state(state)
    except Exception:
        restore_ssh_configuration(saved)
        reload_ssh_stack()
        raise
    files_note = f" Старые директивы Port отключены в файлах: {len(changed)}." if changed else ""
    return f"SSH работает только на порту {desired_port}.{files_note} Вход по паролю {'включён' if password_auth else 'выключен'}."


def rollback_ssh_access():
    state = load_ssh_state()
    backup_path = state.get("backup")
    if not backup_path:
        raise ValueError("Нет сохранённой резервной копии SSH для отката.")
    restore_ssh_configuration(backup_path)
    reload_ssh_stack()
    state.update({"phase": "rolled_back", "updated": int(time.time())})
    save_ssh_state(state)
    return f"Настройки SSH восстановлены из {backup_path}."


def node_action(form):
    action = form.get("action", [""])[0]
    if action == "restart":
        run(["docker", "restart", "remnanode"], timeout=120)
        return "RemnaNode перезапущена."
    if action == "start":
        run(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR, timeout=300)
        return "RemnaNode запущена."
    if action == "pull":
        run(["docker", "compose", "pull"], cwd=COMPOSE_DIR, timeout=900)
        run(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR, timeout=300)
        return "Образ обновлён, контейнер пересоздан."
    raise ValueError("Неизвестное действие.")


LIGHT_VARS = "--bg:#f3f5f9;--bg-soft:#eceff5;--card:rgba(255,255,255,.82);--card-solid:#ffffff;--elev:#f1f4f9;--border:rgba(15,23,42,.08);--border-strong:rgba(15,23,42,.16);--text:#0f172a;--muted:#55657b;--faint:#8592a6;--accent:#0d9488;--accent-2:#6366f1;--accent-ink:#ffffff;--accent-soft:rgba(13,148,136,.10);--ok:#059669;--warn:#b45309;--danger:#dc2626;--danger-soft:rgba(220,38,38,.07);--warn-soft:rgba(217,119,6,.08);--input:#ffffff;--term:#0b1220;--shadow:0 1px 2px rgba(15,23,42,.04),0 18px 40px -24px rgba(15,23,42,.22);--glow-1:rgba(13,148,136,.10);--glow-2:rgba(99,102,241,.09);color-scheme:light"

CSS = r'''
:root{--bg:#070b12;--bg-soft:#0b111b;--card:rgba(16,23,35,.74);--card-solid:#111926;--elev:#151e2d;--border:rgba(148,163,184,.12);--border-strong:rgba(148,163,184,.22);--text:#e8edf5;--muted:#8d9bb0;--faint:#5f6d82;--accent:#5eead4;--accent-2:#818cf8;--accent-ink:#03221d;--accent-soft:rgba(94,234,212,.11);--ok:#34d399;--warn:#fbbf24;--danger:#f87171;--danger-soft:rgba(248,113,113,.10);--warn-soft:rgba(251,191,36,.09);--input:#0a101a;--term:#05080e;--shadow:0 1px 0 rgba(255,255,255,.03) inset,0 24px 50px -28px rgba(0,0,0,.7);--glow-1:rgba(94,234,212,.09);--glow-2:rgba(129,140,248,.10);--radius:16px;--radius-sm:11px;--sans:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--ease:cubic-bezier(.2,.8,.2,1);color-scheme:dark}
''' + ":root[data-theme=light]{" + LIGHT_VARS + "}@media (prefers-color-scheme:light){:root:not([data-theme]){" + LIGHT_VARS + "}}" + r'''
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:14.5px/1.55 var(--sans);font-feature-settings:"cv11","ss01","ss03";-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
::selection{background:var(--accent-soft);color:var(--text)}
.aurora{position:fixed;inset:-25vmax;z-index:0;pointer-events:none;background:radial-gradient(38vmax 28vmax at 18% 12%,var(--glow-1),transparent 62%),radial-gradient(34vmax 30vmax at 88% 18%,var(--glow-2),transparent 62%),radial-gradient(40vmax 30vmax at 55% 105%,var(--glow-1),transparent 60%)}
.grain{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.5;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:56px 56px;mask-image:radial-gradient(ellipse at 50% 0%,#000 0,transparent 70%);-webkit-mask-image:radial-gradient(ellipse at 50% 0%,#000 0,transparent 70%)}
a{color:var(--accent);text-underline-offset:3px}
code{font:12.5px var(--mono);padding:2px 6px;border-radius:6px;background:var(--elev);border:1px solid var(--border)}
.ic{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.app{position:relative;z-index:1;display:grid;grid-template-columns:252px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:20px;padding:22px 14px;border-right:1px solid var(--border);background:color-mix(in srgb,var(--bg) 72%,transparent);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.brand{display:flex;align-items:center;gap:12px;padding:2px 10px 6px;color:var(--text);text-decoration:none}
.brand svg{width:36px;height:36px;flex:none;border-radius:11px;box-shadow:0 10px 26px -10px var(--accent)}
.brand b{display:block;font-size:15.5px;font-weight:700;letter-spacing:-.015em}
.brand small{display:block;color:var(--muted);font-size:12px;font-weight:500}
.nav{display:flex;flex-direction:column;gap:2px}
.nav-label{padding:0 12px 6px;color:var(--faint);font:600 10.5px var(--mono);letter-spacing:.14em;text-transform:uppercase}
.nav a{position:relative;display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:10px;color:var(--muted);text-decoration:none;font-weight:500;transition:color .2s,background .2s}
.nav a:hover{color:var(--text);background:var(--elev)}
.nav a.active{color:var(--text);background:var(--accent-soft)}
.nav a.active:before{content:"";position:absolute;left:-14px;top:9px;bottom:9px;width:3px;border-radius:0 3px 3px 0;background:linear-gradient(var(--accent),var(--accent-2))}
.nav a.active .ic{color:var(--accent)}
.nav .badge{margin-left:auto;width:7px;height:7px;border-radius:50%;background:var(--warn);box-shadow:0 0 0 3px var(--warn-soft)}
.nav .badge.ok{background:var(--ok);box-shadow:0 0 0 3px var(--accent-soft)}
.side-foot{margin-top:auto;display:grid;gap:10px;padding:12px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--card)}
.side-foot .ip{display:flex;align-items:center;gap:9px;color:var(--muted);font:500 12.5px var(--mono);overflow-wrap:anywhere}
.tool-row{display:flex;gap:8px}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;flex:1;height:34px;padding:0 10px;border:1px solid var(--border);border-radius:9px;background:transparent;color:var(--muted);font:500 12.5px var(--sans);text-decoration:none;cursor:pointer;transition:color .2s,border-color .2s,background .2s}
.icon-btn:hover{color:var(--text);border-color:var(--border-strong);background:var(--elev)}
.icon-btn .ic{width:16px;height:16px}
.content{min-width:0;padding:28px clamp(16px,3.6vw,48px) 72px;max-width:1320px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:26px}
.crumb{color:var(--muted);font-size:12.5px;font-weight:500}
.topbar h1{margin:2px 0 0;font-size:clamp(25px,3vw,32px);font-weight:700;letter-spacing:-.03em;line-height:1.15}
.top-tools{display:flex;align-items:center;gap:10px}
.mobile-only{display:none}
.chip{display:inline-flex;align-items:center;gap:9px;height:34px;padding:0 13px;border:1px solid var(--border);border-radius:999px;background:var(--card);color:var(--muted);font:500 12.5px var(--mono);white-space:nowrap;backdrop-filter:blur(10px)}
.dot{position:relative;display:inline-block;width:8px;height:8px;flex:none;border-radius:50%;background:var(--faint)}
.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.bad{background:var(--danger)}
.dot.ok:after,.dot.warn:after{content:"";position:absolute;inset:0;border-radius:50%;background:inherit}
.view{display:none}
.view.active{display:block}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px;margin-bottom:16px}
.span-3{grid-column:span 3}.span-4{grid-column:span 4}.span-5{grid-column:span 5}.span-6{grid-column:span 6}.span-7{grid-column:span 7}.span-8{grid-column:span 8}.span-12{grid-column:1/-1}
.card{position:relative;min-width:0;margin-bottom:16px;padding:22px;border:1px solid var(--border);border-radius:var(--radius);background:var(--card);box-shadow:var(--shadow);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}
.grid>.card{margin-bottom:0}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:18px}
.card h2{margin:0;font-size:16.5px;font-weight:650;letter-spacing:-.015em}
.card h3{margin:18px 0 10px;font-size:14px;font-weight:600}
.sub{margin:5px 0 0;color:var(--muted);font-size:13.5px;max-width:70ch}
.eyebrow{display:flex;align-items:center;gap:7px;margin-bottom:9px;color:var(--accent);font:600 10.5px var(--mono);letter-spacing:.14em;text-transform:uppercase}
.stat{display:flex;flex-direction:column;gap:7px;padding:18px 18px 16px;overflow:hidden}
.stat:after{content:"";position:absolute;right:-30px;top:-30px;width:90px;height:90px;border-radius:50%;background:radial-gradient(circle,var(--accent-soft),transparent 70%);pointer-events:none}
.stat .k{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12.5px;font-weight:500}
.stat .k .ic{width:16px;height:16px}
.stat .v{display:flex;align-items:center;gap:9px;font:650 19px/1.25 var(--sans);letter-spacing:-.02em;overflow-wrap:anywhere}
.stat .v.mono{font:500 14.5px/1.4 var(--mono);letter-spacing:0}
.stat .h{color:var(--faint);font-size:12px}
.ok-t{color:var(--ok)}.warn-t{color:var(--warn)}.bad-t{color:var(--danger)}.muted{color:var(--muted)}.faint{color:var(--faint)}.mono{font-family:var(--mono)}
.steps{display:grid;gap:8px;margin:0;padding:0;list-style:none}
.steps a{display:flex;align-items:center;gap:13px;padding:12px 14px;border:1px solid var(--border);border-radius:12px;color:var(--text);text-decoration:none;transition:border-color .2s,background .2s,transform .25s var(--ease)}
.steps a:hover{border-color:var(--border-strong);background:var(--elev);transform:translateX(3px)}
.steps .n{display:grid;place-items:center;width:28px;height:28px;flex:none;border:1px solid var(--border-strong);border-radius:50%;color:var(--muted);font:600 12px var(--mono)}
.steps .n .ic{width:15px;height:15px;stroke-width:2.6}
.steps .done .n{border-color:transparent;background:linear-gradient(135deg,var(--accent),var(--accent-2));color:var(--accent-ink)}
.steps b{display:block;font-weight:600;font-size:13.5px}
.steps small{display:block;color:var(--muted);font-size:12.5px}
.steps .go{margin-left:auto;color:var(--faint)}
.kv{display:grid}
.kv>div{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-top:1px solid var(--border)}
.kv>div:first-child{border-top:0;padding-top:0}
.kv span{color:var(--muted)}
.kv b{font:500 13px var(--mono);text-align:right;overflow-wrap:anywhere}
.field{display:block;margin:0 0 15px}
.field>span{display:block;margin-bottom:7px;color:var(--muted);font-size:13px;font-weight:500}
.hint{margin:7px 0 0;color:var(--faint);font-size:12.5px;line-height:1.5}
input,select,textarea{width:100%;padding:11px 13px;border:1px solid var(--border-strong);border-radius:10px;background:var(--input);color:var(--text);font:14px var(--sans);outline:none;transition:border-color .2s,box-shadow .2s,background .2s}
input::placeholder,textarea::placeholder{color:var(--faint)}
textarea,.mono-in{font:13px/1.6 var(--mono)}
textarea{min-height:260px;resize:vertical}
textarea.short{min-height:96px}
input:hover,select:hover,textarea:hover{border-color:color-mix(in srgb,var(--accent) 35%,var(--border-strong))}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}
select{appearance:none;-webkit-appearance:none;padding-right:38px;background-image:linear-gradient(45deg,transparent 50%,var(--muted) 50%),linear-gradient(135deg,var(--muted) 50%,transparent 50%);background-position:calc(100% - 19px) 52%,calc(100% - 14px) 52%;background-size:5px 5px;background-repeat:no-repeat}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:0 14px}
.check{display:flex;align-items:flex-start;gap:11px;margin:0 0 12px;color:var(--text);font-size:13.5px;cursor:pointer}
.check input{appearance:none;-webkit-appearance:none;display:grid;place-items:center;flex:none;width:18px;height:18px;margin:1px 0 0;padding:0;border:1.5px solid var(--border-strong);border-radius:6px;background:var(--input);cursor:pointer;transition:background .2s,border-color .2s}
.check input:checked{border-color:var(--accent);background:var(--accent)}
.check input:checked:after{content:"";width:9px;height:5px;border:2px solid var(--accent-ink);border-top:0;border-right:0;transform:translateY(-1px) rotate(-45deg)}
.check small{display:block;margin-top:1px;color:var(--muted);font-size:12.5px}
.switch-row{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:14px 0;border-top:1px solid var(--border);cursor:pointer}
.switch-row:first-child{border-top:0;padding-top:2px}
.switch-row b{display:block;font-weight:600}
.switch-row small{display:block;margin-top:2px;color:var(--muted);font-size:12.5px}
.switch-row code{font-size:11.5px}
.switch{appearance:none;-webkit-appearance:none;position:relative;flex:none;width:44px;height:25px;margin:0;padding:0;border:1px solid var(--border-strong);border-radius:999px;background:var(--elev);cursor:pointer;transition:background .3s var(--ease),border-color .3s}
.switch:after{content:"";position:absolute;top:2px;left:2px;width:19px;height:19px;border-radius:50%;background:var(--muted);box-shadow:0 2px 6px rgba(0,0,0,.3);transition:transform .35s var(--ease),background .3s}
.switch:checked{border-color:var(--accent);background:var(--accent)}
.switch:checked:after{transform:translateX(19px);background:var(--accent-ink)}
.switch:focus-visible{box-shadow:0 0 0 4px var(--accent-soft)}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-top:18px}
.actions.tight{margin-top:0}
.btn{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:8px;height:40px;padding:0 17px;border:1px solid transparent;border-radius:10px;background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent) 62%,var(--accent-2)));color:var(--accent-ink);font:600 13.5px var(--sans);text-decoration:none;white-space:nowrap;cursor:pointer;box-shadow:0 10px 24px -14px var(--accent);transition:transform .15s var(--ease),box-shadow .25s,filter .2s,opacity .2s,background .2s}
.btn .ic{width:16px;height:16px}
.btn:hover{filter:brightness(1.07);box-shadow:0 14px 28px -14px var(--accent)}
.btn:active{transform:translateY(1px) scale(.985)}
.btn:focus-visible{outline:none;box-shadow:0 0 0 4px var(--accent-soft)}
.btn.ghost{border-color:var(--border-strong);background:transparent;color:var(--text);box-shadow:none}
.btn.ghost:hover{background:var(--elev)}
.btn.danger{background:var(--danger);color:#fff;box-shadow:0 10px 24px -14px var(--danger)}
.btn.small{height:32px;padding:0 12px;font-size:12.5px;border-radius:9px}
.btn[disabled]{opacity:.55;cursor:progress}
.btn.loading{color:transparent!important}
.btn.loading .ic{opacity:0}
.btn.loading:after{content:"";position:absolute;width:16px;height:16px;border:2px solid var(--accent-ink);border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite}
.btn.ghost.loading:after{border-color:var(--text);border-right-color:transparent}
.btn.danger.loading:after{border-color:#fff;border-right-color:transparent}
.notice{display:flex;gap:12px;margin:16px 0 0;padding:13px 15px;border:1px solid var(--border);border-radius:12px;background:var(--elev);color:var(--muted);font-size:13px;line-height:1.55}
.notice .ic{margin-top:1px;color:var(--accent)}
.notice b{color:var(--text)}
.notice.warn{border-color:color-mix(in srgb,var(--warn) 38%,transparent);background:var(--warn-soft);color:var(--text)}
.notice.warn .ic{color:var(--warn)}
.notice.danger{border-color:color-mix(in srgb,var(--danger) 38%,transparent);background:var(--danger-soft);color:var(--text)}
.notice.danger .ic{color:var(--danger)}
.pills{display:flex;flex-wrap:wrap;gap:8px}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 10px;border:1px solid var(--border);border-radius:999px;background:var(--elev);color:var(--muted);font:500 12px var(--mono)}
.pill.ok{border-color:color-mix(in srgb,var(--ok) 40%,transparent);color:var(--ok)}
.pill.warn{border-color:color-mix(in srgb,var(--warn) 40%,transparent);color:var(--warn)}
.pill.bad{border-color:color-mix(in srgb,var(--danger) 40%,transparent);color:var(--danger)}
.pipeline{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:20px 0 14px}
.stage{position:relative;overflow:hidden;padding:13px 14px;border:1px solid var(--border);border-radius:12px;background:var(--elev);transition:border-color .35s,background .35s}
.stage small{display:flex;align-items:center;gap:7px;color:var(--faint);font:600 10.5px var(--mono);letter-spacing:.1em;text-transform:uppercase}
.stage small i{display:grid;place-items:center;width:16px;height:16px;border:1.5px solid currentColor;border-radius:50%;font-style:normal}
.stage b{display:block;margin-top:7px;font:500 13px var(--mono);overflow-wrap:anywhere}
.stage.done{border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.stage.done small{color:var(--ok)}
.stage.done small i{border-color:var(--ok);background:var(--ok)}
.stage.done small i:after{content:"";width:6px;height:3px;margin-top:-1px;border:1.6px solid var(--bg);border-top:0;border-right:0;transform:rotate(-45deg)}
.stage.active{border-color:color-mix(in srgb,var(--accent) 55%,transparent);background:color-mix(in srgb,var(--accent) 6%,var(--elev))}
.stage.active small{color:var(--accent)}
.stage.active small i{border-color:var(--accent);border-right-color:transparent;animation:spin .9s linear infinite}
.stage.active:after{content:"";position:absolute;left:0;right:0;bottom:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);animation:sweep 1.5s linear infinite}
.stage.failed{border-color:color-mix(in srgb,var(--danger) 50%,transparent);background:var(--danger-soft)}
.stage.failed small{color:var(--danger)}
.progress{height:6px;overflow:hidden;border:1px solid var(--border);border-radius:999px;background:var(--elev)}
.progress i{display:block;width:0;height:100%;border-radius:inherit;background:linear-gradient(90deg,var(--accent),var(--accent-2),var(--accent));background-size:200% 100%;transition:width .9s var(--ease)}
.progress.running i{animation:flow 1.8s linear infinite}
.progress.failed i{background:var(--danger)}
.job-msg{display:flex;align-items:center;gap:10px;min-height:22px;margin:14px 0 12px;color:var(--muted);font:500 12.5px var(--mono)}
.spinner{width:13px;height:13px;flex:none;border:2px solid var(--accent-soft);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}
.term{margin:0;min-height:120px;max-height:440px;overflow:auto;padding:14px 16px;border:1px solid var(--border);border-radius:12px;background:var(--term);color:#c3d0e2;font:12.5px/1.65 var(--mono);white-space:pre-wrap;word-break:break-word;scrollbar-color:#263247 transparent}
.term.tall{min-height:440px;max-height:64vh}
.term .l{display:block;white-space:pre-wrap}
.term .l.e{color:#fca5a5}
.term .l.w{color:#fcd34d}
.term .l.s{color:#6b7a90}
.term::-webkit-scrollbar{width:10px;height:10px}
.term::-webkit-scrollbar-thumb{border:3px solid var(--term);border-radius:10px;background:#263247}
.code-wrap{position:relative}
.code-wrap .btn{position:absolute;top:10px;right:10px;z-index:1}
.code-wrap .term{padding-right:120px}
.segmented{display:inline-flex;gap:3px;padding:3px;border:1px solid var(--border);border-radius:11px;background:var(--elev)}
.segmented button{height:30px;padding:0 13px;border:0;border-radius:8px;background:transparent;color:var(--muted);font:500 12.5px var(--sans);cursor:pointer;transition:background .25s,color .25s,box-shadow .25s}
.segmented button:hover{color:var(--text)}
.segmented button.active{background:var(--card-solid);color:var(--text);box-shadow:0 2px 10px -3px rgba(0,0,0,.4)}
.live{display:inline-flex;align-items:center;gap:8px;color:var(--muted);font:500 12px var(--mono)}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.sites{display:grid;gap:10px}
.site{display:grid;gap:10px;padding:14px;border:1px solid var(--border);border-radius:12px;background:var(--elev);transition:border-color .2s}
.site:hover{border-color:var(--border-strong)}
.site-row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 12px;min-width:0}
.site-row>b{font-size:13.5px;overflow-wrap:anywhere}
.site-link{min-width:0;font-size:12px;overflow-wrap:anywhere}
.pill{white-space:nowrap}
.pill.fp{width:100%;border-radius:10px;text-align:left;cursor:pointer;white-space:normal;overflow-wrap:anywhere;line-height:1.5}
.empty{display:grid;place-items:center;gap:6px;padding:28px 16px;border:1px dashed var(--border-strong);border-radius:12px;color:var(--muted);text-align:center;font-size:13px}
.empty .ic{width:22px;height:22px;color:var(--faint)}
.foot{margin-top:30px;color:var(--faint);font:12px var(--mono)}
#toasts{position:fixed;right:20px;bottom:20px;z-index:60;display:grid;gap:10px;width:min(430px,calc(100vw - 32px))}
.toast{display:flex;align-items:flex-start;gap:12px;padding:13px 14px;border:1px solid var(--border-strong);border-left:3px solid var(--ok);border-radius:12px;background:var(--card-solid);box-shadow:0 24px 50px -20px rgba(0,0,0,.55);font-size:13.5px;animation:toastIn .5s var(--ease) both}
.toast.error{border-left-color:var(--danger)}
.toast .ic{margin-top:1px;color:var(--ok)}
.toast.error .ic{color:var(--danger)}
.toast p{flex:1;margin:0;overflow-wrap:anywhere}
.toast button{padding:0 2px;border:0;background:none;color:var(--faint);font-size:19px;line-height:1;cursor:pointer}
.toast.out{animation:toastOut .32s ease-in forwards}
dialog{width:min(440px,calc(100vw - 32px));padding:0;border:1px solid var(--border-strong);border-radius:18px;background:var(--card-solid);color:var(--text);box-shadow:0 40px 90px -30px rgba(0,0,0,.7)}
dialog[open]{animation:pop .32s var(--ease)}
dialog::backdrop{background:rgba(3,6,12,.58);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}
.dlg{padding:24px}
.dlg-icon{display:grid;place-items:center;width:42px;height:42px;margin-bottom:14px;border-radius:12px;background:var(--warn-soft);color:var(--warn)}
.dlg h3{margin:0 0 8px;font-size:17px;letter-spacing:-.01em}
.dlg p{margin:0;color:var(--muted);line-height:1.6}
.dlg .actions{justify-content:flex-end;margin-top:24px}
.login{position:relative;z-index:1;display:grid;place-items:center;min-height:100vh;padding:24px 16px}
.login-card{width:min(410px,100%);padding:32px;border:1px solid var(--border);border-radius:22px;background:var(--card);box-shadow:var(--shadow);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.login-card .brand{padding:0 0 26px}
.login-card h1{margin:0 0 6px;font-size:25px;letter-spacing:-.025em}
.login-card .btn{width:100%;height:44px;margin-top:4px}
.pw{position:relative}
.pw input{padding-right:48px}
.pw button{position:absolute;top:50%;right:6px;display:grid;place-items:center;width:34px;height:34px;border:0;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer;transform:translateY(-50%)}
.pw button:hover{color:var(--text);background:var(--elev)}
.form-error{display:flex;gap:10px;margin:0 0 16px;padding:11px 13px;border:1px solid color-mix(in srgb,var(--danger) 40%,transparent);border-radius:10px;background:var(--danger-soft);color:var(--text);font-size:13px}
.form-error .ic{color:var(--danger)}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes sweep{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
@keyframes flow{to{background-position:-200% 0}}
@keyframes ping{0%{transform:scale(1);opacity:.65}80%,100%{transform:scale(3.4);opacity:0}}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes toastIn{from{opacity:0;transform:translateY(16px) scale(.96)}}
@keyframes toastOut{to{opacity:0;transform:translateX(36px)}}
@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.96)}}
@keyframes drift{to{transform:translate3d(3vmax,-2.5vmax,0) rotate(5deg)}}
@keyframes shake{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
@media (prefers-reduced-motion:no-preference){
.aurora{animation:drift 28s ease-in-out infinite alternate}
.dot.ok:after,.dot.warn:after{animation:ping 2.2s var(--ease) infinite}
.view.active>*{animation:rise .55s var(--ease) both}
.view.active>*:nth-child(2){animation-delay:.06s}
.view.active>*:nth-child(3){animation-delay:.12s}
.view.active>*:nth-child(4){animation-delay:.18s}
.view.active>*:nth-child(n+5){animation-delay:.22s}
.grid>.card{animation:rise .55s var(--ease) both}
.grid>.card:nth-child(2){animation-delay:.05s}
.grid>.card:nth-child(3){animation-delay:.1s}
.grid>.card:nth-child(4){animation-delay:.15s}
.no-anim .view.active>*,.no-anim .grid>.card{animation:none}
.login-card{animation:rise .7s var(--ease) both}
.login-card.shake{animation:shake .45s var(--ease)}
.card{transition:border-color .3s,transform .35s var(--ease)}
.stat:hover{transform:translateY(-2px);border-color:var(--border-strong)}
}
@media (max-width:1180px){.span-3{grid-column:span 6}.span-4,.span-5,.span-6,.span-7,.span-8{grid-column:1/-1}}
@media (max-width:880px){
.app{grid-template-columns:1fr}
.side{position:sticky;z-index:20;height:auto;flex-direction:row;align-items:center;gap:6px;padding:10px 12px;border-right:0;border-bottom:1px solid var(--border);overflow-x:auto;scrollbar-width:none}
.side::-webkit-scrollbar{display:none}
.side .brand{padding:0 8px 0 0}.side .brand div,.nav-label,.side-foot{display:none}
.nav{flex-direction:row}.nav a{padding:8px 11px;white-space:nowrap}.nav a.active:before{display:none}
.content{padding-top:20px}
.topbar{align-items:flex-start}
.mobile-only{display:inline-flex}
.pipeline{grid-template-columns:1fr 1fr}
}
@media (max-width:560px){.span-3{grid-column:1/-1}.card{padding:18px}.chip span.long{display:none}.code-wrap .term{padding-right:16px;padding-top:52px}}
@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
'''

THEME_JS = r'''try{var t=localStorage.getItem("nf-theme");if(t==="light"||t==="dark")document.documentElement.dataset.theme=t}catch(e){}'''

COMMON_JS = r'''
(function(){
"use strict";
function currentTheme(){var t=document.documentElement.dataset.theme;if(t)return t;return window.matchMedia&&matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}
document.addEventListener("click",function(e){
  var themeButton=e.target.closest("[data-theme-toggle]");
  if(themeButton){var next=currentTheme()==="dark"?"light":"dark";document.documentElement.dataset.theme=next;try{localStorage.setItem("nf-theme",next)}catch(_e){}}
  var eye=e.target.closest("[data-reveal]");
  if(eye){var input=document.getElementById(eye.dataset.reveal);if(input){var show=input.type==="password";input.type=show?"text":"password";eye.setAttribute("aria-label",show?"Скрыть пароль":"Показать пароль");eye.classList.toggle("on",show);input.focus();}}
});
})();
'''

APP_JS = r'''
(function(){
"use strict";
var bootNode=document.getElementById("boot");
var boot={};try{boot=JSON.parse(bootNode?bootNode.textContent:"{}")}catch(_e){}
var base=boot.base||"";
var STATE=boot.stateLabels||{};
var PHASE=boot.phaseLabels||{};
var ACTIVE=["queued","pulling","starting","verifying"];
var ORDER={queued:1,pulling:1,starting:2,verifying:3,installed:4};
var PROGRESS={idle:0,queued:8,pulling:34,starting:64,verifying:86,installed:100};
var DRAFT="node-forge-compose-draft";
var ICON_OK='<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';
var ICON_ERR='<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>';
function $(s,r){return (r||document).querySelector(s);}
function $$(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s));}
function esc(v){var n=document.createElement("span");n.textContent=v==null?"":String(v);return n.innerHTML;}
function byId(id){return document.getElementById(id);}
function setText(id,v){var el=byId(id);v=v==null?"":String(v);if(el&&el.textContent!==v)el.textContent=v;}

/* ---------- toasts ---------- */
function toast(message,kind){
  var box=byId("toasts");if(!box||!message)return;
  var el=document.createElement("div");
  el.className="toast"+(kind==="error"?" error":"");
  el.setAttribute("role",kind==="error"?"alert":"status");
  el.innerHTML=(kind==="error"?ICON_ERR:ICON_OK)+"<p>"+esc(message)+'</p><button type="button" aria-label="Закрыть">×</button>';
  var closed=false;
  function close(){if(closed)return;closed=true;el.classList.add("out");setTimeout(function(){el.remove()},340);}
  el.querySelector("button").addEventListener("click",close);
  box.appendChild(el);
  while(box.children.length>4)box.firstChild.remove();
  setTimeout(close,kind==="error"?14000:6500);
}

/* ---------- confirm dialog ---------- */
function ask(text,danger){
  var dialog=byId("confirm");
  if(!dialog||typeof dialog.showModal!=="function")return Promise.resolve(window.confirm(text));
  setText("confirm-text",text);
  var ok=byId("confirm-ok");ok.className="btn"+(danger?" danger":"");
  return new Promise(function(resolve){
    function onClose(){dialog.removeEventListener("close",onClose);resolve(dialog.returnValue==="ok");}
    dialog.returnValue="";
    dialog.addEventListener("close",onClose);
    dialog.showModal();
    setTimeout(function(){(danger?byId("confirm-cancel"):ok).focus()},30);
  });
}

/* ---------- views ---------- */
function show(name,scroll){
  var target=byId("view-"+name)||byId("view-overview");
  if(!target)return;
  name=target.id.slice(5);
  document.body.classList.remove("no-anim");
  $$(".view").forEach(function(v){v.classList.toggle("active",v===target)});
  $$(".nav a").forEach(function(a){
    var on=a.dataset.view===name;a.classList.toggle("active",on);
    if(on){a.setAttribute("aria-current","page");if(a.scrollIntoView&&window.innerWidth<880)a.scrollIntoView({block:"nearest",inline:"center",behavior:"smooth"});}
    else a.removeAttribute("aria-current");
  });
  setText("view-title",target.dataset.title||"");
  setText("view-crumb",target.dataset.crumb||"");
  document.title=(target.dataset.title||"Node Forge")+" · Node Forge";
  if(scroll)window.scrollTo({top:0,behavior:"smooth"});
  if(name==="logs")ensureStream();
}
window.addEventListener("hashchange",function(){show(location.hash.slice(1),true)});

/* ---------- forms ---------- */
function setBusy(form,button,busy){
  $$("button",form).forEach(function(b){b.disabled=busy});
  if(button)button.classList.toggle("loading",busy);
  form.setAttribute("aria-busy",busy?"true":"false");
}
document.addEventListener("submit",function(e){
  var form=e.target;
  if(!form.classList||!form.classList.contains("js-form"))return;
  e.preventDefault();
  if(form.getAttribute("aria-busy")==="true")return;
  var button=e.submitter||form.querySelector("button[type=submit],button:not([type])");
  var text=(button&&button.dataset.confirm)||form.dataset.confirm;
  var danger=(button&&button.dataset.danger)||form.dataset.danger;
  (text?ask(text,!!danger):Promise.resolve(true)).then(function(ok){if(ok)send(form,button)});
});
function send(form,button){
  var body=new URLSearchParams(new FormData(form));
  if(button&&button.name)body.set(button.name,button.value);
  setBusy(form,button,true);
  return fetch(form.action,{method:"POST",credentials:"same-origin",headers:{"Accept":"application/json","Content-Type":"application/x-www-form-urlencoded;charset=UTF-8"},body:body})
    .then(function(r){
      if(r.status===401){location.reload();throw null;}
      return r.json().catch(function(){throw new Error("Сервер вернул неожиданный ответ (HTTP "+r.status+").")})
        .then(function(d){if(!r.ok||d.error)throw new Error(d.error||("HTTP "+r.status));return d;});
    })
    .then(function(d){
      toast(d.message||"Готово.");
      if(form.id==="compose-form"){try{sessionStorage.removeItem(DRAFT)}catch(_e){}}
      if(d.status)renderStatus(d.status);
      return refresh();
    })
    .catch(function(err){
      if(!err)return;
      var msg=err instanceof TypeError?"Нет связи с панелью. Проверьте подключение и попробуйте ещё раз.":(err.message||String(err));
      toast(msg,"error");
    })
    .then(function(){setBusy(form,button,false)});
}

/* ---------- partial refresh ---------- */
function refresh(){
  return fetch(base+"/",{credentials:"same-origin",cache:"no-store",headers:{"Accept":"text/html"}})
    .then(function(r){
      if(r.status===401){location.reload();return;}
      if(!r.ok)return;
      return r.text().then(function(html){
        var doc=new DOMParser().parseFromString(html,"text/html");
        document.body.classList.add("no-anim");
        $$(".view[data-refresh]").forEach(function(v){var fresh=doc.getElementById(v.id);if(fresh)v.innerHTML=fresh.innerHTML;});
        ["side-ip","nav"].forEach(function(id){var a=byId(id),b=doc.getElementById(id);if(a&&b)a.innerHTML=b.innerHTML;});
        show((location.hash||"#overview").slice(1),false);
        document.body.classList.add("no-anim");
        bindDynamic();
        if(lastStatus)renderStatus(lastStatus);
      });
    }).catch(function(){});
}

/* ---------- status ---------- */
function stateClass(s){return s==="running"?"ok":(s==="exited"||s==="dead"||s==="restarting")?"bad":"warn";}
function stage(id,state,label){
  var el=byId(id);if(!el)return;
  el.className="stage"+(state?" "+state:"");
  var b=el.querySelector("b");if(b&&label!=null&&b.textContent!==label)b.textContent=label;
}
var lastPhase=null,lastStatus=null;
function renderStatus(d){
  if(!d)return;
  lastStatus=d;
  var label=STATE[d.state]||d.state||"—",cls=stateClass(d.state);
  var ov=byId("ov-state");if(ov){ov.textContent=label;ov.className=cls+"-t";}
  var ovDot=byId("ov-dot");if(ovDot)ovDot.className="dot "+cls;
  setText("ov-image",d.image);setText("ov-restarts",d.restarts);
  var chipDot=byId("chip-dot");if(chipDot)chipDot.className="dot "+cls;
  setText("chip-text",label);
  var job=d.job||{},phase=job.phase||"idle";
  var failed=phase==="failed"||phase==="interrupted";
  var running=ACTIVE.indexOf(phase)>=0;
  var current=failed?(ORDER[job.failed_phase]||1):(ORDER[phase]||0);
  stage("st-compose",d.composeSaved?"done":"",d.composeSaved?"сохранён":"не сохранён");
  var names=["st-image","st-deploy","st-verify"];
  var labels=[job.tag?"remnawave/node:"+job.tag:"—",null,null];
  names.forEach(function(id,i){
    var idx=i+1,state="";
    if(phase==="installed")state="done";
    else if(failed||running){state=idx<current?"done":idx===current?(failed?"failed":"active"):"";}
    var text=labels[i];
    if(i===1)text=state==="done"?"контейнер создан":state==="active"?"запуск…":state==="failed"?"ошибка":"ожидание";
    if(i===2)text=state==="active"?"жду running…":state==="failed"?"ошибка":(STATE[d.state]||d.state||"—");
    stage(id,state,text);
  });
  var bar=byId("inst-progress");
  if(bar){
    var pct=failed?(PROGRESS[job.failed_phase]||20):(PROGRESS[phase]||0);
    bar.className="progress"+(running?" running":"")+(failed?" failed":"");
    var fill=bar.querySelector("i");if(fill)fill.style.width=pct+"%";
    bar.setAttribute("aria-valuenow",String(pct));
  }
  var msg=byId("inst-msg");
  if(msg){var html=(running?'<span class="spinner"></span>':"")+"<span>"+esc(job.message||"")+"</span>";if(msg.innerHTML!==html)msg.innerHTML=html;}
  setText("inst-phase",PHASE[phase]||phase);
  var log=byId("install-log");
  if(log&&job.log!==undefined){
    var text=job.log||"Здесь появится ход загрузки образа и запуска контейнера.";
    if(log.textContent!==text){var bottom=log.scrollHeight-log.scrollTop-log.clientHeight<60;log.textContent=text;if(bottom)log.scrollTop=log.scrollHeight;}
  }
  if(lastPhase&&ACTIVE.indexOf(lastPhase)>=0&&!running&&phase!==lastPhase){
    toast(job.message||PHASE[phase]||phase,phase==="installed"?"ok":"error");
    refresh();
  }
  lastPhase=phase;
}
var pollTimer=null;
function poll(){
  clearTimeout(pollTimer);
  var delay=6000;
  fetch(base+"/api/status",{credentials:"same-origin",cache:"no-store",headers:{"Accept":"application/json"}})
    .then(function(r){if(r.status===401){location.reload();return null;}return r.ok?r.json():null;})
    .then(function(d){if(d){renderStatus(d);if(ACTIVE.indexOf((d.job||{}).phase)>=0)delay=1500;}})
    .catch(function(){})
    .then(function(){pollTimer=setTimeout(poll,document.hidden?Math.max(delay,15000):delay);});
}
document.addEventListener("visibilitychange",function(){if(!document.hidden)poll();});

/* ---------- live logs ---------- */
var stream=null,streamName="container",lineCount=0;
function setLive(text,cls){var dot=byId("live-dot");if(dot)dot.className="dot "+(cls||"");setText("live-text",text);}
function appendLine(line){
  var live=byId("live-log");if(!live)return;
  if(lineCount===0)live.textContent="";
  var bottom=live.scrollHeight-live.scrollTop-live.clientHeight<80;
  var row=document.createElement("span");
  var low=String(line).toLowerCase();
  row.className="l"+(/\b(error|fatal|panic|failed)\b|ошибк/.test(low)?" e":/\bwarn(ing)?\b/.test(low)?" w":/^\s*$/.test(low)?" s":"");
  row.textContent=line;
  live.appendChild(row);lineCount++;
  while(live.childNodes.length>800)live.removeChild(live.firstChild);
  if(bottom)live.scrollTop=live.scrollHeight;
}
function openStream(name){
  if(stream){stream.close();stream=null;}
  streamName=name;lineCount=0;
  var live=byId("live-log");if(live)live.textContent="Подключаю поток логов…";
  $$("[data-stream]").forEach(function(b){b.classList.toggle("active",b.dataset.stream===name)});
  setLive("подключение…","warn");
  stream=new EventSource(base+"/stream?source="+encodeURIComponent(name));
  stream.addEventListener("ready",function(){setLive("в реальном времени","ok");if(lineCount===0&&live)live.textContent="Ждём новые строки…";});
  stream.addEventListener("line",function(ev){var v;try{v=JSON.parse(ev.data)}catch(_e){v=ev.data}appendLine(v);});
  stream.addEventListener("terminal",function(ev){var v="";try{v=JSON.parse(ev.data)}catch(_e){}if(v)appendLine(v);setLive("поток остановлен","bad");if(stream){stream.close();stream=null;}});
  stream.onerror=function(){setLive("переподключение…","warn");};
}
function ensureStream(){if(!stream)openStream(streamName);}

/* ---------- clipboard ---------- */
function copyText(text){
  if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(text).catch(function(){return legacyCopy(text)});
  return legacyCopy(text);
}
function legacyCopy(text){
  return new Promise(function(resolve,reject){
    var ta=document.createElement("textarea");ta.value=text;ta.setAttribute("readonly","");
    ta.style.position="fixed";ta.style.opacity="0";document.body.appendChild(ta);ta.select();
    try{document.execCommand("copy")?resolve():reject(new Error("copy"))}catch(err){reject(err)}
    ta.remove();
  });
}

/* ---------- delegated clicks ---------- */
document.addEventListener("click",function(e){
  var copy=e.target.closest("[data-copy],[data-copy-target]");
  if(copy){
    e.preventDefault();
    var src=copy.dataset.copyTarget?byId(copy.dataset.copyTarget):null;
    var value=src?src.textContent:copy.dataset.copy;
    copyText(value||"").then(function(){
      toast("Скопировано в буфер обмена.");
      var label=copy.querySelector("[data-label]");
      if(label){var old=label.textContent;label.textContent="Скопировано";setTimeout(function(){label.textContent=old},1600);}
    },function(){toast("Не удалось скопировать — выделите текст вручную.","error")});
  }
  var s=e.target.closest("[data-stream]");if(s)openStream(s.dataset.stream);
  if(e.target.closest("[data-clear-log]")){var live=byId("live-log");if(live){live.textContent="";lineCount=0;}}
  if(e.target.closest("[data-refresh-now]")){refresh().then(function(){toast("Данные обновлены.")});}
});

/* ---------- dynamic bits ---------- */
function bindDynamic(){
  var editor=byId("compose-editor");
  if(editor&&!editor.dataset.bound){
    editor.dataset.bound="1";
    try{var saved=sessionStorage.getItem(DRAFT);if(!editor.value&&saved)editor.value=saved;}catch(_e){}
    editor.addEventListener("input",function(){try{sessionStorage.setItem(DRAFT,editor.value)}catch(_e){}});
  }
  var kind=byId("inbound-kind"),tag=byId("inbound-tag");
  if(kind&&tag&&!kind.dataset.bound){
    kind.dataset.bound="1";
    kind.addEventListener("change",function(){
      if(tag.value==="VLESS_REALITY"||tag.value==="HYSTERIA2")tag.value=kind.value==="hysteria"?"HYSTERIA2":"VLESS_REALITY";
      var port=byId("inbound-port");if(port&&(port.value==="2053"||port.value==="8444"))port.value=kind.value==="hysteria"?"8444":"2053";
    });
  }
}

/* ---------- boot ---------- */
show((location.hash||"#overview").slice(1),false);
bindDynamic();
if(boot.flash){
  if(boot.flash.ok)toast(boot.flash.ok);
  if(boot.flash.error)toast(boot.flash.error,"error");
  if((boot.flash.ok||boot.flash.error)&&history.replaceState)history.replaceState(null,"",location.pathname+location.hash);
}
if(boot.status)renderStatus(boot.status);
poll();
})();
'''

ICONS = {
    "overview": '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    "install": '<path d="M21 8 12 3 3 8v8l9 5 9-5z"/><path d="m3 8 9 5 9-5M12 13v8"/>',
    "tls": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "inbound": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "network": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "ssh": '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14 9l2 2"/>',
    "meltun": '<path d="M12 15V3M7 8l5-5 5 5"/><path d="M5 15v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"/>',
    "logs": '<path d="m4 17 6-6-6-6M12 19h8"/>',
    "moon": '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    "logout": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "copy": '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
    "arrow": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    "play": '<path d="M7 4v16l13-8z"/>',
    "restart": '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
    "download": '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    "box": '<path d="M21 16V8l-9-5-9 5v8l9 5z"/>',
    "refresh": '<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16M3 12a9 9 0 0 1 15.5-6.2L21 8"/><path d="M21 3v5h-5M3 21v-5h5"/>',
    "eye": '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "shield": '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/>',
    "trash": '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',
}
LOGO = '<svg viewBox="0 0 36 36" aria-hidden="true"><defs><linearGradient id="nf-g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5eead4"/><stop offset="1" stop-color="#818cf8"/></linearGradient></defs><rect width="36" height="36" rx="11" fill="url(#nf-g)"/><path d="M11 25V11h4.2l5.6 8V11H25v14h-4.2l-5.6-8v8z" fill="#06121c"/></svg>'
FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 36 36'%3E%3Crect width='36' height='36' rx='11' fill='%235eead4'/%3E%3Cpath d='M11 25V11h4.2l5.6 8V11H25v14h-4.2l-5.6-8v8z' fill='%2306121c'/%3E%3C/svg%3E"
FONT_LINKS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&amp;family=JetBrains+Mono:wght@400;500;600&amp;display=swap">'
STATE_LABELS = {
    "running": "работает", "exited": "остановлена", "restarting": "перезапускается",
    "created": "создана", "paused": "на паузе", "dead": "сломана", "removing": "удаляется",
    "not created": "не создана",
}
PHASE_LABELS = {
    "idle": "не запускалась", "queued": "в очереди", "pulling": "загрузка образа",
    "starting": "запуск контейнера", "verifying": "проверка", "installed": "установлена",
    "failed": "ошибка", "interrupted": "прервана",
}
CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def icon(name):
    return f'<svg class="ic" viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>'


def render_page(title, body, boot=None, script=""):
    boot_json = json.dumps(boot or {}, ensure_ascii=False).replace("</", "<\\/")
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="color-scheme" content="dark light"><meta name="robots" content="noindex,nofollow">'
        f'<title>{html.escape(title)}</title><link rel="icon" href="{FAVICON}">{FONT_LINKS}'
        f'<style>{CSS}</style><script>{THEME_JS}</script></head><body>'
        '<div class="aurora" aria-hidden="true"></div><div class="grain" aria-hidden="true"></div>'
        f'{body}<script id="boot" type="application/json">{boot_json}</script>'
        f'<script>{COMMON_JS}</script>{f"<script>{script}</script>" if script else ""}</body></html>'
    )


def render_login(error=""):
    error_html = f'<div class="form-error" role="alert">{icon("alert")}<span>{html.escape(error)}</span></div>' if error else ""
    body = f'''<main class="login"><div class="login-card{' shake' if error else ''}">
<div class="brand">{LOGO}<div><b>Node Forge</b><small>Meltun · управление нодой</small></div></div>
<h1>Вход в панель</h1><p class="sub" style="margin-bottom:22px">Пароль сохранён на сервере в <code>/root/remnanode-manager-access.txt</code>.</p>
{error_html}<form method="post" action="{web_path('login')}">
<label class="field"><span>Пароль администратора</span><div class="pw"><input id="password" autofocus type="password" name="password" autocomplete="current-password" required>
<button type="button" data-reveal="password" aria-label="Показать пароль">{icon("eye")}</button></div></label>
<button class="btn" type="submit">Открыть панель {icon("arrow")}</button></form>
<div class="notice">{icon("info")}<span>При входе по HTTP пароль передаётся без шифрования. Для постоянной работы откройте панель по HTTPS-домену ноды или через SSH-туннель.</span></div>
</div></main>'''
    return render_page("Вход · Node Forge", body)


def stat_card(icon_name, key, value, hint, value_class="", extra=""):
    return (
        f'<div class="card stat span-3"><div class="k">{icon(icon_name)}{key}</div>'
        f'<div class="v {value_class}">{value}</div><div class="h">{hint}</div>{extra}</div>'
    )


def card_head(eyebrow, title, subtitle="", right=""):
    sub = f'<p class="sub">{subtitle}</p>' if subtitle else ""
    return f'<div class="card-head"><div><div class="eyebrow">{eyebrow}</div><h2>{title}</h2>{sub}</div>{right}</div>'


def notice(text, kind="", icon_name="info"):
    return f'<div class="notice {kind}">{icon(icon_name)}<span>{text}</span></div>'


def render_dashboard(csrf, message="", error=""):
    e = html.escape
    s = status_data()
    runtime = runtime_status()
    addresses = server_addresses(public_ip=s["public_ip"])
    sites = managed_sites()
    owners_443 = sorted(port_owners(443))
    job = install_snapshot()
    tags = image_tags()
    forwarder_config = {}
    if ACCESS_FORWARDER_CONFIG.exists():
        try:
            forwarder_config = json.loads(ACCESS_FORWARDER_CONFIG.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            forwarder_config = {}
    forwarder_active = command_ok(["systemctl", "is-active", "--quiet", "remnanode-access-forwarder.service"])
    last = (STATE_DIR / "last-inbound.json").read_text(encoding="utf-8") if (STATE_DIR / "last-inbound.json").exists() else ""
    try:
        meta = json.loads((STATE_DIR / "last-meta.json").read_text(encoding="utf-8")) if (STATE_DIR / "last-meta.json").exists() else {}
    except ValueError:
        meta = {}
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8") if COMPOSE_FILE.exists() else ""
    hidden = f'<input type="hidden" name="csrf" value="{e(csrf)}">'
    ssh = s["ssh"]
    state = s["state"]
    state_label = STATE_LABELS.get(state, state)
    state_cls = "ok" if state == "running" else ("bad" if state in ("exited", "dead", "restarting") else "warn")
    selected_tag = s["image"].rsplit(":", 1)[-1] if s["image"].startswith("remnawave/node:") else "latest"
    if selected_tag not in tags:
        tags = tags + [selected_tag]
    tag_options = "".join(
        f'<option value="{e(tag)}"{" selected" if tag == selected_tag else ""}>{e(tag)}{" — последняя" if tag == "latest" else ""}</option>'
        for tag in tags
    )
    selected_address = s["public_ip"] if any(item["value"] == s["public_ip"] for item in addresses) else (addresses[0]["value"] if addresses else "")
    address_options = "".join(
        f'<option value="{e(item["value"])}"{" selected" if item["value"] == selected_address else ""}>{e(item["value"])} · {e(item["source"])} · {item["family"]}</option>'
        for item in addresses
    ) or '<option value="">Адреса не найдены — обновите страницу</option>'
    public_sites = [site for site in sites if site["public_https"]]
    ssh_password_on = ssh["root_login"] == "yes" and (ssh["password_auth"] == "yes" or ssh["kbd_auth"] == "yes")
    ssh_ports = ", ".join(map(str, ssh["ports"])) or "неизвестно"
    ssh_port_value = ssh["desired_port"] or (ssh["ports"][0] if ssh["ports"] else 22)
    port443_text = ", ".join(owners_443) if owners_443 else "свободен"
    port443_hint = (
        "занят nginx — Xray не сможет слушать 443" if owners_443 == ["nginx"]
        else "свободен для inbound Xray" if not owners_443
        else "слушает inbound ноды"
    )

    # ---- overview ----
    steps = [
        ("install", "Сохранить Docker Compose", "Скопируйте его из карточки ноды в Remnawave", COMPOSE_FILE.exists()),
        ("install", "Установить RemnaNode", "Выберите версию образа и запустите контейнер", state == "running"),
        ("tls", "Выпустить сертификат", "Нужен для Reality self-steal и Hysteria 2", bool(s["certs"])),
        ("inbound", "Сгенерировать inbound", "Вставьте JSON в профиль Xray панели", bool(last)),
        ("meltun", "Подключить MelTun", "История подключений пользователей", bool(forwarder_config)),
        ("ssh", "Закрыть SSH ключом", "Новый порт и вход только по ключу", ssh["key_count"] > 0 and not ssh_password_on),
    ]
    steps_html = "".join(
        f'<li class="{"done" if done else ""}"><a href="#{view}"><span class="n">{icon("check") if done else index}</span>'
        f'<span><b>{title}</b><small>{hint}</small></span><span class="go">{icon("arrow")}</span></a></li>'
        for index, (view, title, hint, done) in enumerate(steps, 1)
    )
    done_count = sum(1 for step in steps if step[3])
    overview = f'''
<div class="grid">
{stat_card("box", "RemnaNode", f'<span id="ov-dot" class="dot {state_cls}"></span><span id="ov-state" class="{state_cls}-t">{e(state_label)}</span>', f'Перезапусков: <span id="ov-restarts">{e(s["restarts"])}</span>')}
{stat_card("install", "Образ", f'<span id="ov-image">{e(s["image"])}</span>', f'Docker {e(s["docker"])} · Compose {e(s["compose"])}', "mono")}
{stat_card("globe", "Публичный IP", e(s["public_ip"]), "исходящий адрес сервера", "mono")}
{stat_card("shield", "TCP 443", e(port443_text), port443_hint, "mono")}
</div>
<div class="grid">
<section class="card span-7">{card_head("Быстрый старт", "Настройка ноды", f"Готово {done_count} из {len(steps)} шагов. Нажмите на шаг, чтобы перейти к нему.")}<ol class="steps">{steps_html}</ol></section>
<div class="span-5" style="display:grid;gap:16px;align-content:start">
<section class="card" style="margin:0">{card_head("Контейнер", "Управление нодой", "Команды выполняются в /opt/remnanode.")}
<form class="js-form" method="post" action="{web_path('action')}">{hidden}<div class="actions tight">
<button class="btn" name="action" value="start">{icon("play")}Запустить</button>
<button class="btn ghost" name="action" value="restart" data-confirm="Перезапустить контейнер remnanode? Активные подключения пользователей прервутся.">{icon("restart")}Перезапустить</button>
<button class="btn ghost" name="action" value="pull" data-confirm="Скачать свежий образ и пересоздать контейнер? Подключения на время прервутся.">{icon("download")}Обновить образ</button>
</div></form></section>
<section class="card" style="margin:0">{card_head("Система", "Сводка")}<div class="kv">
<div><span>Сеть</span><b>{e(s["bbr"])} · {e(s["qdisc"])}</b></div>
<div><span>SSH-порты</span><b>{e(ssh_ports)}</b></div>
<div><span>Вход root по паролю</span><b class="{'warn-t' if ssh_password_on else 'ok-t'}">{'разрешён' if ssh_password_on else 'выключен'}</b></div>
<div><span>Сертификаты</span><b>{len(s["certs"])}</b></div>
<div><span>Compose SHA-256</span><b>{e(s["compose_hash"])}</b></div>
<div><span>MelTun</span><b class="{'ok-t' if forwarder_active else 'faint'}">{'передаёт логи' if forwarder_active else ('настроен, служба остановлена' if forwarder_config else 'не подключён')}</b></div>
</div></section></div></div>'''

    # ---- install ----
    install = f'''
<section class="card">{card_head("Шаг 1 · Конфигурация", "Docker Compose", "Вставьте полный <code>docker-compose.yml</code> из карточки ноды в Remnawave. Сохранение только проверяет и записывает файл — контейнер не запускается.", f'<span class="pill {"ok" if COMPOSE_FILE.exists() else "warn"}">{"сохранён" if COMPOSE_FILE.exists() else "не сохранён"}</span>')}
<form id="compose-form" class="js-form" method="post" action="{web_path('compose')}">{hidden}
<label class="field"><span>docker-compose.yml</span><textarea id="compose-editor" name="compose" spellcheck="false" placeholder="services:&#10;  remnanode:&#10;    container_name: remnanode&#10;    image: remnawave/node:latest&#10;    network_mode: host&#10;    ...">{e(compose_text)}</textarea></label>
<label class="check"><input type="checkbox" name="cert_volume" value="1" checked><span>Подключить каталог сертификатов к контейнеру<small>/var/lib/remnawave/configs/xray/ssl монтируется только для чтения.</small></span></label>
<div class="actions"><button class="btn" type="submit">{icon("check")}Проверить и сохранить</button><span class="faint mono" style="font-size:12px">/opt/remnanode · SHA-256 {e(s["compose_hash"])}</span></div></form></section>
<section class="card">{card_head("Шаг 2 · Установка", "Версия и запуск", "Образ скачивается в фоне — страницу можно не держать открытой.", f'<span class="pill" id="inst-phase">{e(PHASE_LABELS.get(job.get("phase", "idle"), job.get("phase", "")))}</span>')}
<form class="js-form" method="post" action="{web_path('api/install')}">{hidden}<div class="cols" style="align-items:end">
<label class="field"><span>Версия образа remnawave/node</span><select name="version">{tag_options}</select></label>
<div class="field"><button class="btn" type="submit" style="width:100%">{icon("download")}Установить выбранную версию</button></div></div></form>
<div class="pipeline">
<div class="stage" id="st-compose"><small><i></i>01 · Compose</small><b>—</b></div>
<div class="stage" id="st-image"><small><i></i>02 · Образ</small><b>—</b></div>
<div class="stage" id="st-deploy"><small><i></i>03 · Запуск</small><b>—</b></div>
<div class="stage" id="st-verify"><small><i></i>04 · Проверка</small><b>—</b></div></div>
<div class="progress" id="inst-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100"><i></i></div>
<div class="job-msg" id="inst-msg">{e(job.get("message", ""))}</div>
<pre class="term" id="install-log">{e(job.get("log", "") or "Здесь появится ход загрузки образа и запуска контейнера.")}</pre></section>'''

    # ---- certificates ----
    if sites:
        rows = []
        for site in sites:
            days = site["days_left"]
            if days is None:
                expiry = '<span class="pill">—</span>'
            else:
                expiry = f'<span class="pill {"ok" if days > 20 else "warn" if days > 7 else "bad"}">ещё {days} дн.</span>'
            if not site["tls"]:
                toggle = '<span class="faint">только HTTP</span>'
            else:
                enable = "0" if site["public_https"] else "1"
                question = (
                    f"Отключить публичный HTTPS для {site['domain']}? nginx освободит TCP 443, сайт и панель по HTTPS станут недоступны."
                    if site["public_https"] else
                    f"Включить публичный HTTPS для {site['domain']}? nginx займёт TCP 443 — inbound Xray на 443 после этого не запустится."
                )
                toggle = (
                    f'<form class="js-form" method="post" action="{web_path("public-https")}" data-confirm="{e(question)}">{hidden}'
                    f'<input type="hidden" name="domain" value="{e(site["domain"])}"><input type="hidden" name="enabled" value="{enable}">'
                    f'<button class="btn small {"ghost" if site["public_https"] else ""}" type="submit">{"Освободить 443" if site["public_https"] else "Включить 443"}</button></form>'
                )
            link = (
                f'<a class="mono site-link" href="https://{e(site["domain"])}{web_path()}">https://{e(site["domain"])}{web_path()}</a>'
                if site["public_https"] else '<span class="faint">Панель по HTTPS выключена</span>'
            )
            if site["public_https"]:
                listeners = '<span class="pill ok">443 + 8443</span>'
            elif site["tls"]:
                listeners = '<span class="pill">только 8443</span>'
            else:
                listeners = '<span class="pill warn">только HTTP</span>'
            rows.append(
                f'<div class="site"><div class="site-row"><b class="mono">{e(site["domain"])}</b>'
                f'<span class="pills">{expiry}{listeners}</span></div>'
                f'<div class="site-row">{link}{toggle}</div></div>'
            )
        sites_html = f'<div class="sites">{"".join(rows)}</div>'
    else:
        sites_html = f'<div class="empty">{icon("tls")}<span>Сертификатов пока нет.</span></div>'
    owner_note = (
        notice("<b>TCP 443 занят nginx.</b> Если Reality или другой inbound должен слушать 443, нажмите «Освободить 443» у домена — заглушка Reality останется на 127.0.0.1:8443.", "warn", "alert")
        if owners_443 == ["nginx"] else
        notice(f"TCP 443 сейчас: <b>{e(port443_text)}</b>. Публичный HTTPS-сайт включайте, только если Xray не использует 443.")
    )
    certificates = f'''
<div class="grid">
<section class="card span-7">{card_head("Let's Encrypt", "Выпустить сертификат", "Домен проверяется по DNS, сертификат выпускается через HTTP-01 на порту 80 и копируется в каталог Xray.")}
<form class="js-form" method="post" action="{web_path('cert')}">{hidden}
<div class="cols"><label class="field"><span>Домен</span><input name="domain" placeholder="node.example.com" required autocomplete="off" spellcheck="false"></label>
<label class="field"><span>Email для Let's Encrypt</span><input type="email" name="email" placeholder="admin@example.com" required></label></div>
<label class="field"><span>IP сервера для проверки DNS</span><select name="expected_ip" required>{address_options}</select><p class="hint">Выбранный адрес сравнивается с A/AAAA-записями домена. Если записей несколько, каждая должна вести на этот сервер.</p></label>
<label class="check"><input type="checkbox" name="cert_volume" value="1" checked><span>Добавить volume сертификатов в сохранённый Compose</span></label>
<label class="check"><input type="checkbox" name="public_https" value="1"><span>Открыть сайт и панель на публичном TCP 443<small>Не включайте, если inbound Xray (например Reality) слушает 443.</small></span></label>
<label class="check"><input type="checkbox" name="restart_node" value="1"><span>Перезапустить работающую ноду после выпуска</span></label>
<label class="check"><input type="checkbox" name="force_dns" value="1"><span>Игнорировать несовпадение DNS и выбранного IP<small>Только если домен за прокси или DNS ещё не обновился.</small></span></label>
<div class="actions"><button class="btn" type="submit">{icon("tls")}Проверить DNS и выпустить</button></div></form></section>
<section class="card span-5">{card_head("Хранилище", "Сертификаты ноды", "Продлеваются certbot.timer, deploy-hook копирует их в Xray и перезапускает ноду.")}{sites_html}{owner_note}</section>
</div>'''

    # ---- inbound ----
    cert_options = "".join(f'<option value="{e(domain)}">' for domain in s["certs"])
    if last:
        meta_pills = ""
        if meta.get("publicKey"):
            meta_pills = (
                f'<div class="pills" style="margin-top:14px">'
                f'<button class="pill fp" type="button" data-copy="{e(meta.get("publicKey", ""))}" title="Скопировать">{icon("copy")}Public key · {e(meta.get("publicKey", ""))}</button>'
                f'<button class="pill fp" type="button" data-copy="{e(meta.get("shortId", ""))}" title="Скопировать">{icon("copy")}Short ID · {e(meta.get("shortId", ""))}</button></div>'
            )
        result = (
            f'<div class="code-wrap"><button class="btn small ghost" type="button" data-copy-target="inbound-json">{icon("copy")}<span data-label>Копировать</span></button>'
            f'<pre class="term" id="inbound-json">{e(last)}</pre></div>{meta_pills}'
        )
    else:
        result = f'<div class="empty">{icon("inbound")}<span>Сгенерированный inbound появится здесь.</span></div>'
    inbound = f'''
<div class="grid">
<section class="card span-5">{card_head("Профиль Xray", "Сгенерировать inbound", "JSON вставляется в конфигурационный профиль ноды в панели Remnawave. На сервере он сам не применяется.")}
<form class="js-form" method="post" action="{web_path('inbound')}">{hidden}
<label class="field"><span>Тип</span><select name="kind" id="inbound-kind"><option value="reality">VLESS TCP Reality + self-steal</option><option value="hysteria">Hysteria 2 + TLS</option></select></label>
<div class="cols"><label class="field"><span>Tag</span><input name="tag" id="inbound-tag" value="VLESS_REALITY" class="mono-in"></label>
<label class="field"><span>Порт</span><input type="number" min="1" max="65535" name="inbound_port" id="inbound-port" value="2053" class="mono-in"></label></div>
<label class="field"><span>Домен с сертификатом</span><input name="inbound_domain" list="cert-domains" placeholder="node.example.com" required autocomplete="off" spellcheck="false"><datalist id="cert-domains">{cert_options}</datalist>
<p class="hint">Reality берёт этот домен как SNI и маскируется под TLS-сайт на 127.0.0.1:8443, поэтому сертификат нужен заранее.</p></label>
<div class="actions"><button class="btn" type="submit">{icon("inbound")}Сгенерировать</button></div></form>
{notice("Порты 80, 8443, порт панели и SSH заняты. Порт 443 доступен Reality, только если nginx его не держит.")}</section>
<section class="card span-7">{card_head("Результат", "Последний inbound")}{result}</section>
</div>'''

    # ---- network ----
    switches = [
        ("bbr", "BBR + fq", "Алгоритм перегрузки TCP от Google и очередь fq.", s["bbr"] == "bbr", f'сейчас: <code>{e(s["bbr"])} / {e(s["qdisc"])}</code>'),
        ("fastopen", "TCP Fast Open", "Экономит RTT на повторных TCP-подключениях.", s["fastopen"] == "3", f'сейчас: <code>{e(s["fastopen"])}</code>'),
        ("mtu", "MTU probing", "Помогает при «чёрных дырах» MTU у провайдеров.", s["mtu_probing"] == "1", f'сейчас: <code>{e(s["mtu_probing"])}</code>'),
        ("buffers", "VPN-буферы 16 MiB", "Увеличивает окна TCP для быстрых каналов.", s["rmem_max"] == "16777216", f'rmem_max: <code>{e(s["rmem_max"])}</code>'),
        ("backlog", "Очереди 8192", "netdev_max_backlog и somaxconn для пиков нагрузки.", s["backlog"] == "8192", f'backlog: <code>{e(s["backlog"])}</code>'),
    ]
    switches_html = "".join(
        f'<label class="switch-row"><span><b>{title}</b><small>{hint} {now}</small></span>'
        f'<input class="switch" type="checkbox" name="{name}" value="1"{" checked" if on else ""}></label>'
        for name, title, hint, on, now in switches
    )
    network = f'''
<div class="grid">
<section class="card span-7">{card_head("sysctl", "Параметры ядра", "Каждый переключатель применяется сразу после сохранения. Выключенный — возвращает значение, которое было до установки панели.")}
<form class="js-form" method="post" action="{web_path('network')}">{hidden}<div>{switches_html}</div>
<div class="actions"><button class="btn" type="submit">{icon("check")}Применить</button></div></form></section>
<section class="card span-5">{card_head("Где хранится", "Файлы и откат")}<div class="kv">
<div><span>Настройки</span><b>/etc/sysctl.d/99-remnanode-manager-network.conf</b></div>
<div><span>Исходные значения</span><b>/var/lib/remnanode-manager/network-baseline.json</b></div>
<div><span>Резервные копии</span><b>/var/lib/remnanode-manager/backups</b></div></div>
{notice("Перед каждым изменением сохраняется резервная копия файлов sysctl.")}</section>
</div>'''

    # ---- ssh ----
    fingerprints = "".join(f'<div class="pill fp">{e(item)}</div>' for item in ssh["fingerprints"])
    fingerprints = fingerprints or '<span class="faint">Ключи root пока не найдены.</span>'
    ssh_finalize = ""
    if ssh["phase"] == "staged":
        ssh_finalize = f'''<section class="card" style="border-color:color-mix(in srgb,var(--warn) 45%,transparent)">{card_head("Этап 2 из 2", f"Оставить только порт {e(str(ssh_port_value))}", "Сейчас старый и новый порты работают одновременно.")}
{notice(f"<b>Сначала откройте вторую SSH-сессию на порту {e(str(ssh_port_value))}</b> и убедитесь, что вход работает. Только после этого подтверждайте.", "warn", "alert")}
<form class="js-form" method="post" action="{web_path('ssh-finalize')}" data-confirm="Оставить только SSH-порт {e(str(ssh_port_value))}? Старые порты будут закрыты." data-danger="1">{hidden}
<div class="cols" style="align-items:end;margin-top:16px"><label class="field"><span>Введите новый порт для подтверждения</span><input name="confirm_port" inputmode="numeric" placeholder="{e(str(ssh_port_value))}" required class="mono-in"></label>
<div class="field"><button class="btn danger" type="submit" style="width:100%">Закрыть старые порты</button></div></div></form></section>'''
    ssh_rollback = (
        f'<form class="js-form" method="post" action="{web_path("ssh-rollback")}" data-confirm="Вернуть настройки SSH из резервной копии, сделанной перед подготовкой?" data-danger="1">{hidden}'
        f'<button class="btn ghost" type="submit">{icon("restart")}Откатить SSH</button></form>'
        if ssh["backup"] else ""
    )
    phase_names = {"unmanaged": "не менялся", "staged": "ждёт подтверждения", "finalized": "применён", "rolled_back": "откачен"}
    ssh_view = f'''
<div class="grid">
{stat_card("ssh", "Порты сейчас", e(ssh_ports), "sshd и ssh.socket", "mono")}
{stat_card("shield", "Вход root по паролю", f'<span class="{"warn-t" if ssh_password_on else "ok-t"}">{"разрешён" if ssh_password_on else "выключен"}</span>', "PasswordAuthentication")}
{stat_card("ssh", "Ключей root", str(ssh["key_count"]), "authorized_keys")}
{stat_card("refresh", "Этап", e(phase_names.get(ssh["phase"], ssh["phase"])), "двухэтапная смена")}
</div>
{ssh_finalize}
<div class="grid">
<section class="card span-7">{card_head("Этап 1 из 2", "Подготовить SSH", "Новый порт поднимается параллельно текущему. Старый закрывается только после отдельного подтверждения.")}
<form class="js-form" method="post" action="{web_path('ssh')}">{hidden}
<div class="cols"><label class="field"><span>Новый SSH-порт</span><input type="number" min="1" max="65535" name="ssh_port" value="{e(str(ssh_port_value))}" required class="mono-in"></label></div>
<label class="field"><span>Публичный OpenSSH-ключ root</span><textarea class="short" name="public_key" spellcheck="false" placeholder="ssh-ed25519 AAAAC3... comment"></textarea><p class="hint">Только публичная часть ключа. Существующие ключи не заменяются.</p></label>
<label class="check"><input type="checkbox" name="password_auth" value="1"{" checked" if ssh_password_on else ""}><span>Разрешить root вход по паролю<small>Если снять флажок, останется только вход по ключу — нужен хотя бы один ключ.</small></span></label>
<div class="actions"><button class="btn" type="submit">{icon("shield")}Подготовить безопасно</button></div></form>
{ssh_rollback and f'<div class="actions">{ssh_rollback}</div>'}</section>
<section class="card span-5">{card_head("authorized_keys", "Ключи root", "Отпечатки ключей, которые принимает OpenSSH.")}<div style="display:grid;gap:8px">{fingerprints}</div>
{notice("Перед каждым шагом создаётся резервная копия конфигурации SSH. Откат возвращает состояние до подготовки.")}</section>
</div>'''

    # ---- meltun ----
    meltun_state = (
        '<span class="pill ok"><span class="dot ok"></span>передаёт логи</span>' if forwarder_active
        else '<span class="pill warn">служба остановлена</span>' if forwarder_config
        else '<span class="pill">не подключён</span>'
    )
    https_links = "".join(
        f'<a class="pill" href="https://{e(site["domain"])}{web_path()}">https://{e(site["domain"])}{web_path()}</a>'
        for site in public_sites
    )
    meltun = f'''
<div class="grid">
<section class="card span-7">{card_head("Access log", "Передавать подключения в MelTun", "Нода сама обменяет одноразовый код на рабочий ключ по исходящему HTTPS. Домен и сертификат ей не нужны.", meltun_state)}
<form class="js-form" method="post" action="{web_path('access-forwarder')}">{hidden}<input type="hidden" name="endpoint" value="https://meltun.org/api/admin/node-logs/ingest">
<div class="cols"><label class="field"><span>ID ноды — как при выдаче кода</span><input name="node_id" value="{e(forwarder_config.get('node_id', ''))}" placeholder="GERMANY" required class="mono-in" autocomplete="off"></label>
<label class="field"><span>Часовой пояс логов Xray</span><select name="log_timezone"><option value="UTC"{" selected" if forwarder_config.get("log_timezone", "UTC") == "UTC" else ""}>UTC</option><option value="Europe/Moscow"{" selected" if forwarder_config.get("log_timezone") == "Europe/Moscow" else ""}>Europe/Moscow</option></select></label></div>
<label class="field"><span>Одноразовый код из MelTun</span><input name="pair_code" type="password" autocomplete="off" placeholder="Код действует 10 минут" required class="mono-in"></label>
<div class="actions"><button class="btn" type="submit">{icon("meltun")}Подключить ноду</button></div></form>
{f'<div class="pills" style="margin-top:16px">{https_links}</div>' if https_links else ''}</section>
<section class="card span-5">{card_head("Порядок", "Как подключить")}
<ol class="steps">
<li><a href="#meltun"><span class="n">1</span><span><b>Получите код</b><small>MelTun → Ноды → Сбор логов Xray: ID и публичный IP ноды.</small></span></a></li>
<li><a href="#install"><span class="n">2</span><span><b>Пересохраните Compose</b><small>Добавится монтирование /var/log/remnanode — затем переустановите контейнер.</small></span></a></li>
<li><a href="#meltun"><span class="n">3</span><span><b>Включите access log</b><small>В профиле Xray: log.access = /var/log/remnanode/access.log</small></span></a></li>
</ol>
<div class="code-wrap" style="margin-top:14px"><button class="btn small ghost" type="button" data-copy-target="log-json">{icon("copy")}<span data-label>Копировать</span></button>
<pre class="term" id="log-json">"log": {{
  "access": "/var/log/remnanode/access.log",
  "error": "/var/log/remnanode/error.log",
  "loglevel": "warning"
}}</pre></div></section>
</div>'''

    # ---- logs ----
    logs = f'''
<section class="card"><div class="toolbar"><div class="segmented" role="tablist">
<button type="button" class="active" data-stream="container">Docker logs</button><button type="button" data-stream="xray">Xray · xlogs</button></div>
<div class="tool-row" style="align-items:center"><span class="live"><span id="live-dot" class="dot"></span><span id="live-text">ожидание</span></span>
<button type="button" class="btn small ghost" data-clear-log>{icon("trash")}Очистить</button></div></div>
<div id="live-log" class="term tall">Откройте вкладку, чтобы подключить поток логов.</div></section>'''

    views = [
        ("overview", "Обзор", "Состояние ноды", "overview", overview),
        ("install", "Установка", "Compose и версия RemnaNode", "install", install),
        ("tls", "Сертификаты", "TLS, домены и порт 443", "tls", certificates),
        ("inbound", "Inbound", "Генератор профилей Xray", "inbound", inbound),
        ("network", "Сеть", "Тюнинг ядра", "network", network),
        ("ssh", "SSH", "Ключ, порт и пароль", "ssh", ssh_view),
        ("meltun", "MelTun", "История подключений", "meltun", meltun),
        ("logs", "Логи", "Потоки в реальном времени", "logs", logs),
    ]
    badges = {
        "install": "ok" if state == "running" else "warn",
        "ssh": "warn" if ssh["phase"] == "staged" else "",
    }
    badge_html = '<i class="badge"></i>'
    nav = "".join(
        f'<a href="#{key}" data-view="{key}">{icon(icon_name)}<span>{title}</span>'
        f'{badge_html if badges.get(key) == "warn" else ""}</a>'
        for key, title, _crumb, icon_name, _body in views
    )
    sections = "".join(
        f'<section class="view" id="view-{key}" data-title="{title}" data-crumb="{crumb}"{"" if key == "logs" else " data-refresh"}>{body}</section>'
        for key, title, crumb, _icon, body in views
    )
    body = f'''<div class="app">
<aside class="side"><a class="brand" href="#overview">{LOGO}<div><b>Node Forge</b><small>Meltun · нода</small></div></a>
<nav class="nav" id="nav" aria-label="Разделы">{nav}</nav>
<div class="side-foot"><div class="ip" id="side-ip"><span class="dot {state_cls}"></span>{e(s["public_ip"])}</div>
<div class="tool-row"><button class="icon-btn" type="button" data-theme-toggle title="Сменить тему">{icon("moon")}Тема</button>
<a class="icon-btn" href="{web_path('logout')}" title="Выйти">{icon("logout")}Выйти</a></div></div></aside>
<div class="content"><header class="topbar"><div><div class="crumb" id="view-crumb">Состояние ноды</div><h1 id="view-title">Обзор</h1></div>
<div class="top-tools"><span class="chip"><span id="chip-dot" class="dot {state_cls}"></span><span class="long">remnanode ·</span><span id="chip-text">{e(state_label)}</span></span>
<button class="icon-btn mobile-only" type="button" data-theme-toggle title="Сменить тему" style="flex:none;width:34px">{icon("moon")}</button>
<a class="icon-btn mobile-only" href="{web_path('logout')}" title="Выйти" style="flex:none;width:34px">{icon("logout")}</a></div></header>
<main>{sections}</main>
<footer class="foot">Node Forge · backend {e(BIND)}:{PORT} · маршрут {e(BASE_PATH)}/</footer></div></div>
<div id="toasts" aria-live="polite"></div>
<dialog id="confirm"><form method="dialog" class="dlg"><div class="dlg-icon">{icon("alert")}</div><h3>Подтвердите действие</h3><p id="confirm-text"></p>
<div class="actions"><button class="btn ghost" value="cancel" id="confirm-cancel">Отмена</button><button class="btn" value="ok" id="confirm-ok">Продолжить</button></div></form></dialog>'''
    boot = {
        "base": BASE_PATH, "stateLabels": STATE_LABELS, "phaseLabels": PHASE_LABELS,
        "status": runtime, "flash": {"ok": message, "error": error},
    }
    return render_page("Node Forge", body, boot, APP_JS)


class Handler(BaseHTTPRequestHandler):
    server_version = "NodeForge/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"{self.client_ip()} {fmt % args}", flush=True)

    def send_html(self, body, code=200, headers=None):
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, body, code=200):
        payload = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def client_ip(self):
        ip = self.client_address[0]
        # Nginx is the only local reverse proxy; it overwrites X-Real-IP.
        if ip in ("127.0.0.1", "::1"):
            forwarded = normalize_ip(self.headers.get("X-Real-IP", ""))
            if forwarded:
                return forwarded
        return ip

    def is_https(self):
        return self.headers.get("X-Forwarded-Proto") == "https"

    def session(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return None, None
        token = jar["rnm_session"].value if "rnm_session" in jar else ""
        return token, get_session(token)

    def wants_json(self):
        return "application/json" in self.headers.get("Accept", "")

    def stream_logs(self, source):
        commands = {
            "container": ["docker", "logs", "--follow", "--tail", "150", "--timestamps", "remnanode"],
            "xray": ["docker", "exec", "remnanode", "xlogs"],
        }
        if source not in commands:
            return self.send_json({"error": "Неизвестный источник логов."}, 400)
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
            self.wfile.write(f"event: ready\ndata: {json.dumps(source)}\n\n".encode())
            self.wfile.flush()
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
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            message = f"Команда логов завершилась с кодом {process.poll()}."
            self.wfile.write(f"event: terminal\ndata: {json.dumps(message, ensure_ascii=False)}\n\n".encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            selector.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()

    def routed(self):
        path, _, query = self.path.partition("?")
        if path == BASE_PATH:
            return "/", query
        if not path.startswith(BASE_PATH + "/"):
            return None, query
        return path[len(BASE_PATH):] or "/", query

    def form(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 1_000_000:
            raise ValueError("Слишком большой запрос.")
        return urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)

    def redirect(self, message="", error=""):
        query = urllib.parse.urlencode({key: value for key, value in (("ok", message), ("error", error)) if value})
        self.send_response(303)
        self.send_header("Location", web_path() + ("?" + query if query else ""))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def respond(self, message="", error="", status=None):
        if self.wants_json():
            if error:
                return self.send_json({"error": error}, 400)
            payload = {"ok": True, "message": message}
            if status is not None:
                payload["status"] = status
            return self.send_json(payload)
        return self.redirect(message=message, error=error)

    def session_cookie(self, token, max_age):
        secure = "; Secure" if self.is_https() else ""
        return f"rnm_session={token}; Max-Age={max_age}; HttpOnly; SameSite=Strict; Path={web_path()}{secure}"

    def do_GET(self):
        path, query = self.routed()
        if path is None:
            return self.send_html("Not found", 404)
        token, session = self.session()
        if path == "/logout":
            drop_session(token)
            return self.send_html(render_login(), headers={"Set-Cookie": self.session_cookie("", 0)})
        if not session:
            if path.startswith("/api/") or path == "/stream":
                return self.send_json({"error": "Требуется вход."}, 401)
            return self.send_html(render_login(), 401)
        args = urllib.parse.parse_qs(query)
        if path == "/api/status":
            return self.send_json(runtime_status())
        if path == "/stream":
            return self.stream_logs(args.get("source", ["container"])[0])
        if path != "/":
            return self.send_html("Not found", 404)
        return self.send_html(render_dashboard(session["csrf"], args.get("ok", [""])[0], args.get("error", [""])[0]))

    def do_POST(self):
        path, _ = self.routed()
        if path is None:
            return self.send_html("Not found", 404)
        try:
            form = self.form()
        except Exception as exc:
            return self.send_html(render_login(str(exc)), 400)
        if path == "/login":
            ip = self.client_ip()
            if not login_allowed(ip):
                return self.send_html(render_login("Слишком много попыток. Подождите минуту."), 429)
            if hmac.compare_digest(form.get("password", [""])[0].encode(), ADMIN_PASSWORD.encode()):
                reset_login_failures(ip)
                self.send_response(303)
                self.send_header("Location", web_path())
                self.send_header("Set-Cookie", self.session_cookie(create_session(), SESSION_TTL))
                self.send_header("Content-Length", "0")
                return self.end_headers()
            record_login_failure(ip)
            return self.send_html(render_login("Неверный пароль."), 401)
        token, session = self.session()
        if not session:
            if self.wants_json() or path.startswith("/api/"):
                return self.send_json({"error": "Сессия истекла — войдите заново."}, 401)
            return self.send_html(render_login(), 401)
        if not hmac.compare_digest(form.get("csrf", [""])[0].encode(), session["csrf"].encode()):
            return self.respond(error="Проверка CSRF не пройдена. Обновите страницу.")
        if path == "/access-forwarder" and form.get("token", [""])[0].strip() and not (
            self.is_https() or (self.client_address[0] in ("127.0.0.1", "::1") and "X-Forwarded-For" not in self.headers)
        ):
            return self.respond(error="Постоянный токен ноды можно передавать только по HTTPS или через SSH-туннель. Одноразовый код подключения можно вводить и по HTTP.")
        handlers = {
            "/compose": apply_compose,
            "/access-forwarder": configure_access_forwarder,
            "/cert": issue_certificate,
            "/public-https": toggle_public_https,
            "/network": apply_network,
            "/ssh": apply_ssh_access,
            "/ssh-finalize": finalize_ssh_access,
            "/ssh-rollback": lambda _form: rollback_ssh_access(),
            "/inbound": generate_inbound,
            "/action": node_action,
        }
        try:
            if path == "/api/install":
                start_install(form)
                return self.respond(message="Установка запущена. Ход виден ниже.", status=runtime_status())
            handler = handlers.get(path)
            if not handler:
                raise ValueError("Неизвестное действие.")
            return self.respond(message=handler(form))
        except Exception as exc:
            return self.respond(error=str(exc)[-4000:])


if __name__ == "__main__":
    network_baseline()
    load_install_state()
    threading.Thread(target=warm_caches, daemon=True, name="warm-caches").start()
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()
PY
chmod 0750 /opt/remnanode-manager/app.py

cat > /opt/remnanode-manager/access_forwarder.py <<'PY'
#!/usr/bin/env python3
"""Forward Xray access events with a durable offset and idempotent event IDs."""
import datetime
import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.request
from pathlib import Path

CONFIG = Path("/etc/remnanode-access-forwarder.json")
STATE = Path("/var/lib/remnanode-manager/access-forwarder-state.json")
SOURCE = Path("/var/log/remnanode/access.log")
LINE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(?:\.\d+)?) from (\[[^]]+\]|[^\s:]+):\d+ accepted (tcp|udp):([^\s]+).*? email: ([^\s]+)")


def parse_line(raw, inode, offset, log_timezone="UTC"):
    match = LINE.search(raw)
    if not match:
        return None
    stamp, source, network, destination, username = match.groups()
    route_match = re.search(r"\[([^]]+)\]\s+email:", raw)
    route = route_match.group(1) if route_match else ""
    try:
        source = str(ipaddress.ip_address(source.strip("[]")))
        occurred = datetime.datetime.strptime(stamp.split(".")[0], "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None
    if username == "-" or not username:
        return None
    identity = hashlib.sha256(f"{inode}:{offset}:{raw}".encode()).hexdigest()
    zone = datetime.timezone(datetime.timedelta(hours=3)) if log_timezone == "Europe/Moscow" else datetime.timezone.utc
    return {
        "event_id": identity, "occurred_at": occurred.replace(tzinfo=zone).astimezone(datetime.timezone.utc).isoformat(),
        "panel_username": username[:255], "source_ip": source,
        "destination": destination[:255], "network": network, "route": (route or "")[:255],
    }


def load_state():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(inode, offset):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"inode": inode, "offset": offset}))
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE)


def send_batch(config, events):
    data = json.dumps({"node_id": config["node_id"], "events": events}).encode()
    request = urllib.request.Request(
        config["endpoint"], data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + config["token"]},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"Unexpected response: {response.status}")


def main():
    while True:
        try:
            config = json.loads(CONFIG.read_text())
            if config.get("endpoint") != "https://meltun.org/api/admin/node-logs/ingest":
                raise ValueError("Invalid endpoint")
            stat = SOURCE.stat()
            state = load_state()
            inode = stat.st_ino
            # First activation starts at the current tail; rotation or truncation starts at zero.
            offset = stat.st_size if not state else (state.get("offset", 0) if state.get("inode") == inode and stat.st_size >= state.get("offset", 0) else 0)
            if not state:
                save_state(inode, offset)
            events = []
            with SOURCE.open("rb") as stream:
                stream.seek(offset)
                for _ in range(200):
                    start = stream.tell()
                    raw = stream.readline()
                    if not raw or not raw.endswith(b"\n"):
                        break
                    offset = stream.tell()
                    event = parse_line(raw.decode("utf-8", "replace").strip(), inode, start, config.get("log_timezone", "UTC"))
                    if event:
                        events.append(event)
            if events:
                send_batch(config, events)
            save_state(inode, offset)
            if len(events) < 200:
                time.sleep(2)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            print(f"Access forwarder waiting: {exc}", flush=True)
            time.sleep(10)
        except Exception as exc:
            print(f"Access forwarder retrying: {type(exc).__name__}: {exc}", flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
PY
chmod 0750 /opt/remnanode-manager/access_forwarder.py

cat > /etc/systemd/system/remnanode-access-forwarder.service <<'UNIT'
[Unit]
Description=Forward RemnaNode Xray access logs to Meltun
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/remnanode-manager/access_forwarder.py
Restart=always
RestartSec=5
User=root
Group=root
UMask=0077
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/remnanode-manager
ReadOnlyPaths=/var/log/remnanode /etc/remnanode-access-forwarder.json

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/logrotate.d/remnanode-access <<'ROTATE'
/var/log/remnanode/access.log /var/log/remnanode/error.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    copytruncate
    su root root
}
ROTATE

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
if nginx -t >/dev/null 2>&1; then
  systemctl reload nginx
fi
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
if [[ -f /etc/remnanode-access-forwarder.json ]]; then
  systemctl enable --now remnanode-access-forwarder.service
  systemctl restart remnanode-access-forwarder.service
fi

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

# Re-installing Node Forge upgrades existing managed TLS sites without
# reissuing certificates or changing the Xray/REALITY listener.
python3 - <<'PY'
import os
import runpy

with open('/etc/remnanode-manager.env', encoding='utf-8') as env_file:
    for line in env_file:
        key, separator, value = line.strip().partition('=')
        if separator and key.startswith('RNM_'):
            os.environ[key] = value
app = runpy.run_path('/opt/remnanode-manager/app.py')
domains = app['refresh_https_manager_routes']()
if domains:
    print('HTTPS manager routes updated: ' + ', '.join(domains))
PY

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
