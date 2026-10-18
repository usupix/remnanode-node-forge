"""MelTun public availability page. Python standard library; one collector."""
import concurrent.futures
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

LOG = logging.getLogger("meltun-status")
MSK = ZoneInfo("Europe/Moscow")
INTERVAL = 60
MAX_GAP = 150
ROOT = Path(__file__).parent
COUNTRIES = {"DE": "Германия", "EE": "Эстония", "SE": "Швеция", "LV": "Латвия",
             "NL": "Нидерланды", "FI": "Финляндия", "TR": "Турция", "KZ": "Казахстан",
             "US": "США", "RU": "Россия", "GB": "Великобритания", "FR": "Франция",
             "PL": "Польша", "LT": "Литва", "UA": "Украина", "CH": "Швейцария",
             "AT": "Австрия", "CZ": "Чехия", "ES": "Испания", "IT": "Италия",
             "RO": "Румыния", "BG": "Болгария", "NO": "Норвегия", "DK": "Дания",
             "CA": "Канада", "AU": "Австралия", "BR": "Бразилия", "JP": "Япония",
             "SG": "Сингапур", "HK": "Гонконг", "AE": "ОАЭ", "IL": "Израиль",
             "BE": "Бельгия", "IE": "Ирландия", "PT": "Португалия", "AM": "Армения",
             "GE": "Грузия", "MD": "Молдова", "RS": "Сербия", "IS": "Исландия"}
LABELS = {"GERMANY-DARAFOREST": "Германия · Dataforest", "ES-NODA": "Эстония",
          "EE-GAME-NODA": "Эстония · игровой", "SWEDEN-UPHOST": "Швеция",
          "LV-NODA": "Латвия", "NL01-NODA": "Нидерланды", "FINLAND": "Финляндия",
          "TYRKNEY": "Турция", "KZ-YANDEX": "Казахстан", "USA": "США", "RUSSIAVK": "Россия · VK"}


def normalized_ip(value):
    try:
        parsed = ipaddress.ip_address(value)
        if getattr(parsed, "ipv4_mapped", None):
            parsed = parsed.ipv4_mapped
        return str(parsed)
    except ValueError:
        return ""


class Store:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, country TEXT NOT NULL,
                    position INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                    created REAL NOT NULL, last_ts REAL, state TEXT NOT NULL DEFAULT 'unknown',
                    raw_state TEXT, failures INTEGER NOT NULL DEFAULT 0, latency REAL,
                    agent_id TEXT, cert_hash TEXT, agent_seen REAL, agent_core INTEGER,
                    source TEXT NOT NULL DEFAULT 'panel', agent_ip TEXT, panel_uuid TEXT UNIQUE,
                    agent_name TEXT, agent_country TEXT
                );
                CREATE TABLE IF NOT EXISTS spans (
                    id INTEGER PRIMARY KEY, node_id TEXT NOT NULL, start REAL NOT NULL,
                    end REAL NOT NULL, state TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS spans_node_end ON spans(node_id,end);
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY, node_id TEXT NOT NULL, start REAL NOT NULL, end REAL,
                    kind TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS replays (nonce TEXT PRIMARY KEY, expires REAL NOT NULL);
            """)
            existing = {row[1] for row in db.execute("PRAGMA table_info(nodes)")}
            for name in ("agent_name", "agent_country"):
                if name not in existing:
                    db.execute("ALTER TABLE nodes ADD COLUMN " + name + " TEXT")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    def sync(self, inventory, now):
        with self.lock, self.connect() as db:
            db.execute("UPDATE nodes SET active=0 WHERE source='panel'")
            for node in inventory:
                country = str(node.get("countryCode") or "").upper()
                name = LABELS.get(node["name"], COUNTRIES.get(country, node["name"]))
                # Keep multiple nodes in a country distinguishable when their name is new.
                if node["name"] not in LABELS and name != node["name"]:
                    name += " · " + node["name"][:60]
                existing = db.execute("SELECT id FROM nodes WHERE panel_uuid=? OR id=?", (node["uuid"], node["uuid"])).fetchone()
                if not existing and normalized_ip(node["address"]):
                    existing = db.execute("SELECT id FROM nodes WHERE source='agent' AND agent_ip=? LIMIT 1", (normalized_ip(node["address"]),)).fetchone()
                status_id = existing[0] if existing else node["uuid"]
                node["status_id"] = status_id
                db.execute("""INSERT INTO nodes(id,name,country,position,active,created,panel_uuid)
                    VALUES(?,?,?,?,1,?,?) ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,country=excluded.country,position=excluded.position,
                    active=1,panel_uuid=excluded.panel_uuid,source='panel'""",
                    (status_id, name[:100], country[:2], int(node.get("viewPosition") or 0), now, node["uuid"]))

    def _span(self, db, node_id, start, end, state):
        if end <= start:
            return
        previous = db.execute("SELECT * FROM spans WHERE node_id=? ORDER BY id DESC LIMIT 1", (node_id,)).fetchone()
        if previous and previous["state"] == state and abs(previous["end"] - start) < .01:
            db.execute("UPDATE spans SET end=? WHERE id=?", (end, previous["id"]))
        else:
            db.execute("INSERT INTO spans(node_id,start,end,state) VALUES(?,?,?,?)", (node_id, start, end, state))

    def observe(self, node_id, raw, latency, now):
        with self.lock, self.connect() as db:
            row = db.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
            if not row:
                return
            if row["last_ts"] is not None and now <= row["last_ts"]:
                return
            # Require two failed cycles before publishing an outage.
            failures = row["failures"] + 1 if raw in ("down", "degraded") else 0
            state = "unknown" if failures == 1 else raw
            if raw == "unknown":
                failures = 0
            confirmed = row["failures"] == 1 and failures == 2 and row["last_ts"] is not None and now - row["last_ts"] <= MAX_GAP
            if row["last_ts"] is not None:
                self._span(db, node_id, row["last_ts"], min(now, row["last_ts"] + MAX_GAP), raw if confirmed else row["state"])
            if state in ("down", "degraded") and row["state"] not in ("down", "degraded"):
                db.execute("INSERT INTO incidents(node_id,start,kind) VALUES(?,?,?)", (node_id, row["last_ts"] if confirmed else now, state))
            if state == "up":
                db.execute("UPDATE incidents SET end=? WHERE node_id=? AND end IS NULL", (now, node_id))
            db.execute("UPDATE nodes SET last_ts=?,state=?,raw_state=?,failures=?,latency=? WHERE id=?",
                       (now, state, raw, failures, latency, node_id))

    def meta(self, key, value=None):
        with self.lock, self.connect() as db:
            if value is not None:
                db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
                return value
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return row[0] if row else None

    def heartbeat(self, node_id, payload, fingerprint, source, now):
        agent_id = payload["agent_id"]
        replay = fingerprint + ":" + payload["nonce"]
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM replays WHERE expires<?", (now,))
            if db.execute("SELECT 1 FROM replays WHERE nonce=?", (replay,)).fetchone():
                return False
            agent = db.execute("SELECT * FROM nodes WHERE agent_id=?", (agent_id,)).fetchone()
            if agent and agent["cert_hash"] != fingerprint and node_id != agent["id"]:
                return False
            target = node_id or (agent["id"] if agent else "agent:" + agent_id)
            row = db.execute("SELECT * FROM nodes WHERE id=?", (target,)).fetchone()
            if row and row["agent_id"] and row["agent_id"] != agent_id:
                return False
            if agent and agent["id"] != target:
                return False
            if not row:
                db.execute("""INSERT INTO nodes(id,name,country,position,created,source,agent_ip)
                    VALUES(?,?,?,1000,?,'agent',?)""", (target, payload["name"], payload["country"], now, source))
            db.execute("""UPDATE nodes SET agent_id=?,cert_hash=?,agent_seen=?,agent_core=?,agent_ip=?,
                agent_name=?,agent_country=?,active=1 WHERE id=?""",
                (agent_id, fingerprint, now, int(payload["core_running"]), source, payload["name"], payload["country"], target))
            db.execute("INSERT INTO replays VALUES(?,?)", (replay, now + 300))
            return True

    def observe_agents(self, now):
        with self.connect() as db:
            rows = db.execute("SELECT id,agent_seen,agent_core FROM nodes WHERE source='agent' AND active=1").fetchall()
        for row in rows:
            state = "down" if now - row["agent_seen"] > 180 else "up" if row["agent_core"] else "degraded"
            self.observe(row["id"], state, None, now)

    def agent_unhealthy(self, node_id, now):
        with self.connect() as db:
            row = db.execute("SELECT agent_seen,agent_core FROM nodes WHERE id=?", (node_id,)).fetchone()
            return bool(row and row["agent_seen"] and now - row["agent_seen"] < 180 and row["agent_core"] == 0)

    def public(self, days=90, now=None, hours=None):
        now = time.time() if now is None else now
        if hours is not None:
            if hours not in (3, 6, 12):
                raise ValueError("Invalid hourly period")
            start = now - hours * 3600
            step = 600 if hours == 12 else 300
            bins = [(start + i * step, min(now, start + (i + 1) * step)) for i in range(hours * 3600 // step)]
        else:
            if days not in (7, 30, 90):
                raise ValueError("Invalid daily period")
            midnight = dt.datetime.fromtimestamp(now, MSK).replace(hour=0, minute=0, second=0, microsecond=0)
            first = midnight - dt.timedelta(days=days - 1)
            start = first.timestamp()
            step = 86400
            bins = [((first + dt.timedelta(days=i)).timestamp(), min(now, (first + dt.timedelta(days=i + 1)).timestamp())) for i in range(days)]
        with self.lock, self.connect() as db:
            rows = db.execute("SELECT * FROM nodes WHERE active=1 ORDER BY position,name").fetchall()
            names, seen = {}, {}
            for node in rows:
                code = node["agent_country"] or node["country"]
                country = COUNTRIES.get(code, "Другая страна")
                seen[country] = seen.get(country, 0) + 1
                names[node["id"]] = country + (" #" + str(seen[country]) if seen[country] > 1 else "")
            latest = float(self.meta("last_cycle") or 0)
            fresh = latest > 0 and now - latest <= MAX_GAP
            output = []
            for node in rows:
                spans = [dict(r) for r in db.execute("SELECT start,end,state FROM spans WHERE node_id=? AND end>? ORDER BY start", (node["id"], start))]
                if node["last_ts"] is not None:
                    spans.append({"start": node["last_ts"], "end": min(now, node["last_ts"] + MAX_GAP), "state": node["state"]})
                history = []
                totals = {"up": 0., "down": 0., "degraded": 0.}
                for a, b in bins:
                    amounts = {"up": 0., "down": 0., "degraded": 0.}
                    for span in spans:
                        if span["state"] in amounts:
                            amounts[span["state"]] += max(0, min(b, span["end"]) - max(a, span["start"]))
                    measured = sum(amounts.values())
                    for key in amounts:
                        totals[key] += amounts[key]
                    history.append({"date": dt.datetime.fromtimestamp(a, MSK).date().isoformat(), "start": a, "end": b,
                                    "uptime": round(amounts["up"] / measured * 100, 3) if measured else None,
                                    "measured_seconds": round(measured), "outage_seconds": round(amounts["down"]),
                                    "degraded_seconds": round(amounts["degraded"])})
                measured = sum(totals.values())
                current = node["state"] if fresh and node["last_ts"] and now - node["last_ts"] <= MAX_GAP else "unknown"
                output.append({"id": node["id"], "name": names[node["id"]],
                               "country": node["agent_country"] or node["country"], "state": current,
                               "since": node["created"], "last_check": node["last_ts"],
                               "uptime": round(totals["up"] / measured * 100, 3) if measured else None,
                               "measured_seconds": round(measured), "history": history})
            incidents = [{"id": r["id"], "name": names[r["node_id"]], "start": r["start"], "end": r["end"], "kind": r["kind"]}
                         for r in db.execute("""SELECT i.id,i.node_id,i.start,i.end,i.kind FROM incidents i
                JOIN nodes n ON n.id=i.node_id WHERE n.active=1 AND (i.end IS NULL OR i.end>?) ORDER BY i.start DESC LIMIT 40""", (start,))]
        states = [n["state"] for n in output]
        overall = "unknown" if not states or not fresh else ("down" if all(s == "down" for s in states) else
                   "degraded" if any(s in ("down", "degraded") for s in states) else "unknown" if "unknown" in states else "up")
        return {"state": overall, "days": days if hours is None else None, "hours": hours,
                "period_start": start, "bucket_seconds": step, "updated_at": latest or None, "generated_at": now,
                "interval_seconds": INTERVAL, "timezone": "Europe/Moscow", "nodes": output, "incidents": incidents}


def panel_nodes():
    token = Path(os.environ.get("STATUS_PANEL_TOKEN_FILE", "/run/secrets/panel-api-token")).read_text().strip()
    req = urllib.request.Request(os.environ.get("STATUS_PANEL_URL", "http://remnawave:3000/api/nodes"), headers={
        "Authorization": "Bearer " + token, "Host": "control.meltun.ru", "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "127.0.0.1"})
    with urllib.request.urlopen(req, timeout=12) as response:
        payload = json.load(response)["response"]
    nodes = payload if isinstance(payload, list) else payload["nodes"]
    return [n for n in nodes if not n.get("isDisabled")]


def probe(node):
    start = time.monotonic()
    try:
        with socket.create_connection((node["address"], int(node["port"])), timeout=4):
            latency = (time.monotonic() - start) * 1000
        return ("up" if node.get("isConnected") else "degraded"), latency
    except (OSError, ValueError):
        return "down", None


def verify_proof(payload, certificate, signature, ca_file):
    """Trust only the panel CA; never accept a client-supplied CA or private key."""
    if not isinstance(certificate, str) or len(certificate) > 6000 or "PRIVATE KEY" in certificate:
        return None
    try:
        signature = base64.b64decode(signature, validate=True)
        if len(signature) > 512:
            return None
        with tempfile.TemporaryDirectory(prefix="status-proof-") as temp:
            cert, public, signed, message = [Path(temp) / name for name in ("cert.pem", "pub.pem", "sig", "message")]
            cert.write_text(certificate)
            checked = subprocess.run(["openssl", "verify", "-CAfile", str(ca_file), "-purpose", "any", str(cert)], capture_output=True, timeout=5)
            if checked.returncode:
                return None
            result = subprocess.run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"], capture_output=True, timeout=5)
            if result.returncode:
                return None
            public.write_bytes(result.stdout)
            signed.write_bytes(signature)
            message.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
            result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(signed), str(message)], capture_output=True, timeout=5)
            return hashlib.sha256(certificate.encode()).hexdigest() if result.returncode == 0 else None
    except (ValueError, TypeError, OSError, subprocess.SubprocessError):
        return None


class Service:
    def __init__(self, store):
        self.store = store
        self.inventory = []
        self.inventory_at = 0
        self.lock = threading.Lock()
        self.rates = {}
        self.stop = threading.Event()

    def source_node(self, source):
        with self.lock:
            if time.time() - self.inventory_at > MAX_GAP:
                return None
            inventory = list(self.inventory)
        matches = []
        for node in inventory:
            addresses = {normalized_ip(node["address"])}
            if not normalized_ip(node["address"]):
                try:
                    addresses.update(normalized_ip(r[4][0]) for r in socket.getaddrinfo(node["address"], None, type=socket.SOCK_STREAM))
                except OSError:
                    continue
            if source and source in addresses:
                matches.append(node.get("status_id", node["uuid"]))
        return matches[0] if len(matches) == 1 else None

    def cycle(self):
        now = time.time()
        try:
            nodes = panel_nodes()
            self.store.sync(nodes, now)
            with self.lock:
                self.inventory, self.inventory_at = nodes, now
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(probe, n): n for n in nodes}
                for future in concurrent.futures.as_completed(futures):
                    node = futures[future]
                    state, latency = future.result()
                    if state == "up" and self.store.agent_unhealthy(node["status_id"], time.time()):
                        state = "degraded"
                    self.store.observe(node["status_id"], state, latency, time.time())
            self.store.observe_agents(time.time())
            self.store.meta("last_cycle", time.time())
        except Exception as error:
            # Never put API responses, addresses or credentials in logs/public output.
            LOG.warning("Collector unavailable (%s)", type(error).__name__)
            with self.store.connect() as db:
                rows = db.execute("SELECT id,agent_seen,agent_core FROM nodes WHERE active=1 AND source='panel'").fetchall()
            for row in rows:
                recent = row["agent_seen"] and time.time() - row["agent_seen"] < 180
                state = ("up" if row["agent_core"] else "degraded") if recent else "unknown"
                self.store.observe(row["id"], state, None, time.time())
            self.store.observe_agents(time.time())
            self.store.meta("last_cycle", time.time())

    def collect(self):
        while not self.stop.is_set():
            started = time.monotonic()
            self.cycle()
            self.stop.wait(max(1, INTERVAL - (time.monotonic() - started)))

    def rate_allowed(self, source):
        now = time.monotonic()
        with self.lock:
            if len(self.rates) > 4096:
                self.rates = {ip: stamp for ip, stamp in self.rates.items() if now - stamp < 60}
            previous = self.rates.get(source, -100)
            if now - previous < 5:
                return False
            self.rates[source] = now
            return True


def handler_class(service):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send(self, status, data, content_type="application/json; charset=utf-8"):
            raw = json.dumps(data, ensure_ascii=False).encode() if isinstance(data, dict) else data
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store" if content_type.startswith("application/json") else "public, max-age=60")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            from urllib.parse import urlsplit, parse_qs
            parsed = urlsplit(self.path)
            if parsed.path == "/api/status":
                try:
                    args = parse_qs(parsed.query, keep_blank_values=True)
                    hours = int(args["hours"][0]) if "hours" in args else None
                    days = int(args.get("days", ["90"])[0])
                    if days not in (7, 30, 90):
                        raise ValueError()
                    if hours is not None and (hours not in (3, 6, 12) or "days" in args):
                        raise ValueError()
                except ValueError:
                    return self.send(400, {"error": "Invalid period"})
                return self.send(200, service.store.public(days, hours=hours))
            if parsed.path == "/healthz":
                stamp = float(service.store.meta("last_cycle") or 0)
                healthy = time.time() - stamp <= MAX_GAP
                return self.send(200 if healthy else 503, {"ok": healthy})
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8"), "/favicon.svg": ("favicon.svg", "image/svg+xml"),
                      "/flags.svg": ("flags.svg", "image/svg+xml"), "/theme.js": ("theme.js", "application/javascript; charset=utf-8")}
            if parsed.path in assets:
                filename, mime = assets[parsed.path]
                return self.send(200, (ROOT / "static" / filename).read_bytes(), mime)
            return self.send(404, {"error": "Not found"})

        def do_POST(self):
            if self.path != "/api/agent/heartbeat":
                return self.send(404, {"error": "Not found"})
            source = normalized_ip(self.headers.get("X-Real-IP", ""))
            if not service.rate_allowed(source):
                return self.send(429, {"error": "Try later"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 12000:
                    raise ValueError()
                data = json.loads(self.rfile.read(length))
                import re
                payload = data["payload"]
                if set(payload) != {"agent_id", "timestamp", "nonce", "core_running", "name", "country"}:
                    raise ValueError()
                if not re.fullmatch(r"[a-f0-9]{32}", payload["agent_id"]) or not re.fullmatch(r"[a-f0-9]{32}", payload["nonce"]):
                    raise ValueError()
                if type(payload["timestamp"]) is not int or abs(time.time() - payload["timestamp"]) > 120:
                    raise ValueError()
                if not isinstance(payload["core_running"], bool) or not isinstance(payload["name"], str) or not 1 <= len(payload["name"]) <= 80:
                    raise ValueError()
                if any(ord(c) < 32 for c in payload["name"]) or not re.fullmatch(r"[A-Z]{2}|", payload["country"]):
                    raise ValueError()
            except (ValueError, KeyError, TypeError):
                return self.send(400, {"error": "Invalid request"})
            fingerprint = verify_proof(payload, data.get("certificate"), data.get("signature"), os.environ.get("STATUS_CA_FILE", "/run/secrets/panel-ca.pem"))
            if not fingerprint:
                return self.send(403, {"error": "Signature does not match this Remnawave panel"})
            node_id = service.source_node(source)
            ok = service.store.heartbeat(node_id, payload, fingerprint, source, time.time())
            return self.send(200 if ok else 403, {"ok": ok})
    return Handler


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    store = Store(os.environ.get("STATUS_DB", "/data/status.sqlite3"))
    service = Service(store)
    threading.Thread(target=service.collect, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), handler_class(service))
    server.daemon_threads = True
    server.serve_forever()
