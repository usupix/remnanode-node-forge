"""MelTun public availability page. Python standard library; one collector."""
import concurrent.futures
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
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


def overlap_seconds(intervals, start, end):
    """Measure the union so overlapping maintenance notices never double-count."""
    clipped = sorted((max(start, a), min(end, b)) for a, b in intervals if b > start and a < end)
    total, until = 0., start
    for a, b in clipped:
        total += max(0, b - max(a, until))
        until = max(until, b)
    return total


def maintenance_state(record, now):
    if record.get("cancelled_at") is not None:
        return "cancelled"
    if now < record["starts_at"]:
        return "scheduled"
    return "active" if now < record["ends_at"] else "completed"


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
                CREATE TABLE IF NOT EXISTS maintenance (
                    id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
                    starts_at REAL NOT NULL, ends_at REAL NOT NULL, node_ids TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1, cancelled_at REAL
                );
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

    def maintenance_list(self, now=None):
        now = time.time() if now is None else now
        with self.lock, self.connect() as db:
            records = [dict(row) for row in db.execute("SELECT * FROM maintenance ORDER BY starts_at DESC LIMIT 300")]
        for record in records:
            record["node_ids"] = json.loads(record["node_ids"])
            record["status"] = maintenance_state(record, now)
        return records

    def save_maintenance(self, value, now=None):
        import math
        now = time.time() if now is None else now
        title, description, node_ids = value.get("title"), value.get("description", ""), value.get("node_ids")
        start, end = value.get("starts_at"), value.get("ends_at")
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 100:
            raise ValueError("Укажи название работ длиной до 100 символов.")
        if not isinstance(description, str) or len(description) > 2000:
            raise ValueError("Описание — до 2000 символов.")
        if any(ord(c) < 32 for c in title) or any(ord(c) < 32 and c not in "\n\t\r" for c in description):
            raise ValueError("В тексте есть недопустимые символы.")
        if any(type(t) not in (int, float) or not math.isfinite(t) for t in (start, end)) or end <= start:
            raise ValueError("Окончание должно быть позже начала.")
        if end - start > 30 * 86400 or start < now - 90 * 86400 or end > now + 730 * 86400:
            raise ValueError("Проверь даты: длительность работ — до 30 дней.")
        if not isinstance(node_ids, list) or len(node_ids) > 200 or any(not isinstance(n, str) for n in node_ids):
            raise ValueError("Выбери серверы для работ.")
        node_ids = sorted(set(node_ids))
        if value.get("id") is not None and (type(value["id"]) is not int or type(value.get("version")) is not int):
            raise ValueError("Проверь выбранную запись.")
        with self.lock, self.connect() as db:
            known = {r[0] for r in db.execute("SELECT id FROM nodes WHERE active=1")}
            if any(node_id not in known for node_id in node_ids):
                raise ValueError("Один из выбранных серверов больше не доступен в списке.")
            if value.get("id") is None:
                cursor = db.execute("""INSERT INTO maintenance(title,description,starts_at,ends_at,node_ids,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?)""", (title.strip(), description.strip(), start, end, json.dumps(node_ids), now, now))
                return cursor.lastrowid
            record = db.execute("SELECT * FROM maintenance WHERE id=?", (value["id"],)).fetchone()
            if not record or record["cancelled_at"] is not None:
                raise ValueError("Работы не найдены или уже отменены.")
            if value.get("version") != record["version"]:
                raise ValueError("Запись уже изменилась. Обнови список и повтори редактирование.")
            db.execute("""UPDATE maintenance SET title=?,description=?,starts_at=?,ends_at=?,node_ids=?,updated_at=?,
                version=version+1 WHERE id=?""", (title.strip(), description.strip(), start, end, json.dumps(node_ids), now, record["id"]))
            return record["id"]

    def cancel_maintenance(self, record_id, version, now=None):
        now = time.time() if now is None else now
        with self.lock, self.connect() as db:
            row = db.execute("SELECT * FROM maintenance WHERE id=?", (record_id,)).fetchone()
            if not row or row["version"] != version or row["cancelled_at"] is not None:
                raise ValueError("Запись изменилась. Обнови список.")
            if row["starts_at"] <= now:
                raise ValueError("Начавшиеся работы нельзя отменить. Их можно завершить досрочно.")
            db.execute("UPDATE maintenance SET cancelled_at=?,updated_at=?,version=version+1 WHERE id=?", (now, now, record_id))

    def finish_maintenance(self, record_id, version, now=None):
        now = time.time() if now is None else now
        with self.lock, self.connect() as db:
            row = db.execute("SELECT * FROM maintenance WHERE id=?", (record_id,)).fetchone()
            if not row or row["version"] != version or row["cancelled_at"] is not None:
                raise ValueError("Запись изменилась. Обнови список.")
            if not row["starts_at"] <= now < row["ends_at"]:
                raise ValueError("Досрочно завершить можно только текущие работы.")
            db.execute("UPDATE maintenance SET ends_at=?,updated_at=?,version=version+1 WHERE id=?", (now, now, record_id))

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
            plans = []
            for record in self.maintenance_list(now):
                if record["status"] == "cancelled" or record["ends_at"] <= start:
                    continue
                affected = [node_id for node_id in names if not record["node_ids"] or node_id in record["node_ids"]]
                if affected:
                    plans.append({k: record[k] for k in ("id", "title", "description", "starts_at", "ends_at", "status", "node_ids")})
                    plans[-1].update({"names": [names[node_id] for node_id in affected], "all_servers": not record["node_ids"]})
            plans.sort(key=lambda p: ({"active": 0, "scheduled": 1, "completed": 2}[p["status"]], -p["ends_at"] if p["status"] == "completed" else p["starts_at"]))
            latest = float(self.meta("last_cycle") or 0)
            fresh = latest > 0 and now - latest <= MAX_GAP
            output = []
            for node in rows:
                node_plans = [p for p in plans if not p["node_ids"] or node["id"] in p["node_ids"]]
                planned_intervals = [(p["starts_at"], p["ends_at"]) for p in node_plans]
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
                                    "degraded_seconds": round(amounts["degraded"]),
                                    "maintenance_seconds": round(overlap_seconds(planned_intervals, a, b))})
                measured = sum(totals.values())
                current = node["state"] if fresh and node["last_ts"] and now - node["last_ts"] <= MAX_GAP else "unknown"
                stable_since = None
                if current == "up":
                    stable_since = node["last_ts"]
                    previous = db.execute("SELECT start,end,state FROM spans WHERE node_id=? ORDER BY id DESC LIMIT 1", (node["id"],)).fetchone()
                    if previous and previous["state"] == "up" and abs(previous["end"] - node["last_ts"]) < .01:
                        stable_since = previous["start"]
                last = db.execute("SELECT start,end,kind FROM incidents WHERE node_id=? ORDER BY start DESC LIMIT 1", (node["id"],)).fetchone()
                node_incidents = [dict(r) for r in db.execute("SELECT start,end,kind FROM incidents WHERE node_id=? AND (end IS NULL OR end>?) ORDER BY start DESC LIMIT 30", (node["id"], start))]
                count = db.execute("SELECT count(*) FROM incidents WHERE node_id=? AND (end IS NULL OR end>?)", (node["id"], start)).fetchone()[0]
                if any(p["status"] == "active" for p in node_plans):
                    current = "maintenance"
                output.append({"id": node["id"], "name": names[node["id"]],
                               "country": node["agent_country"] or node["country"], "state": current,
                               "since": node["created"], "last_check": node["last_ts"],
                               "uptime": round(totals["up"] / measured * 100, 3) if measured else None,
                               "measured_seconds": round(measured), "history": history,
                               "outage_seconds": round(totals["down"]), "degraded_seconds": round(totals["degraded"]),
                               "stable_since": stable_since, "last_incident": dict(last) if last else None,
                               "incident_count": count, "incidents": node_incidents,
                               "maintenance": [p["id"] for p in node_plans]})
            incidents = [{"id": r["id"], "name": names[r["node_id"]], "start": r["start"], "end": r["end"], "kind": r["kind"]}
                         for r in db.execute("""SELECT i.id,i.node_id,i.start,i.end,i.kind FROM incidents i
                JOIN nodes n ON n.id=i.node_id WHERE n.active=1 AND (i.end IS NULL OR i.end>?) ORDER BY i.start DESC LIMIT 40""", (start,))]
        states = [n["state"] for n in output]
        overall = "unknown" if not states or not fresh else ("down" if all(s == "down" for s in states) else
                   "degraded" if any(s in ("down", "degraded") for s in states) else "maintenance" if "maintenance" in states else "unknown" if "unknown" in states else "up")
        return {"state": overall, "days": days if hours is None else None, "hours": hours,
                "period_start": start, "bucket_seconds": step, "updated_at": latest or None, "generated_at": now,
                "interval_seconds": INTERVAL, "timezone": "Europe/Moscow", "nodes": output, "incidents": incidents,
                "maintenance": plans}


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


class AdminAuth:
    def __init__(self, config=None):
        self.config = config
        self.sessions = {}
        self.attempts = {}
        self.lock = threading.Lock()

    def login(self, password, source, now=None):
        now = time.time() if now is None else now
        with self.lock:
            self.attempts = {key: [t for t in times if now - t < 60] for key, times in self.attempts.items() if times and now - times[-1] < 60}
            attempts = self.attempts.setdefault(source, [])
            if len(attempts) >= 5:
                return "limited", None
            attempts.append(now)
        try:
            config = self.config or json.loads(Path(os.environ.get("STATUS_ADMIN_FILE", "/run/secrets/status-admin.json")).read_text())
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(config["salt"]), int(config["iterations"])).hex()
        except (OSError, ValueError, KeyError):
            return "unavailable", None
        if not hmac.compare_digest(digest, config["hash"]):
            return "invalid", None
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            self.attempts.pop(source, None)
            self.sessions = {key: session for key, session in self.sessions.items() if session["expires"] > now}
            self.sessions[token] = {"csrf": csrf, "expires": now + 43200}
        return "ok", token

    def session(self, cookie, now=None):
        now = time.time() if now is None else now
        try:
            parsed = SimpleCookie(cookie)
            token = parsed["status_admin"].value
        except Exception:
            return None, None
        with self.lock:
            session = self.sessions.get(token)
            if session and session["expires"] > now:
                return token, dict(session)
            self.sessions.pop(token, None)
        return None, None

    def logout(self, token):
        with self.lock:
            self.sessions.pop(token, None)


class Service:
    def __init__(self, store):
        self.store = store
        self.inventory = []
        self.inventory_at = 0
        self.lock = threading.Lock()
        self.rates = {}
        self.stop = threading.Event()
        self.auth = AdminAuth()

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

        def send(self, status, data, content_type="application/json; charset=utf-8", headers=None):
            raw = json.dumps(data, ensure_ascii=False).encode() if isinstance(data, dict) else data
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store" if content_type.startswith("application/json") or self.path.startswith("/admin") else "public, max-age=60")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            from urllib.parse import urlsplit, parse_qs
            parsed = urlsplit(self.path)
            if parsed.path == "/api/admin/state":
                _, session = service.auth.session(self.headers.get("Cookie", ""))
                if not session:
                    return self.send(401, {"error": "Войди в управление работами."})
                public = service.store.public(hours=3)
                return self.send(200, {"csrf": session["csrf"], "nodes": [{"id": n["id"], "name": n["name"]} for n in public["nodes"]],
                                       "maintenance": service.store.maintenance_list()})
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
            assets.update({"/admin": ("admin.html", "text/html; charset=utf-8"), "/admin/": ("admin.html", "text/html; charset=utf-8"),
                           "/admin.js": ("admin.js", "application/javascript; charset=utf-8")})
            if parsed.path in assets:
                filename, mime = assets[parsed.path]
                return self.send(200, (ROOT / "static" / filename).read_bytes(), mime)
            return self.send(404, {"error": "Not found"})

        def do_POST(self):
            if self.path.startswith("/api/admin/"):
                return self.admin_post()
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

        def admin_post(self):
            origin = self.headers.get("Origin")
            if origin and origin != "https://status.meltun.org":
                return self.send(403, {"error": "Недопустимый источник запроса."})
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                return self.send(415, {"error": "Ожидается JSON."})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 12000:
                    raise ValueError()
                value = json.loads(self.rfile.read(length))
                if not isinstance(value, dict):
                    raise ValueError()
            except (ValueError, TypeError):
                return self.send(400, {"error": "Не удалось прочитать запрос."})
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
            if self.path == "/api/admin/login":
                password = value.get("password", "")
                if not isinstance(password, str) or len(password) > 256:
                    return self.send(400, {"error": "Проверь пароль."})
                source = normalized_ip(self.headers.get("X-Real-IP", self.client_address[0]))
                result, token = service.auth.login(password, source)
                if result != "ok":
                    code, message = {"limited": (429, "Слишком много попыток. Подожди минуту."),
                                     "invalid": (401, "Неверный пароль."),
                                     "unavailable": (503, "Вход пока не настроен.")}[result]
                    return self.send(code, {"error": message})
                return self.send(200, {"ok": True}, headers={"Set-Cookie": "status_admin=" + token + "; Path=/api/admin; HttpOnly; SameSite=Strict; Max-Age=43200" + secure})
            token, session = service.auth.session(self.headers.get("Cookie", ""))
            if not session:
                return self.send(401, {"error": "Сессия закончилась. Войди заново."})
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", "").encode(), session["csrf"].encode()):
                return self.send(403, {"error": "Обнови страницу и повтори действие."})
            try:
                if self.path == "/api/admin/maintenance":
                    record_id = service.store.save_maintenance(value)
                    return self.send(200, {"ok": True, "id": record_id})
                if self.path in ("/api/admin/cancel", "/api/admin/finish"):
                    if type(value.get("id")) is not int or type(value.get("version")) is not int:
                        raise ValueError("Проверь выбранную запись.")
                    action = service.store.finish_maintenance if self.path.endswith("/finish") else service.store.cancel_maintenance
                    action(value["id"], value["version"])
                    return self.send(200, {"ok": True})
                if self.path == "/api/admin/logout":
                    service.auth.logout(token)
                    return self.send(200, {"ok": True}, headers={"Set-Cookie": "status_admin=; Path=/api/admin; HttpOnly; SameSite=Strict; Max-Age=0" + secure})
            except ValueError as error:
                return self.send(400, {"error": str(error)})
            return self.send(404, {"error": "Not found"})
    return Handler


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    store = Store(os.environ.get("STATUS_DB", "/data/status.sqlite3"))
    service = Service(store)
    threading.Thread(target=service.collect, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), handler_class(service))
    server.daemon_threads = True
    server.serve_forever()
