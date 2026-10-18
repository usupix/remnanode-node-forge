import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("status_app", ROOT / "app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def inventory():
    return [{"uuid": "panel-node", "name": "FINLAND", "countryCode": "FI", "viewPosition": 1,
             "address": "198.51.100.20", "port": 12345, "isConnected": True}]


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = app.Store(Path(self.temp.name) / "status.db")
        self.now = 1792324800.0
        self.store.sync(inventory(), self.now)
        self.store.meta("last_cycle", self.now)

    def test_no_invented_history(self):
        result = self.store.public(90, self.now)
        node = result["nodes"][0]
        self.assertIsNone(node["uptime"])
        self.assertTrue(all(day["uptime"] is None for day in node["history"]))

    def test_real_time_and_unknown_gaps(self):
        self.store.observe("panel-node", "up", 4, self.now)
        self.store.observe("panel-node", "up", 4, self.now + 600)
        self.store.meta("last_cycle", self.now + 600)
        node = self.store.public(7, self.now + 660)["nodes"][0]
        self.assertEqual(node["measured_seconds"], app.MAX_GAP + 60)
        self.assertEqual(node["uptime"], 100)

    def test_debounce_and_incident_resolution(self):
        for offset, state in [(0, "up"), (60, "down"), (120, "down"), (180, "up")]:
            self.store.observe("panel-node", state, None, self.now + offset)
        self.store.meta("last_cycle", self.now + 180)
        result = self.store.public(7, self.now + 180)
        self.assertEqual(result["nodes"][0]["uptime"], 33.333)
        self.assertEqual(result["incidents"][0]["start"], self.now + 60)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["end"], self.now + 180)

    def test_stale_monitor_is_unknown(self):
        self.store.observe("panel-node", "up", 4, self.now)
        self.assertEqual(self.store.public(7, self.now + 151)["state"], "unknown")

    def test_hourly_windows_have_real_buckets(self):
        for hours, count, size in ((3, 36, 300), (6, 72, 300), (12, 72, 600)):
            result = self.store.public(hours=hours, now=self.now)
            self.assertEqual(len(result["nodes"][0]["history"]), count)
            self.assertEqual(result["period_start"], self.now - hours * 3600)
            self.assertEqual(result["bucket_seconds"], size)
            self.assertEqual(result["nodes"][0]["history"][-1]["end"], self.now)

    def test_hourly_uptime_clips_spans_to_window(self):
        with self.store.connect() as db:
            self.store._span(db, "panel-node", self.now - 8 * 3600, self.now - 3600, "up")
            self.store._span(db, "panel-node", self.now - 3600, self.now, "down")
        node = self.store.public(hours=3, now=self.now)["nodes"][0]
        self.assertEqual(node["measured_seconds"], 3 * 3600)
        self.assertEqual(node["uptime"], 66.667)
        self.assertEqual(node["history"][-1]["outage_seconds"], 300)
        self.assertEqual(node["history"][0]["uptime"], 100)

    def test_country_names_and_duplicates_only(self):
        nodes = inventory() + [{**inventory()[0], "uuid": "ee-1", "countryCode": "EE", "name": "ES-NODA", "viewPosition": 2},
                               {**inventory()[0], "uuid": "ee-2", "countryCode": "EE", "name": "EE-GAME-NODA", "viewPosition": 3}]
        self.store.sync(nodes, self.now)
        result = self.store.public(hours=3, now=self.now)
        self.assertEqual([node["name"] for node in result["nodes"]], ["Финляндия", "Эстония", "Эстония #2"])
        self.assertNotIn("latency_ms", result["nodes"][0])

    def test_http_hours_and_rejected_periods(self):
        from http.server import HTTPServer
        import threading
        import urllib.request
        import urllib.error
        server = HTTPServer(("127.0.0.1", 0), app.handler_class(app.Service(self.store)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:" + str(server.server_port)
        try:
            with urllib.request.urlopen(base + "/api/status?hours=3") as response:
                self.assertEqual(json.load(response)["hours"], 3)
            for query in ("hours=5", "hours=3&days=7", "hours="):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(base + "/api/status?" + query)
                self.assertEqual(caught.exception.code, 400)
                caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_public_has_no_private_inventory(self):
        text = json.dumps(self.store.public(7, self.now))
        for value in ("198.51.100.20", "cert_hash", "agent_ip", "token", "12345"):
            self.assertNotIn(value, text)

    def test_signed_agent_dedup_and_adoption(self):
        payload = {"agent_id": "a" * 32, "nonce": "b" * 32, "core_running": True,
                   "name": "New server", "country": "DE"}
        self.assertTrue(self.store.heartbeat(None, payload, "certificate", "203.0.113.25", self.now))
        self.assertFalse(self.store.heartbeat(None, payload, "certificate", "203.0.113.25", self.now))
        self.store.sync(inventory(), self.now + 60)
        self.assertEqual(len(self.store.public(7, self.now)["nodes"]), 2)
        new = {**inventory()[0], "uuid": "new-panel-node", "address": "203.0.113.25", "name": "GERMANY-DARAFOREST"}
        self.store.sync(inventory() + [new], self.now + 60)
        self.assertEqual(new["status_id"], "agent:" + "a" * 32)
        self.assertEqual(len(self.store.public(7, self.now)["nodes"]), 2)

    def test_certificate_binding_cannot_be_replaced(self):
        payload = {"agent_id": "a" * 32, "nonce": "b" * 32, "core_running": True, "name": "N", "country": ""}
        self.assertTrue(self.store.heartbeat("panel-node", payload, "first", "198.51.100.20", self.now))
        self.assertFalse(self.store.heartbeat(None, {**payload, "nonce": "c" * 32}, "other", "203.0.113.26", self.now))
        self.assertTrue(self.store.heartbeat("panel-node", {**payload, "nonce": "d" * 32}, "other", "198.51.100.20", self.now))


class ProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.path = Path(cls.temp.name)
        def run(*args):
            subprocess.run(["openssl", *args], cwd=cls.path, capture_output=True, check=True)
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=TestPanel", "-days", "1", "-keyout", "ca.key", "-out", "ca.pem")
        run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=TestNode", "-keyout", "node.key", "-out", "node.csr")
        run("x509", "-req", "-in", "node.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-out", "node.pem")
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=OtherPanel", "-days", "1", "-keyout", "other.key", "-out", "other.pem")
        source = (ROOT.parent / "install-remnanode-manager.sh").read_text(encoding="utf-8")
        agent = source.split("cat > /opt/remnanode-manager/status_agent.py <<'STATUS_AGENT'\n", 1)[1].split("\nSTATUS_AGENT\n", 1)[0]
        cls.agent = {"__name__": "agent_test"}
        exec(compile(agent, "status_agent.py", "exec"), cls.agent)
        secret = base64.b64encode(json.dumps({"nodeCertPem": (cls.path / "node.pem").read_text(),
                     "nodeKeyPem": (cls.path / "node.key").read_text()}).encode()).decode()
        cls.config = {"secret_key": secret, "agent_id": "a" * 32, "name": "Test node", "country": "DE"}

    def test_proof_is_accepted_and_private_key_never_sent(self):
        proof = self.agent["proof"](self.config, True)
        self.assertTrue(app.verify_proof(proof["payload"], proof["certificate"], proof["signature"], self.path / "ca.pem"))
        self.assertNotIn("PRIVATE KEY", json.dumps(proof))
        self.assertNotIn(self.config["secret_key"], json.dumps(proof))

    def test_wrong_ca_and_tampered_payload_rejected(self):
        proof = self.agent["proof"](self.config, True)
        self.assertIsNone(app.verify_proof(proof["payload"], proof["certificate"], proof["signature"], self.path / "other.pem"))
        proof["payload"]["core_running"] = False
        self.assertIsNone(app.verify_proof(proof["payload"], proof["certificate"], proof["signature"], self.path / "ca.pem"))

    def test_mismatched_private_key_rejected(self):
        secret = base64.b64encode(json.dumps({"nodeCertPem": (self.path / "node.pem").read_text(),
                     "nodeKeyPem": (self.path / "other.key").read_text()}).encode()).decode()
        with self.assertRaises(ValueError):
            self.agent["proof"]({**self.config, "secret_key": secret}, True)

    def test_docker_top_includes_required_pid_column(self):
        from unittest.mock import patch
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "PID COMMAND\n42 rw-core\n", "")) as run:
            self.assertTrue(self.agent["core_running"]())
        self.assertEqual(run.call_args.args[0][-1], "pid,comm")


if __name__ == "__main__":
    unittest.main()
