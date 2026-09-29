import pathlib
import unittest


def load_forwarder():
    installer = pathlib.Path(__file__).resolve().parents[1] / "install-remnanode-manager.sh"
    source = installer.read_text(encoding="utf-8")
    source = source.split("cat > /opt/remnanode-manager/access_forwarder.py <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    scope = {"__name__": "test_forwarder"}
    exec(compile(source, "access_forwarder.py", "exec"), scope)
    return scope


class AccessForwarderTests(unittest.TestCase):
    def test_ipv4_with_panel_username_and_route(self):
        parse = load_forwarder()["parse_line"]
        line = "2026/09/29 10:23:11.340278 from 198.51.100.4:46365 accepted tcp:example.org:443 [VLESS >> direct] email: tg_42_1"
        event = parse(line, 7, 100)
        self.assertEqual(event["source_ip"], "198.51.100.4")
        self.assertEqual(event["destination"], "example.org:443")
        self.assertEqual(event["route"], "VLESS >> direct")
        self.assertEqual(event["panel_username"], "tg_42_1")
        self.assertEqual(event["network"], "tcp")

    def test_ipv6_and_deterministic_event_id(self):
        parse = load_forwarder()["parse_line"]
        line = "2026/09/29 10:23:11 from [2001:db8::1]:54321 accepted udp:1.1.1.1:53 [HY >> direct] email: tg_7_1"
        event = parse(line, 8, 20)
        self.assertEqual(event["source_ip"], "2001:db8::1")
        self.assertEqual(event["event_id"], parse(line, 8, 20)["event_id"])
        self.assertNotEqual(event["event_id"], parse(line, 8, 21)["event_id"])

    def test_log_timezone_is_converted_to_utc(self):
        parse = load_forwarder()["parse_line"]
        line = "2026/09/29 10:23:11 from 198.51.100.4:1234 accepted tcp:example.org:443 [VLESS >> direct] email: tg_42_1"
        event = parse(line, 7, 100, "Europe/Moscow")
        self.assertEqual(event["occurred_at"], "2026-09-29T07:23:11+00:00")

    def test_ignores_unattributed_line(self):
        parse = load_forwarder()["parse_line"]
        self.assertIsNone(parse("2026/09/29 10:23:11 from 198.51.100.4:1 accepted tcp:example.org:443", 1, 1))


if __name__ == "__main__":
    unittest.main()
