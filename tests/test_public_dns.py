import ast
import io
import ipaddress
import json
import pathlib
import urllib.parse
import urllib.request
import unittest
from unittest.mock import patch


def load(*names, **extra):
    installer = pathlib.Path(__file__).resolve().parents[1] / "install-remnanode-manager.sh"
    source = installer.read_text(encoding="utf-8").split("cat > /opt/remnanode-manager/app.py <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    tree = ast.parse(source)
    nodes = [node for node in tree.body if (isinstance(node, ast.FunctionDef) and node.name in names)
             or (isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "PUBLIC_DOH" for t in node.targets))]
    scope = {"ipaddress": ipaddress, "json": json, "urllib": urllib, **extra}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "app.py", "exec"), scope)
    return scope


class Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class PublicDnsTests(unittest.TestCase):
    def scope(self):
        return load("normalize_ip", "resolve_public_addresses")

    def test_reads_a_and_aaaa_from_doh(self):
        def fake(request, timeout):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
            if query["type"] == ["A"]:
                return Reply(json.dumps({"Answer": [{"type": 5, "data": "alias.example."}, {"type": 1, "data": "185.130.112.222"}]}).encode())
            return Reply(json.dumps({"Answer": [{"type": 28, "data": "2001:db8::1"}]}).encode())
        with patch("urllib.request.urlopen", side_effect=fake):
            self.assertEqual(self.scope()["resolve_public_addresses"]("node.example.org"), ["185.130.112.222", "2001:db8::1"])

    def test_falls_back_to_second_provider(self):
        calls = []

        def fake(request, timeout):
            calls.append(request.full_url)
            if "cloudflare" in request.full_url:
                raise OSError("blocked")
            return Reply(json.dumps({"Answer": [{"type": 1, "data": "203.0.113.5"}]}).encode())
        with patch("urllib.request.urlopen", side_effect=fake):
            self.assertEqual(self.scope()["resolve_public_addresses"]("node.example.org"), ["203.0.113.5"])
        self.assertTrue(any("dns.google" in url for url in calls))

    def test_unreachable_doh_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=OSError("offline")):
            self.assertEqual(self.scope()["resolve_public_addresses"]("node.example.org"), [])


if __name__ == "__main__":
    unittest.main()
