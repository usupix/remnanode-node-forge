import ast
import io
import json
import pathlib
import re
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch


def load_pairing():
    installer = pathlib.Path(__file__).resolve().parents[1] / "install-remnanode-manager.sh"
    source = installer.read_text(encoding="utf-8").split("cat > /opt/remnanode-manager/app.py <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    functions = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name in ("redeem_pair_code", "configure_access_forwarder")]
    scope = {"re": re, "json": json, "urllib": urllib}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "app.py", "exec"), scope)
    return scope


class PairingTests(unittest.TestCase):
    def test_pair_code_is_exchanged_over_https(self):
        scope = load_pairing()
        class Reply(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *_args): self.close()
        with patch("urllib.request.urlopen", return_value=Reply(json.dumps({"token": "t" * 64}).encode())) as urlopen:
            self.assertEqual(scope["redeem_pair_code"]("GERMANY", "a" * 32), "t" * 64)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://meltun.org/api/admin/node-logs/pair")
        self.assertEqual(json.loads(request.data), {"node_id": "GERMANY", "code": "a" * 32})

    def test_pairing_stores_only_working_token(self):
        scope = load_pairing()
        saved = {}
        scope.update({
            "ACCESS_FORWARDER_CONFIG": "/tmp/unused",
            "atomic_write": lambda _path, data, mode: saved.update(data=json.loads(data), mode=mode),
            "run": lambda _args: None,
            "redeem_pair_code": lambda _node_id, _code: "t" * 64,
        })
        scope["configure_access_forwarder"]({
            "endpoint": ["https://meltun.org/api/admin/node-logs/ingest"],
            "node_id": ["GERMANY"], "pair_code": ["a" * 32],
        })
        self.assertEqual(saved["data"]["token"], "t" * 64)
        self.assertNotIn("pair_code", saved["data"])
        self.assertEqual(saved["mode"], 0o600)

    def test_pairing_shows_specific_id_error(self):
        scope = load_pairing()
        response = io.BytesIO(json.dumps({"detail": "Для указанного ID ноды нет активного кода."}).encode())
        error = urllib.error.HTTPError("https://meltun.org/api/admin/node-logs/pair", 404, "Not Found", {}, response)
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(ValueError, "ID ноды нет активного кода"):
                scope["redeem_pair_code"]("GERMANY", "a" * 32)


if __name__ == "__main__":
    unittest.main()
