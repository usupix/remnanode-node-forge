import ast
import pathlib
import unittest


def load_nginx_config():
    installer = pathlib.Path(__file__).resolve().parents[1] / "install-remnanode-manager.sh"
    source = installer.read_text(encoding="utf-8").split("cat > /opt/remnanode-manager/app.py <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ("nginx_http_config", "nginx_tls_config")]
    scope = {"BASE_PATH": "/secret-manager"}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "app.py", "exec"), scope)
    return scope["nginx_tls_config"]


class ManagerHttpsTests(unittest.TestCase):
    def test_public_tls_site_proxies_secret_path(self):
        config = load_nginx_config()("de.example.org", True)
        self.assertIn("listen 443 ssl;", config)
        self.assertIn("location ^~ /secret-manager/", config)
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", config)
        self.assertIn("listen 127.0.0.1:8443 ssl;", config)

    def test_reality_fallback_keeps_internal_tls_listener(self):
        config = load_nginx_config()("de.example.org", False)
        self.assertNotIn("listen 443 ssl;", config)
        self.assertIn("listen 127.0.0.1:8443 ssl;", config)
        self.assertIn("location ^~ /secret-manager/", config)


if __name__ == "__main__":
    unittest.main()
