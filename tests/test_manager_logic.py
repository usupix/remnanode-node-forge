import ast
import pathlib
import re
import secrets
import threading
import time
import unittest


def load(*names, **extra):
    installer = pathlib.Path(__file__).resolve().parents[1] / "install-remnanode-manager.sh"
    source = installer.read_text(encoding="utf-8").split("cat > /opt/remnanode-manager/app.py <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    functions = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name in names]
    scope = {"re": re, "secrets": secrets, "threading": threading, "time": time, **extra}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "app.py", "exec"), scope)
    return scope


PRIVATE = "aEVmS9cBo4mI8kz3Wq1pY7tN2rX5uL0dF6gH4jK8mQ0"
PUBLIC = "Zx3qO9vV1nH7mTq2pR4sK8yL6cB0aD5eF1gH3jK7mN0"


class X25519Tests(unittest.TestCase):
    def test_legacy_output(self):
        parse = load("parse_x25519")["parse_x25519"]
        self.assertEqual(parse(f"Private key: {PRIVATE}\nPublic key: {PUBLIC}\n"), (PRIVATE, PUBLIC))

    def test_new_output_uses_password_as_public_key(self):
        parse = load("parse_x25519")["parse_x25519"]
        output = f"PrivateKey: {PRIVATE}\nPassword: {PUBLIC}\nHash32: Ab0cD1eF2gH3iJ4kL5mN6oP7qR8sT9uV0wX1yZ2aB3c\n"
        self.assertEqual(parse(output), (PRIVATE, PUBLIC))

    def test_garbage_is_rejected(self):
        parse = load("parse_x25519")["parse_x25519"]
        with self.assertRaises(RuntimeError):
            parse("Error: container is not running")


class PublicHttpsTests(unittest.TestCase):
    def site(self, public):
        scope = load("nginx_http_config", "nginx_manager_location", "nginx_tls_config", BASE_PATH="/secret")
        return scope["nginx_tls_config"]("de.example.org", public)

    def test_disable_and_enable_round_trip(self):
        toggle = load("set_public_https")["set_public_https"]
        public = self.site(True)
        private = toggle(public, False)
        self.assertNotIn("listen 443 ssl;", private)
        self.assertIn("listen 127.0.0.1:8443 ssl;", private)
        self.assertEqual(toggle(private, True), public)
        self.assertEqual(toggle(public, True), public)
        self.assertEqual(private, self.site(False))

    def test_foreign_site_is_refused(self):
        toggle = load("set_public_https")["set_public_https"]
        with self.assertRaises(RuntimeError):
            toggle("server { listen 443 ssl; }", False)


class PortOwnerTests(unittest.TestCase):
    def test_parses_ss_users(self):
        parse = load("parse_port_owners")["parse_port_owners"]
        output = (
            'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=8),("nginx",pid=811,fd=8))\n'
            'LISTEN 0 4096 [::]:443 [::]:* users:(("xray",pid=1201,fd=12))\n'
        )
        self.assertEqual(parse(output), {"nginx", "xray"})
        self.assertEqual(parse(""), set())


class SessionTests(unittest.TestCase):
    def scope(self):
        return load(
            "create_session", "get_session", "drop_session",
            "login_allowed", "record_login_failure", "reset_login_failures",
            sessions={}, sessions_guard=threading.Lock(), SESSION_TTL=60,
            attempts={}, attempts_guard=threading.Lock(), LOGIN_LIMIT=5,
        )

    def test_sessions_are_unique_and_revocable(self):
        scope = self.scope()
        first, second = scope["create_session"](), scope["create_session"]()
        self.assertNotEqual(first, second)
        self.assertNotEqual(scope["get_session"](first)["csrf"], scope["get_session"](second)["csrf"])
        scope["drop_session"](first)
        self.assertIsNone(scope["get_session"](first))
        self.assertIsNotNone(scope["get_session"](second))
        self.assertIsNone(scope["get_session"]("forged"))

    def test_expired_session_is_rejected(self):
        scope = self.scope()
        token = scope["create_session"]()
        scope["sessions"][token]["expires"] = time.time() - 1
        self.assertIsNone(scope["get_session"](token))

    def test_login_limit_is_per_client(self):
        scope = self.scope()
        for _ in range(5):
            scope["record_login_failure"]("198.51.100.1")
        self.assertFalse(scope["login_allowed"]("198.51.100.1"))
        self.assertTrue(scope["login_allowed"]("198.51.100.2"))
        self.assertTrue(scope["login_allowed"]("198.51.100.1", now=time.time() + 61))


if __name__ == "__main__":
    unittest.main()
