import ast
import pathlib
import re
import subprocess
import unittest

INSTALLER = pathlib.Path(__file__).resolve().parents[1] / "install-remnanode-manager.sh"


def installer_text():
    return INSTALLER.read_text(encoding="utf-8")


def heredoc_after(marker):
    text = installer_text()
    body = text.split(marker, 1)[1]
    return body.split("\nSYSCTL\n", 1)[0]


def parse_sysctl(body):
    values = {}
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def panel_values_all_enabled():
    """Run the panel's apply_network() with every switch on and capture what it writes."""
    source = installer_text().split("cat > /opt/remnanode-manager/app.py <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    functions = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "apply_network"]
    written = {}
    scope = {
        "SYSCTL_BBR": "bbr", "SYSCTL_TUNE": "tune",
        "backup": lambda *_a: "backup",
        "network_baseline": lambda: {},
        "run": lambda *_a, **_k: "",
        "atomic_write": lambda path, data, _mode: written.__setitem__(path, data),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), "app.py", "exec"), scope)
    scope["apply_network"]({name: ["1"] for name in ("bbr", "fastopen", "mtu", "buffers", "backlog")})
    return parse_sysctl(written["tune"])


class NetworkDefaultsTests(unittest.TestCase):
    def test_installer_matches_panel_switches(self):
        installed = parse_sysctl(heredoc_after("cat > /etc/sysctl.d/99-remnanode-manager-network.conf <<'SYSCTL'\n"))
        self.assertEqual(installed, panel_values_all_enabled())

    def test_extra_settings_are_vpn_friendly(self):
        extra = parse_sysctl(heredoc_after("cat > /etc/sysctl.d/98-remnanode-extra-network.conf <<'SYSCTL'\n"))
        self.assertEqual(extra["net.ipv4.tcp_slow_start_after_idle"], "0")
        self.assertEqual(extra["net.ipv4.tcp_keepalive_time"], "600")
        self.assertNotIn("net.ipv4.tcp_congestion_control", extra)

    def test_baseline_is_saved_before_tuning(self):
        text = installer_text()
        function = text.split("tune_network() {", 1)[1].split("\n}\ntune_network\n", 1)[0]
        self.assertLess(function.index("network-baseline.json"), function.index("99-remnanode-manager-network.conf"))
        self.assertIn("RNM_SKIP_NETWORK_TUNING", function)
        self.assertIn("network-tuned", function)

    def test_installer_is_valid_bash(self):
        result = subprocess.run(["bash", "-n", str(INSTALLER)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
