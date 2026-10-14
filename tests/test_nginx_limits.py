import pathlib
import shutil
import subprocess
import tempfile
import unittest

INSTALLER = pathlib.Path(__file__).resolve().parents[1] / "install-remnanode-manager.sh"
DEBIAN_DEFAULT = """user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
\tworker_connections 768;
\t# multi_accept on;
}
"""


def function_source():
    text = INSTALLER.read_text(encoding="utf-8")
    return "raise_nginx_limits_in() {" + text.split("raise_nginx_limits_in() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"


@unittest.skipIf(shutil.which("bash") is None, "bash is required")
class NginxLimitsTests(unittest.TestCase):
    def run_on(self, content, times=1):
        with tempfile.TemporaryDirectory() as tmp:
            conf = pathlib.Path(tmp) / "nginx.conf"
            conf.write_text(content, encoding="utf-8", newline="\n")
            script = function_source() + "".join(f'raise_nginx_limits_in "{conf.as_posix()}"\n' for _ in range(times))
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return conf.read_text(encoding="utf-8")

    def test_raises_debian_default(self):
        out = self.run_on(DEBIAN_DEFAULT)
        self.assertIn("\tworker_connections 16384;", out)
        self.assertIn("worker_processes auto;\nworker_rlimit_nofile 65535;", out)

    def test_idempotent(self):
        once = self.run_on(DEBIAN_DEFAULT)
        self.assertEqual(self.run_on(once), once)
        self.assertEqual(once.count("worker_rlimit_nofile"), 1)

    def test_keeps_higher_custom_value(self):
        out = self.run_on(DEBIAN_DEFAULT.replace("768", "40000"))
        self.assertIn("worker_connections 40000;", out)


if __name__ == "__main__":
    unittest.main()
