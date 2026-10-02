"""Real systemd regression for production template-service/timer stop tasks."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.environ.get("CORPVPN_SYSTEMD_TEST") == "1", "requires disposable root/systemd runner")
class SystemdUnitStops(unittest.TestCase):
    def test_instantiated_services_and_timers_stop_before_mutation(self):
        import yaml
        self.assertEqual(os.geteuid(), 0)
        prefix = "corpvpn-unit-regression-" + str(os.getpid())
        names = [prefix + "@alpha.service", prefix + ".timer"]
        directory = Path("/etc/systemd/system")
        files = {prefix + "@.service": "[Service]\nExecStart=/bin/sleep infinity\n",
                 prefix + "-job.service": "[Service]\nType=oneshot\nExecStart=/bin/true\n",
                 prefix + ".timer": "[Timer]\nOnActiveSec=1h\nUnit=" + prefix + "-job.service\n"}
        root = Path(__file__).resolve().parents[1]

        def systemctl(*args, check=True):
            return subprocess.run(["systemctl", *args], check=check, capture_output=True, text=True)

        try:
            for name, content in files.items():
                self.assertFalse((directory / name).exists())
                (directory / name).write_text(content)
            systemctl("daemon-reload")
            for playbook, stop_name in (("uninstall.yml", "Stop only CorpVPN units"),
                                        ("restore.yml", "Stop gateway writers and tunnels")):
                systemctl("start", *names)
                for name in names:
                    self.assertEqual(systemctl("is-active", name).stdout.strip(), "active")
                units = systemctl("list-unit-files", "--type=service", "--type=timer", "--no-legend").stdout
                self.assertIn(prefix + "@.service", units)
                self.assertNotIn(names[0], units)
                tasks = yaml.safe_load((root / "deploy/ansible" / playbook).read_text())[0]["tasks"]
                discovery = next(t for t in tasks if t["name"] == "Installed service and timer units")
                flat = tasks + [t for block in tasks for t in block.get("block", [])]
                stop = copy.deepcopy(next(t for t in flat if t["name"] == stop_name))
                stop["loop"] = names
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "stop.yml"
                    path.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False,
                                                    "tasks": [discovery, stop]}]))
                    result = subprocess.run([sys.executable, "-m", "ansible.cli.playbook", "-i", "localhost,",
                                             "-c", "local", str(path)], stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name in names:
                    self.assertNotEqual(systemctl("is-active", name, check=False).returncode, 0, playbook + ": " + name)
        finally:
            systemctl("stop", *names, check=False)
            for name in files:
                (directory / name).unlink(missing_ok=True)
            systemctl("daemon-reload")
            systemctl("reset-failed", *names, check=False)
