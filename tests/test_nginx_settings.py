"""Exercise production TLS assertions through the installed Ansible controller."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(importlib.util.find_spec("ansible"), "requires deployment dependencies")
class NginxSettings(unittest.TestCase):
    def test_supported_tls_modes_and_missing_certificate(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        task = yaml.safe_load((root / "deploy/ansible/roles/nginx/tasks/main.yml").read_text())[0]
        common = {"vpn_panel_nginx_enabled": True, "vpn_panel_enabled_protocols": ["vless"],
                  "vpn_panel_tls_mode": "selfsigned", "vpn_panel_ssl_cert_path": "/tmp/fullchain.pem",
                  "vpn_panel_ssl_key_path": "/tmp/privkey.pem", "vpn_panel_certbot_email": "ops@example.com",
                  "nginx_server_name": "vpn.example.com", "vpn_panel_trusted_proxy_cidrs": ["127.0.0.1/32"],
                  "vpn_panel_public_url": "https://vpn.example.com"}
        for overrides, success in [({}, True), ({"vpn_panel_tls_mode": "letsencrypt"}, True),
                                   ({"vpn_panel_tls_mode": "none"}, True),
                                   ({"vpn_panel_ssl_key_path": ""}, False)]:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "settings.yml"
                path.write_text(yaml.safe_dump([{"hosts": "all", "gather_facts": False,
                                                "vars": {**common, **overrides}, "tasks": [task]}]))
                result = subprocess.run([sys.executable, "-m", "ansible.cli.playbook", "-i", "localhost,",
                                         "-c", "local", str(path)], stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True,
                                        env={**os.environ, "ANSIBLE_HOME": temporary + "/ansible-home",
                                             "ANSIBLE_LOCAL_TEMP": temporary + "/controller",
                                             "ANSIBLE_REMOTE_TEMP": temporary + "/remote"})
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
