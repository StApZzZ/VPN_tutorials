"""Guards between the panel source and the Ansible deploy that ships it.

Previous implementation broke production twice by shipping a subset of modules (the service then
dies with ModuleNotFoundError on a clean host), and once by rendering an env key
that nothing reads. These checks keep site.yml, env.j2 and config.py in step.
"""

import re
import yaml
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "panel"
SITE = ROOT / "deploy" / "ansible" / "site.yml"
ENV_J2 = ROOT / "deploy" / "ansible" / "roles" / "app" / "templates" / "env.j2"


def _site_list(name: str) -> list[str]:
    defaults = ROOT / "deploy/ansible/roles/preflight/defaults/main.yml"
    return yaml.safe_load(defaults.read_text())[name]


class DeployManifestTests(unittest.TestCase):
    def test_every_panel_module_is_shipped(self):
        shipped = set(_site_list("vpn_panel_app_source_files"))
        modules = {p.name for p in SRC.glob("*.py")}
        self.assertEqual(sorted(modules - shipped), [], "modules missing from site.yml")
        self.assertEqual(sorted((shipped - {"requirements.txt"}) - modules), [], "site.yml lists absent files")
        self.assertIn("requirements.txt", shipped)

    def test_every_shipped_dir_exists(self):
        for name in _site_list("vpn_panel_app_source_dirs"):
            self.assertTrue((SRC / name).is_dir(), name)

    def test_env_keys_are_read_by_config(self):
        env_keys = set(re.findall(r"^([A-Z][A-Z0-9_]+)=", ENV_J2.read_text(encoding="utf-8"), re.M))
        config_src = (SRC / "config.py").read_text(encoding="utf-8")
        read = set(re.findall(r'os\.getenv\(\s*"([A-Z0-9_]+)"', config_src))
        read |= set(re.findall(r'_flag\(\s*"([A-Z0-9_]+)"', config_src))
        read |= set(re.findall(r'_env_first\(\s*"([A-Z0-9_]+)"', config_src))
        self.assertEqual(sorted(env_keys - read), [], "env.j2 renders keys config.py never reads")


if __name__ == "__main__":
    unittest.main()
