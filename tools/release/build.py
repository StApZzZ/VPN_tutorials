#!/usr/bin/env python3
"""Build a deterministic source archive and CycloneDX dependency inventory."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
if out == root or root in out.parents:
    parser.error("artifact directory must be outside the checkout")
if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root).strip():
    raise SystemExit("Release artifacts require a clean committed checkout")
out.mkdir(parents=True, exist_ok=True)
subprocess.run(["python3", str(root / "tools/release/check_tree.py")], check=True)
sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
version = (root / "VERSION").read_text().strip()
epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=root))
archive = subprocess.check_output(["git", "archive", "--format=tar", "--prefix=corpvpn-" + version + "/", "HEAD"], cwd=root)
with (out / ("corpvpn-" + version + ".tar.gz")).open("wb") as target:
    with gzip.GzipFile(filename="", fileobj=target, mode="wb", mtime=epoch) as stream:
        stream.write(archive)
components = []
lock = (root / "panel/requirements.lock").read_text()
for match in re.finditer(r"^([A-Za-z0-9_.-]+)==([^ ;\\\n]+)([^\n]*)\n((?:[ \t]+.*\n)*)", lock, re.M):
    name, value, marker, block = match.groups()
    components.append({"type": "library", "name": name, "version": value,
                       "purl": "pkg:pypi/" + name.lower().replace("_", "-") + "@" + value,
                       "hashes": [{"alg": "SHA-256", "content": digest} for digest in re.findall(r"sha256:([a-f0-9]{64})", block)],
                       "properties": [{"name": "corpvpn:environment-marker", "value": marker.replace("\\", "").strip()}]})
# No dependency on a YAML parser in the release job: scalar pins are unambiguous.
pins = {}
for line in (root / "deploy/versions.yml").read_text().splitlines():
    if line.startswith("corpvpn_") and ": " in line:
        key, value = line.split(": ", 1);pins[key] = value.strip('"')
for name, version_key, commit_key, license_id in [
        ("xray-core", "corpvpn_xray_version", "corpvpn_xray_commit", "MPL-2.0"),
        ("amneziawg-go", "corpvpn_amneziawg_go_version", "corpvpn_amneziawg_go_commit", "MIT"),
        ("amneziawg-tools", "corpvpn_amneziawg_tools_version", "corpvpn_amneziawg_tools_commit", "GPL-2.0-only"),
        ("go", "corpvpn_go_version", "", "BSD-3-Clause"),
        ("go", "corpvpn_xray_go_version", "", "BSD-3-Clause")]:
    component = {"type": "application", "name": name, "version": pins[version_key], "licenses": [{"license": {"id": license_id}}]}
    if commit_key:component["properties"] = [{"name": "corpvpn:git-commit", "value": pins[commit_key]}]
    if name == "xray-core":
        component["version"] += "-" + pins["corpvpn_xray_build_revision"]
        component["properties"].extend([
            {"name": "corpvpn:go-mod-sha256", "value": hashlib.sha256((root / "deploy/ansible/roles/xray/files/xray-go.mod").read_bytes()).hexdigest()},
            {"name": "corpvpn:go-sum-sha256", "value": hashlib.sha256((root / "deploy/ansible/roles/xray/files/xray-go.sum").read_bytes()).hexdigest()}])
    components.append(component)
for module in json.loads((root / "tools/release/native-modules.json").read_text())["modules"]:
    components.append({"type": "library", "name": module["name"], "version": module["version"],
                       "purl": "pkg:golang/" + module["name"] + "@" + module["version"],
                       "properties": [{"name": "corpvpn:go-module-checksum", "value": module["go_sum"]},
                                      {"name": "corpvpn:native-products", "value": ",".join(module["products"])}]})
sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "name": "CorpVPN", "version": version},
                     "properties": [{"name": "corpvpn:source-commit", "value": sha},
                                    {"name": "corpvpn:source-tree", "value": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root).decode().strip()},
                                    {"name": "corpvpn:inventory-scope", "value": "Python lock union across supported Python versions, pinned native sources and their embedded Go modules; distribution packages are managed by the host OS"}]},
        "components": components}
(out / "corpvpn-sbom.cdx.json").write_text(json.dumps(sbom, indent=2) + "\n")
report = root / "docs/RELEASE-TESTS.md"
if not report.exists():raise SystemExit("Release test report is required")
(out / "RELEASE-TESTS.md").write_bytes(report.read_bytes())
(out / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in sorted(out.iterdir()) if p.name != "SHA256SUMS" and p.is_file()))
print("Release artifacts prepared for source commit " + sha)
