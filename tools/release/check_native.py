#!/usr/bin/env python3
"""Verify that production Go binaries contain the reviewed module inventory."""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--go", required=True)
parser.add_argument("--xray", required=True)
parser.add_argument("--awg", default="/usr/local/bin/amneziawg-go")
args = parser.parse_args()
expected = json.loads((Path(__file__).with_name("native-modules.json")).read_text())["modules"]
actual = {}
for product, binary in (("xray-core", args.xray), ("amneziawg-go", args.awg)):
    output = subprocess.check_output([args.go, "version", "-m", binary], text=True)
    for line in output.splitlines():
        if line.startswith("\tdep\t"):
            _, _, name, version, checksum = line.split("\t")
            entry = actual.setdefault((name, version), {"name": name, "version": version,
                                                       "go_sum": checksum, "products": []})
            entry["products"].append(product)
if sorted(actual.values(), key=lambda m: (m["name"], m["version"])) != expected:
    raise SystemExit("Native module inventory differs from the reviewed release lock")
print(f"Verified {len(expected)} embedded native modules")
