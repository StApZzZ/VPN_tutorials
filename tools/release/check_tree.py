#!/usr/bin/env python3
"""Check distributable paths and executable metadata without private search lists."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root).decode().split("\0")
errors = []
for name in filter(None, paths):
    p = root / name
    if not p.is_file():
        continue
    if re.search(r"(?:^|/)(?:\.env|quickstart\.env|terraform\.tfstate(?:\..*)?|hosts\.yml|all\.secrets\.yml|id_(?:rsa|ed25519)|[^/]*\.pem|[^/]*\.key)$", name):
        errors.append(name + ": private runtime file")
    if p.suffix in {".sh", ".py"} or p.name.startswith("corpvpn-"):
        data = p.read_bytes()
        if data.startswith(b"#!") and not p.stat().st_mode & 0o111:
            errors.append(name + ": shebang without executable bit")
    if p.stat().st_size < 2_000_000:
        data = p.read_bytes()
        if re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", data):
            errors.append(name + ": private key material")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("Distributable paths and executable bits passed")
