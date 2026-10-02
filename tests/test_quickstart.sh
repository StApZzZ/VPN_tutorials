#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$ROOT/deploy/quickstart.sh" "$ROOT/deploy/run.sh"
exec python3 "$ROOT/tests/test_quickstart.py"
