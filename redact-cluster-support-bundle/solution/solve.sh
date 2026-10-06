#!/usr/bin/env bash
set -euo pipefail

# Oracle solution for redact-cluster-support-bundle.
# The fixed service and its smoke check live beside this script.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -m 0755 "$here/intake_server.py" /app/sluice/intake_server.py
python3 "$here/smoke_check.py"

echo "oracle complete"
