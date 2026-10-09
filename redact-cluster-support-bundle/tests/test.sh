#!/usr/bin/env bash
# Verifier entrypoint.
#
# Deliberately no `set -e`: a non-zero pytest exit is an expected outcome and
# the reward file must still be written.
set -uo pipefail

mkdir -p /logs/verifier

if [ "$PWD" = "/" ]; then
    echo "Error: no working directory set. Set a WORKDIR in tests/Dockerfile." >&2
    echo 0 > /logs/verifier/reward.txt
    exit 0
fi

# pytest and pytest-json-ctrf are pre-installed in the verifier image, in a
# root-only directory that only this process is pointed at.
PYTHONPATH=/opt/verifier PYTHONDONTWRITEBYTECODE=1 \
    python -m pytest -p no:cacheprovider --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
rc=$?

if [ "$rc" -eq 0 ]; then
    echo 1 > /logs/verifier/reward.txt
else
    echo 0 > /logs/verifier/reward.txt
fi

exit 0
