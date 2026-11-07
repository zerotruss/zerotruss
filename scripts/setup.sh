#!/bin/bash
# Create the virtual environment and install the locked dependencies.
#   --require-hashes   every package must match a hash in the lock files
#   --only-binary      prebuilt wheels only, so no package runs build scripts on this machine
set -euo pipefail
cd "$(dirname "$0")/.."

python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: \
    -r requirements.txt -r requirements-dev.txt
echo "setup done: $(.venv/bin/python --version)"
