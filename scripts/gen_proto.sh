#!/bin/bash
# Regenerate zerotruss/ext_mcp_pb2.py from proto/ext_mcp.proto.
# Only needed if the proto file changes; the generated file is committed.
# Uses .venv/bin/python unless PYTHON is set (the pipeline sets it).
set -euo pipefail
cd "$(dirname "$0")/.."

"${PYTHON:-.venv/bin/python}" -m grpc_tools.protoc -I proto --python_out=zerotruss proto/ext_mcp.proto
echo "generated zerotruss/ext_mcp_pb2.py"
