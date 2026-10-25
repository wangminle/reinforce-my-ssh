#!/usr/bin/env bash
# stage0-audit.sh — 独立只读审计；不部署、不接管、不写阶段状态。
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/audit.py" "$@"
