#!/usr/bin/env bash
# 旧文件名兼容入口；主实现见 stage1-newport.sh。
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec /bin/bash "$SCRIPT_DIR/stage1-newport.sh" "$@"
