#!/usr/bin/env bash
# Usage: ./pipeline/run.sh <ELF> [--output DIR] [--compare] [--entry main]
set -euo pipefail
source "$(dirname "$0")/common.sh"
exec "$PYTHON" "$ROOT_DIR/tools/run_pipeline.py" "$@"
