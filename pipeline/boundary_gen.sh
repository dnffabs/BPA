#!/usr/bin/env bash
# Run all prerequisites through boundary_gen; usage: boundary_gen.sh <ELF> <output-dir>
set -euo pipefail
source "$(dirname "$0")/common.sh"
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <ELF> <output-dir>" >&2
    exit 2
fi
exec "$PYTHON" "$ROOT_DIR/tools/run_pipeline.py" "$1" --output "$2" --stage boundary_gen
