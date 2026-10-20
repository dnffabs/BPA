#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${BPA_PYTHON:-}" ]]; then
    PYTHON="$BPA_PYTHON"
elif command -v uv >/dev/null 2>&1; then
    # Resolve through uv so .python-version and uv.lock apply to direct runs too.
    PYTHON="$(uv run --locked --project "$ROOT_DIR" python -c 'import sys; print(sys.executable)')"
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON="$ROOT_DIR/.venv/bin/python"
else
    echo "Python environment not found. Install uv and run: uv sync --locked" >&2
    exit 1
fi
export PYTHONDONTWRITEBYTECODE=1
