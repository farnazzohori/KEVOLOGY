#!/usr/bin/env bash
# Git bundle — run from this folder
set -euo pipefail
cd "$(dirname "$0")"
echo "[Git] ui_variant=git — starting from $(pwd)"
if [[ ! -d .venv ]]; then
  python3 -m venv --system-site-packages .venv 2>/dev/null || python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt 2>/dev/null || true
fi
exec ./run.sh
