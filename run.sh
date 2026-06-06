#!/usr/bin/env bash
# Ninjas KEV console — run inside tmux session "kev"
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
if [[ ! -d "$VENV" ]]; then
    echo "Virtual env not found. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi

PORT="$(python3 -c "import json; print(json.load(open('config.json')).get('server_port',8009))" 2>/dev/null || echo 8009)"
echo "============================================"
echo " Ninjas KEV — open in browser:"
for ip in $(hostname -I 2>/dev/null); do
  echo "   http://${ip}:${PORT}/"
done
echo "   http://127.0.0.1:${PORT}/  (local)"
echo " Login: ninjas / ninjas"
echo "============================================"

exec "$VENV/bin/python" app.py
