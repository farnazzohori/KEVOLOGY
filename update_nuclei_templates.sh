#!/usr/bin/env bash
# Re-index locally installed Nuclei templates (no automatic download).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="$(python3 -c "
from pathlib import Path
from nuclei_config import load_config, nuclei_templates_path
r = Path('${ROOT}')
print(nuclei_templates_path(load_config(r), r))
")"

mkdir -p "$DEST"

count="$(find "$DEST" -name 'CVE-*.yaml' 2>/dev/null | wc -l | tr -d ' ')"
echo "[*] Local Nuclei templates: ${count} CVE-*.yaml file(s)"
echo "[*] Directory (from config.json): ${DEST}"

if [[ "$count" == "0" ]]; then
  echo "[!] No templates found. See NUCLEI_TEMPLATES.md in the project root."
fi

echo "[*] Rebuild cve-nuclei-map.json + nuclei-linked/ …"
cd "$ROOT"
python3 build_cve_nuclei_map.py

echo "[*] Done."
