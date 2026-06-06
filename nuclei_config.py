"""Shared config helpers for Ninjas KEV console."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_NUCLEI_DIR = "DB-Exploits/nuclei-templates-main"


def load_config(root: Path, config_file: str = "config.json") -> Dict[str, Any]:
    cfg: Dict[str, Any] = {"nuclei_templates_dir": DEFAULT_NUCLEI_DIR}
    path = root / config_file
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def nuclei_templates_path(config: Dict[str, Any], root: Path) -> Path:
    raw = (config.get("nuclei_templates_dir") or DEFAULT_NUCLEI_DIR).strip()
    p = Path(raw)
    if not p.is_absolute():
        p = root / p
    return p.resolve()
