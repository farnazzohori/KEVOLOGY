#!/usr/bin/env python3
"""Map KEV catalog CVEs (KEV.json) to local Nuclei YAML templates.

Outputs:
  cve-nuclei-map.json   — full mapping for the UI / reporting
  nuclei-linked/        — one subfolder per CVE with symlinks to templates
  cve-nuclei-report.html — operator-readable has / missing summary
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from nuclei_config import load_config as load_project_config, nuclei_templates_path

ROOT = Path(__file__).resolve().parent
KEV_JSON = ROOT / "KEV.json"
OUT_JSON = ROOT / "cve-nuclei-map.json"
OUT_LINK_DIR = ROOT / "nuclei-linked"
OUT_HTML = ROOT / "cve-nuclei-report.html"

NUCLEI_ROOT = ROOT / "DB-Exploits" / "nuclei-templates-main"  # overridden in main()

CVE_IN_NAME = re.compile(r"(CVE-\d{4}-\d+)", re.I)
URL_RE = re.compile(r"https?://[^\s;\"'<>]+", re.I)
GITHUB_RE = re.compile(r"https?://github\.com/[^\s\"'<>]+", re.I)
NUCLEI_GH_BASE = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
POC_URL_HINT = re.compile(
    r"vulhub|exploit-?db|metasploit|packetstorm|"
    r"/poc[/\-_]|poc[/\-_]|/exploits?/|proof.?of.?concept|"
    r"github\.com/.+/(blob|tree)/.+(poc|exploit)",
    re.I,
)
_yaml_cache: dict[str, dict] = {}


def load_kev_cves() -> list[dict]:
    data = json.loads(KEV_JSON.read_text(encoding="utf-8"))
    return data.get("vulnerabilities") or []


def index_nuclei_by_cve() -> dict[str, list[str]]:
    """Every CVE-*.yaml under nuclei-templates-main, keyed by CVE id."""
    by_cve: dict[str, list[str]] = defaultdict(list)
    if not NUCLEI_ROOT.is_dir():
        return by_cve
    for path in NUCLEI_ROOT.rglob("CVE-*.yaml"):
        m = CVE_IN_NAME.search(path.name)
        if not m:
            continue
        cve = m.group(1).upper()
        rel = path.relative_to(ROOT).as_posix()
        by_cve[cve].append(rel)
    for cve in by_cve:
        by_cve[cve].sort()
    return dict(by_cve)


def grep_kev_yaml_files() -> list[str]:
    """grep -RIl KEV|kev under the configured templates directory."""
    if not NUCLEI_ROOT.is_dir():
        return []
    try:
        out = subprocess.run(
            [
                "grep", "-RIl",
                "--include=*.yml", "--include=*.yaml",
                r"KEV\|kev", str(NUCLEI_ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except Exception:
        return []
    lines = [ln.strip() for ln in (out.stdout or "").splitlines() if ln.strip()]
    rels = []
    for ln in lines:
        p = Path(ln)
        try:
            rels.append(p.relative_to(ROOT).as_posix())
        except ValueError:
            rels.append(ln)
    return rels


def cve_from_kev_tagged_yaml(rel_path: str) -> str | None:
    m = CVE_IN_NAME.search(Path(rel_path).name)
    return m.group(1).upper() if m else None


def _clean_url(url: str) -> str:
    return url.rstrip(".,);]")


def urls_from_notes(notes: str) -> list[str]:
    if not notes:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in URL_RE.finditer(notes):
        u = _clean_url(m.group(0))
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def nuclei_github_url(rel_template: str) -> str | None:
    prefix = "DB-Exploits/nuclei-templates-main/"
    if not rel_template.startswith(prefix):
        return None
    sub = rel_template[len(prefix) :]
    return NUCLEI_GH_BASE + sub


def is_poc_url(url: str) -> bool:
    return bool(POC_URL_HINT.search(url))


def parse_nuclei_yaml(rel_path: str) -> dict:
    if rel_path in _yaml_cache:
        return _yaml_cache[rel_path]
    empty = {
        "references": [],
        "github": [],
        "poc": [],
        "other": [],
        "nuclei_github": None,
    }
    path = ROOT / rel_path
    if not path.is_file():
        _yaml_cache[rel_path] = empty
        return empty
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        _yaml_cache[rel_path] = empty
        return empty

    refs: list[str] = []
    in_ref = False
    for line in text.splitlines():
        if line.strip() == "reference:" or line.strip().startswith("reference:"):
            in_ref = True
            continue
        if in_ref:
            stripped = line.strip()
            if stripped.startswith("- "):
                refs.append(_clean_url(stripped[2:].strip().strip("'\"")))
            elif line and not line[0].isspace():
                in_ref = False

    github: list[str] = []
    poc: list[str] = []
    other: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if not ref or ref in seen:
            continue
        seen.add(ref)
        if "github.com" in ref.lower():
            github.append(ref)
            if is_poc_url(ref):
                poc.append(ref)
        else:
            other.append(ref)
            if is_poc_url(ref):
                poc.append(ref)

    data = {
        "references": refs,
        "github": github,
        "poc": poc,
        "other": other,
        "nuclei_github": nuclei_github_url(rel_path),
    }
    _yaml_cache[rel_path] = data
    return data


def merge_links_for_cve(
    templates: list[str],
    notes: str,
) -> dict:
    """Collect GitHub / POC / Nuclei-upstream links for one CVE row."""
    nuclei_gh: list[str] = []
    github: list[str] = []
    poc: list[str] = []
    other: list[str] = []
    seen_gh: set[str] = set()
    seen_poc: set[str] = set()
    seen_other: set[str] = set()
    seen_nuclei: set[str] = set()

    for rel in templates:
        meta = parse_nuclei_yaml(rel)
        ng = meta.get("nuclei_github")
        if ng and ng not in seen_nuclei:
            seen_nuclei.add(ng)
            nuclei_gh.append(ng)
        for u in meta.get("github") or []:
            if u not in seen_gh:
                seen_gh.add(u)
                github.append(u)
        for u in meta.get("poc") or []:
            if u not in seen_poc:
                seen_poc.add(u)
                poc.append(u)
        for u in meta.get("other") or []:
            if u not in seen_other:
                seen_other.add(u)
                other.append(u)

    for u in urls_from_notes(notes):
        if "github.com" in u.lower():
            if u not in seen_gh:
                seen_gh.add(u)
                github.append(u)
        elif u not in seen_other:
            seen_other.add(u)
            other.append(u)
        if is_poc_url(u) and u not in seen_poc:
            seen_poc.add(u)
            poc.append(u)

    return {
        "nuclei_github": nuclei_gh,
        "github": github,
        "poc": poc,
        "other": other,
        "has_poc": bool(poc),
    }


def build_map() -> dict:
    vulns = load_kev_cves()
    by_cve = index_nuclei_by_cve()
    kev_tagged = grep_kev_yaml_files()
    kev_tagged_set = set(kev_tagged)

    rows = []
    has_tpl = 0
    kev_flag_only = 0
    with_poc = 0

    for v in vulns:
        cve = (v.get("cveID") or "").strip().upper()
        templates = by_cve.get(cve, [])
        # Templates that mention KEV in yaml AND match this CVE filename
        kev_marked = [t for t in templates if t in kev_tagged_set]
        # Any KEV-tagged yaml whose filename is this CVE (even if not in by_cve yet)
        extra_kev = [
            t for t in kev_tagged
            if cve_from_kev_tagged_yaml(t) == cve and t not in templates
        ]
        all_templates = sorted(set(templates + extra_kev))

        has = bool(all_templates)
        if has:
            has_tpl += 1
        if not has and any(cve_from_kev_tagged_yaml(t) == cve for t in kev_tagged):
            kev_flag_only += 1

        links = merge_links_for_cve(all_templates, v.get("notes") or "")
        if links["has_poc"]:
            with_poc += 1

        rows.append({
            "cveID": cve,
            "vendor": v.get("vendorProject") or "",
            "product": v.get("product") or "",
            "dateAdded": v.get("dateAdded") or "",
            "has_nuclei_template": has,
            "template_count": len(all_templates),
            "templates": all_templates,
            "kev_tagged_in_yaml": kev_marked or extra_kev,
            "links": links,
        })

    rows.sort(key=lambda r: (not r["has_nuclei_template"], r["cveID"]))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kev_catalog_count": len(rows),
        "with_nuclei_template": has_tpl,
        "without_nuclei_template": len(rows) - has_tpl,
        "nuclei_cve_files_indexed": sum(len(v) for v in by_cve.values()),
        "grep_kev_yaml_count": len(kev_tagged),
        "with_poc_link": with_poc,
        "rows": rows,
    }


def write_symlinks(data: dict) -> None:
    if OUT_LINK_DIR.exists():
        for child in OUT_LINK_DIR.iterdir():
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                import shutil
                shutil.rmtree(child)
    OUT_LINK_DIR.mkdir(parents=True, exist_ok=True)

    for row in data["rows"]:
        if not row["templates"]:
            continue
        cve = row["cveID"]
        cdir = OUT_LINK_DIR / cve
        cdir.mkdir(exist_ok=True)
        for i, rel in enumerate(row["templates"]):
            src = ROOT / rel
            if not src.is_file():
                continue
            dest_name = Path(rel).name
            if i > 0 and dest_name in {Path(t).name for t in row["templates"][:i]}:
                dest_name = f"{i}_{dest_name}"
            dest = cdir / dest_name
            if dest.exists():
                dest.unlink()
            dest.symlink_to(os.path.relpath(src, cdir))


def write_html(data: dict) -> None:
    rows = data["rows"]
    with_tpl = [r for r in rows if r["has_nuclei_template"]]
    without = [r for r in rows if not r["has_nuclei_template"]]

    def links_html(r: dict) -> str:
        lk = r.get("links") or {}
        parts: list[str] = []
        for u in (lk.get("nuclei_github") or [])[:2]:
            short = u.split("github.com/")[-1][:48]
            parts.append(
                f'<a href="{u}" target="_blank" rel="noopener" title="{u}">'
                f'nucl:{short}</a>'
            )
        for u in (lk.get("poc") or [])[:3]:
            short = u.split("github.com/")[-1] if "github.com" in u else u[:40]
            parts.append(
                f'<a class="poc" href="{u}" target="_blank" rel="noopener" '
                f'title="{u}">poc:{short[:40]}</a>'
            )
        for u in (lk.get("github") or [])[:2]:
            if u in (lk.get("poc") or []):
                continue
            short = u.split("github.com/")[-1][:40]
            parts.append(f'<a href="{u}" target="_blank">gh:{short}</a>')
        return "<br>".join(parts) if parts else "—"

    def row_html(r, ok: bool) -> str:
        tpls = r["templates"]
        lk = links_html(r)
        if ok:
            links = "<br>".join(
                f'<code class="tpl">{t}</code>' for t in tpls[:5]
            )
            if len(tpls) > 5:
                links += f"<br><span class='muted'>+{len(tpls)-5} more</span>"
            badge = f'<span class="yes">YES ({len(tpls)})</span>'
            folder = f'nuclei-linked/{r["cveID"]}/'
        else:
            links = "—"
            badge = '<span class="no">NO</span>'
            folder = "—"
        return f"""<tr>
          <td><code>{r['cveID']}</code></td>
          <td>{r['vendor']}</td>
          <td>{r['product']}</td>
          <td>{r['dateAdded']}</td>
          <td>{badge}</td>
          <td class="tpls">{links}</td>
          <td class="tpls">{lk}</td>
          <td>{folder}</td>
        </tr>"""

    body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>KEV ↔ Nuclei template map</title>
<style>
  body {{ font-family: ui-monospace, monospace; background:#050913; color:#cffafe; padding:20px; }}
  h1 {{ color:#22d3ee; }}
  .stats {{ display:flex; gap:20px; margin:16px 0; flex-wrap:wrap; }}
  .stat {{ background:rgba(2,6,23,.8); border:1px solid #1e293b; padding:12px 18px; border-radius:8px; }}
  .stat b {{ font-size:22px; color:#4ade80; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; margin-top:20px; }}
  th, td {{ border:1px solid #334155; padding:8px; text-align:left; vertical-align:top; }}
  th {{ background:#0f172a; color:#67e8f9; }}
  tr:hover {{ background:rgba(34,211,238,.06); }}
  .yes {{ color:#4ade80; font-weight:bold; }}
  .no {{ color:#f87171; font-weight:bold; }}
  .tpl {{ color:#a5f3fc; font-size:10px; word-break:break-all; }}
  .muted {{ color:#64748b; }}
  a.poc {{ color:#fbbf24; }}
  h2 {{ color:#fbbf24; margin-top:28px; }}
</style></head><body>
<h1>KEV catalog ↔ Nuclei templates</h1>
<p>Generated: {data['generated_at']}</p>
<div class="stats">
  <div class="stat">KEV CVEs<br><b>{data['kev_catalog_count']}</b></div>
  <div class="stat">With template<br><b style="color:#4ade80">{data['with_nuclei_template']}</b></div>
  <div class="stat">Missing template<br><b style="color:#f87171">{data['without_nuclei_template']}</b></div>
  <div class="stat">grep KEV|kev yamls<br><b>{data['grep_kev_yaml_count']}</b></div>
  <div class="stat">With POC link<br><b style="color:#fbbf24">{data.get('with_poc_link', 0)}</b></div>
</div>
<h2>With Nuclei template ({len(with_tpl)})</h2>
<table><thead><tr><th>CVE</th><th>Vendor</th><th>Product</th><th>Added</th><th>Template</th><th>YAML path(s)</th><th>GitHub / POC</th><th>Linked folder</th></tr></thead>
<tbody>{''.join(row_html(r, True) for r in with_tpl)}</tbody></table>
<h2>Missing Nuclei template ({len(without)})</h2>
<table><thead><tr><th>CVE</th><th>Vendor</th><th>Product</th><th>Added</th><th>Template</th><th>YAML path(s)</th><th>GitHub / POC</th><th>Linked folder</th></tr></thead>
<tbody>{''.join(row_html(r, False) for r in without)}</tbody></table>
</body></html>"""

    OUT_HTML.write_text(body, encoding="utf-8")


def main():
    global NUCLEI_ROOT
    cfg = load_project_config(ROOT)
    NUCLEI_ROOT = nuclei_templates_path(cfg, ROOT)
    NUCLEI_ROOT.mkdir(parents=True, exist_ok=True)
    print(f"[*] Templates directory: {NUCLEI_ROOT}")
    print("[*] Building CVE ↔ Nuclei map …")
    data = build_map()
    OUT_JSON.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"    wrote {OUT_JSON}")
    write_symlinks(data)
    print(f"    symlinks under {OUT_LINK_DIR}/")
    write_html(data)
    print(f"    wrote {OUT_HTML}")
    print(
        f"[*] {data['with_nuclei_template']}/{data['kev_catalog_count']} KEV entries "
        f"have at least one CVE-*.yaml template"
    )


if __name__ == "__main__":
    main()
