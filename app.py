#!/usr/bin/env python3
"""
Ninjas KEV Console — auto-sync (KEV + Nuclei + CVE map) and HTTP server.
"""

import os
import sys
import json
import time
import signal
import logging
import argparse
import threading
import hashlib
import hmac
import base64
import subprocess
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Optional, Set

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("Installing required package: requests")
    os.system(f"{sys.executable} -m pip install requests")
    import requests

ROOT = Path(__file__).resolve().parent

from nuclei_config import load_config as _load_cfg, nuclei_templates_path

CONFIG: Dict[str, Any] = {
    "kev_url": "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json",
    "kev_file": "KEV.json",
    "server_port": 8001,
    "update_interval": 86400,
    "daily_update_hour": 3,
    "nuclei_templates_dir": "DB-Exploits/nuclei-templates-main",
    "ui_variant": "git",
    "auth": {
        "username": "ninjas",
        "password": "ninjas",
        "secret": "ninjas-kev-console-change-me",
    },
    "proxy": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 8080,
        "username": "",
        "password": "",
    },
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(ROOT / "kev_updater.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

REVIEWS_FILE = "reviews.json"
UPDATE_STATUS_FILE = "update_status.json"
_STATUS_LOCK = threading.Lock()
_REVIEWS_LOCK = threading.Lock()
_SYNC_RUNNING = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("load %s failed: %s", path, e)
        return default


def _save_json_atomic(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def next_sync_iso(config: Dict[str, Any]) -> str:
    from datetime import timedelta
    hour = int(config.get("daily_update_hour", 3))
    now = datetime.now()
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target.strftime("%Y-%m-%dT%H:%M:%S")


def load_update_status() -> Dict[str, Any]:
    return _load_json(ROOT / UPDATE_STATUS_FILE, {
        "last_run_at": None,
        "last_run_ok": False,
        "summary": "No sync yet.",
        "components": {},
    })


def save_update_status(status: Dict[str, Any]) -> None:
    with _STATUS_LOCK:
        _save_json_atomic(ROOT / UPDATE_STATUS_FILE, status)


# ---------------------------------------------------------------------------
# Auth (HMAC token, 7-day TTL)
# ---------------------------------------------------------------------------

def _auth_cfg(config: Dict[str, Any]) -> Dict[str, str]:
    return config.get("auth") or {}


def make_token(username: str, secret: str, ttl_sec: int = 7 * 86400) -> str:
    exp = int(time.time()) + ttl_sec
    payload = f"{username}:{exp}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_token(token: str, secret: str) -> Optional[str]:
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, exp_s, sig = raw.rsplit(":", 2)
        payload = f"{username}:{exp_s}"
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp_s) < time.time():
            return None
        return username
    except Exception:
        return None


def check_credentials(username: str, password: str, config: Dict[str, Any]) -> bool:
    auth = _auth_cfg(config)
    return (
        username == auth.get("username")
        and password == auth.get("password")
    )


# ---------------------------------------------------------------------------
# Sync engine — KEV.json + Nuclei templates + CVE↔Nuclei map
# ---------------------------------------------------------------------------

class SyncEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def get_proxy_dict(self):
        proxy = self.config.get("proxy") or {}
        if not proxy.get("enabled"):
            return None
        host, port = proxy.get("host"), proxy.get("port")
        user, pw = proxy.get("username") or "", proxy.get("password") or ""
        if user and pw:
            url = f"http://{user}:{pw}@{host}:{port}"
        else:
            url = f"http://{host}:{port}"
        return {"http": url, "https": url}

    @staticmethod
    def _kev_cve_ids(path: Path) -> Set[str]:
        if not path.exists():
            return set()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {
                (v.get("cveID") or "").upper()
                for v in (data.get("vulnerabilities") or [])
                if v.get("cveID")
            }
        except Exception:
            return set()

    @staticmethod
    def _nuclei_root(config: Dict[str, Any]) -> Path:
        return nuclei_templates_path(config, ROOT)

    @staticmethod
    def _count_nuclei_cve_yamls(config: Dict[str, Any]) -> int:
        root = SyncEngine._nuclei_root(config)
        if not root.is_dir():
            return 0
        return sum(1 for _ in root.rglob("CVE-*.yaml"))

    @staticmethod
    def _map_stats() -> Dict[str, int]:
        p = ROOT / "cve-nuclei-map.json"
        if not p.exists():
            return {"with_template": 0, "with_poc": 0, "kev_total": 0}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return {
                "with_template": int(data.get("with_nuclei_template") or 0),
                "with_poc": int(data.get("with_poc_link") or 0),
                "kev_total": int(data.get("kev_catalog_count") or 0),
            }
        except Exception:
            return {"with_template": 0, "with_poc": 0, "kev_total": 0}

    def download_kev(self) -> Dict[str, Any]:
        kev_path = ROOT / self.config["kev_file"]
        before = self._kev_cve_ids(kev_path)
        result = {"ok": False, "added": 0, "total": len(before), "message": ""}

        try:
            logger.info("Downloading KEV from %s", self.config["kev_url"])
            proxies = self.get_proxy_dict()
            resp = requests.get(
                self.config["kev_url"],
                proxies=proxies,
                timeout=60,
                verify=False,
            )
            resp.raise_for_status()
            data = resp.json()

            if kev_path.exists():
                kev_path.rename(kev_path.with_suffix(".json.bak"))

            with open(kev_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            after = self._kev_cve_ids(kev_path)
            added = len(after - before)
            result.update({
                "ok": True,
                "added": added,
                "total": len(after),
                "message": f"catalog v{data.get('catalogVersion', '?')} — {len(after)} CVEs",
            })
            logger.info("KEV sync OK — +%s new, total %s", added, len(after))
        except Exception as e:
            result["message"] = str(e)
            logger.error("KEV sync failed: %s", e)
        return result

    def update_nuclei_templates(self) -> Dict[str, Any]:
        before = self._count_nuclei_cve_yamls(self.config)
        dest = self._nuclei_root(self.config)
        dest.mkdir(parents=True, exist_ok=True)

        after = self._count_nuclei_cve_yamls(self.config)
        if after == 0:
            logger.info("No local Nuclei templates — upload required (%s)", dest)
            return {
                "ok": True,
                "added": 0,
                "total": 0,
                "message": f"no local templates — see NUCLEI_TEMPLATES.md (dir: {dest})",
            }

        result = {"ok": False, "added": 0, "total": after, "message": ""}
        script = ROOT / "update_nuclei_templates.sh"
        if not script.exists():
            result["message"] = "update_nuclei_templates.sh missing"
            return result
        try:
            logger.info("Re-indexing %s local Nuclei template(s)…", after)
            proc = subprocess.run(
                ["bash", str(script)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode != 0:
                tail = (proc.stderr or proc.stdout or "")[-400:]
                result["message"] = f"exit {proc.returncode}: {tail}"
                logger.error("Nuclei re-index failed: %s", result["message"])
                return result
            after = self._count_nuclei_cve_yamls(self.config)
            result.update({
                "ok": True,
                "added": max(0, after - before),
                "total": after,
                "message": f"{after} CVE-*.yaml templates indexed locally",
            })
            logger.info("Nuclei re-index OK — +%s templates, total %s", result["added"], after)
        except subprocess.TimeoutExpired:
            result["message"] = "timeout after 600s"
            logger.error("Nuclei re-index timed out")
        except Exception as e:
            result["message"] = str(e)
            logger.error("Nuclei re-index error: %s", e)
        return result

    def rebuild_cve_map(self) -> Dict[str, Any]:
        before = self._map_stats()
        result = {"ok": False, "added": 0, "total": before["with_template"], "message": ""}
        script = ROOT / "build_cve_nuclei_map.py"
        if not script.exists():
            result["message"] = "build_cve_nuclei_map.py missing"
            return result
        try:
            logger.info("Rebuilding CVE ↔ Nuclei map + GitHub links…")
            proc = subprocess.run(
                [sys.executable, str(script)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode != 0:
                tail = (proc.stderr or proc.stdout or "")[-400:]
                result["message"] = f"exit {proc.returncode}: {tail}"
                logger.error("Map rebuild failed: %s", result["message"])
                return result
            after = self._map_stats()
            result.update({
                "ok": True,
                "added": max(0, after["with_template"] - before["with_template"]),
                "total": after["with_template"],
                "message": (
                    f"{after['with_template']} mapped · "
                    f"{after['with_poc']} GitHub/POC links"
                ),
            })
            logger.info("Map rebuild OK — +%s mappings", result["added"])
        except subprocess.TimeoutExpired:
            result["message"] = "timeout after 600s"
        except Exception as e:
            result["message"] = str(e)
            logger.error("Map rebuild error: %s", e)
        return result

    def run_full_sync(self) -> Dict[str, Any]:
        global _SYNC_RUNNING
        if _SYNC_RUNNING:
            logger.warning("Sync already in progress")
            return load_update_status()
        _SYNC_RUNNING = True
        try:
            kev = self.download_kev()
            nuclei = self.update_nuclei_templates()
            cmap = self.rebuild_cve_map()

            ok = kev["ok"] and nuclei["ok"] and cmap["ok"]
            parts = []
            if kev["added"]:
                parts.append(f"{kev['added']} KEV entries")
            if nuclei["added"]:
                parts.append(f"{nuclei['added']} Nuclei templates")
            if cmap["added"]:
                parts.append(f"{cmap['added']} CVE map links")
            if not parts:
                parts.append("no new items (catalogs refreshed)")

            status = {
                "last_run_at": _utc_now_iso(),
                "last_run_ok": ok,
                "summary": f"Last sync {_utc_now_iso()}: +{', +'.join(parts)}",
                "components": {
                    "kev": kev,
                    "nuclei_templates": nuclei,
                    "cve_nuclei_map": cmap,
                },
            }
            save_update_status(status)
            logger.info("Full sync complete — ok=%s — %s", ok, status["summary"])
            return status
        finally:
            _SYNC_RUNNING = False

    def _seconds_until_daily_hour(self) -> float:
        from datetime import timedelta
        hour = int(self.config.get("daily_update_hour", 3))
        now = datetime.now()
        target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return max(60.0, (target - now).total_seconds())

    def sync_loop(self):
        interval = max(3600, int(self.config.get("update_interval", 86400)))
        logger.info("Daily sync loop — interval %ss, target hour %s:00",
                    interval, self.config.get("daily_update_hour", 3))

        self.run_full_sync()

        while self.running:
            wait = min(interval, self._seconds_until_daily_hour())
            logger.info("Next sync in %.0f seconds", wait)
            slept = 0.0
            while self.running and slept < wait:
                chunk = min(30.0, wait - slept)
                time.sleep(chunk)
                slept += chunk
            if self.running:
                self.run_full_sync()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.running = True
        self.thread = threading.Thread(target=self.sync_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=8)


# ---------------------------------------------------------------------------
# Reviews persistence
# ---------------------------------------------------------------------------

def _load_reviews():
    path = ROOT / REVIEWS_FILE
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("reviews load failed: %s", e)
        return {}


def _save_reviews(reviews):
    path = ROOT / REVIEWS_FILE
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(reviews, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class KEVHTTPHandler(SimpleHTTPRequestHandler):
    config = CONFIG

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        super().end_headers()

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _bearer_user(self) -> Optional[str]:
        auth = self.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            token = self.headers.get("X-Ninjas-Token") or ""
        secret = _auth_cfg(self.config).get("secret", "")
        return verify_token(token, secret)

    def _require_auth(self) -> Optional[str]:
        user = self._bearer_user()
        if not user:
            self._send_json(401, {"error": "unauthorized"})
        return user

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in ("", "/"):
            return self._serve_file("login.html")

        if path == "/index.html":
            pass  # auth enforced client-side (Bearer token lives in sessionStorage)

        if path == "/api/me":
            user = self._bearer_user()
            if not user:
                return self._send_json(401, {"error": "unauthorized"})
            return self._send_json(200, {"ok": True, "user": user})

        if path == "/api/config":
            user = self._require_auth()
            if not user:
                return
            cfg = self.config
            tpl = SyncEngine._nuclei_root(cfg)
            return self._send_json(200, {
                "nuclei_templates_dir": cfg.get("nuclei_templates_dir", ""),
                "nuclei_templates_resolved": str(tpl),
                "daily_update_hour": int(cfg.get("daily_update_hour", 3)),
                "ui_variant": cfg.get("ui_variant", "git"),
            })

        if path == "/api/update-status":
            user = self._require_auth()
            if not user:
                return
            status = load_update_status()
            status["next_run_at"] = next_sync_iso(self.config)
            status["daily_update_hour"] = int(self.config.get("daily_update_hour", 3))
            return self._send_json(200, status)

        if path == "/api/reviews":
            user = self._require_auth()
            if not user:
                return
            return self._send_json(200, _load_reviews())

        return super().do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]

        if path == "/api/login":
            try:
                body = self._read_json_body()
            except Exception as e:
                return self._send_json(400, {"error": f"bad json: {e}"})
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            if not check_credentials(username, password, self.config):
                return self._send_json(401, {"error": "invalid credentials"})
            secret = _auth_cfg(self.config).get("secret", "")
            token = make_token(username, secret)
            return self._send_json(200, {"ok": True, "token": token, "user": username})

        if path == "/api/sync/trigger":
            user = self._require_auth()
            if not user:
                return
            engine = getattr(self.server, "sync_engine", None)
            if not engine:
                return self._send_json(503, {"error": "sync engine unavailable"})
            threading.Thread(target=engine.run_full_sync, daemon=True).start()
            return self._send_json(202, {"ok": True, "message": "sync started"})

        if path == "/api/reviews":
            user = self._require_auth()
            if not user:
                return
            try:
                body = self._read_json_body()
            except Exception as e:
                return self._send_json(400, {"error": f"bad json: {e}"})

            cve = (body.get("cve") or "").strip().upper()
            if not cve:
                return self._send_json(400, {"error": "cve is required"})

            reviewer = (body.get("reviewer") or user).strip()[:80]
            note = (body.get("note") or "").strip()[:500]
            reviewed = bool(body.get("reviewed", True))

            with _REVIEWS_LOCK:
                reviews = _load_reviews()
                if reviewed:
                    prev = reviews.get(cve, {})
                    at = prev.get("at") if prev.get("reviewed") else _utc_now_iso()
                    reviews[cve] = {
                        "reviewed": True,
                        "reviewer": reviewer or prev.get("reviewer", user),
                        "note": note or prev.get("note", ""),
                        "at": at or _utc_now_iso(),
                    }
                else:
                    reviews.pop(cve, None)
                _save_reviews(reviews)
                payload = reviews.get(cve, {"reviewed": False, "cve": cve})
            return self._send_json(200, payload)

        return self._send_json(404, {"error": "not found"})

    def _serve_file(self, name: str):
        fp = ROOT / name
        if not fp.exists():
            self.send_error(404)
            return
        content = fp.read_bytes()
        ctype = "text/html; charset=utf-8" if name.endswith(".html") else "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def run_server(port: int, sync_engine: SyncEngine):
    server_address = ("", port)
    httpd = HTTPServer(server_address, KEVHTTPHandler)
    httpd.sync_engine = sync_engine
    KEVHTTPHandler.config = sync_engine.config

    logger.info("Ninjas KEV server → http://0.0.0.0:%s", port)
    logger.info("Login → http://0.0.0.0:%s/", port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server…")
        httpd.shutdown()


def load_config(config_file="config.json") -> Dict[str, Any]:
    cfg = _load_cfg(ROOT, config_file)
    CONFIG.update({k: v for k, v in cfg.items() if k != "auth"})
    if "auth" in cfg:
        CONFIG["auth"] = {**CONFIG.get("auth", {}), **cfg["auth"]}
    logger.info("Loaded config from %s", ROOT / config_file)
    return CONFIG


def save_config(config, config_file="config.json"):
    try:
        with open(ROOT / config_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.error("Could not save config: %s", e)


def main():
    parser = argparse.ArgumentParser(description="Ninjas KEV sync + HTTP server")
    parser.add_argument("--port", type=int)
    parser.add_argument("--update-interval", type=int)
    parser.add_argument("--update-only", action="store_true")
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    os.chdir(ROOT)
    config = load_config(args.config)
    if args.port:
        config["server_port"] = args.port
    if args.update_interval:
        config["update_interval"] = args.update_interval

    save_config(config, args.config)
    engine = SyncEngine(config)

    if args.update_only:
        status = engine.run_full_sync()
        sys.exit(0 if status.get("last_run_ok") else 1)

    engine.start()

    def shutdown(sig, frame):
        logger.info("Shutdown signal received")
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        run_server(config["server_port"], engine)
    finally:
        engine.stop()


if __name__ == "__main__":
    main()
