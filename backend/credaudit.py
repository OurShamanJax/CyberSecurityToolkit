"""Login auditor — tests a login endpoint against a password list.

For YOUR OWN systems only (e.g. a local OWASP Juice Shop). Throttled and capped.
Pure stdlib HTTP so there are no extra dependencies and nothing leaves the box.
"""
import time, json as _json, urllib.request, urllib.error, urllib.parse
from pathlib import Path
from .config import settings


def _read_list(name: str, cap: int):
    p = settings.WORDLISTS_DIR / Path(name).name
    if not p.exists():
        return []
    words = [w.strip() for w in p.read_text(encoding="utf-8", errors="replace").splitlines() if w.strip()]
    return words[:cap]


def run_audit(o: dict) -> dict:
    base = str(o.get("base_url", "")).rstrip("/")
    if not base:
        return {"ok": False, "error": "A target URL is required."}
    url = base + o.get("login_path", "/rest/user/login")
    uf, pf = o.get("user_field", "email"), o.get("pass_field", "password")
    username = o.get("username", "")
    mode = o.get("mode", "json")
    success = int(o.get("success_status", 200))
    cap = min(int(o.get("max_tries", 300)), 2000)
    words = _read_list(o.get("wordlist", "passwords-top.txt"), cap)
    if not words:
        return {"ok": False, "error": "Wordlist not found or empty."}
    log, found, tried, errs = [], None, 0, 0
    t0 = time.time()
    for pw in words:
        tried += 1
        body = {uf: username, pf: pw}
        try:
            if mode == "json":
                data, headers = _json.dumps(body).encode(), {"Content-Type": "application/json"}
            else:
                data, headers = urllib.parse.urlencode(body).encode(), {"Content-Type": "application/x-www-form-urlencoded"}
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=6) as r:
                code = r.getcode()
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:
            errs += 1
            log.append({"pw": pw, "code": "ERR", "note": str(e)[:70]})
            if errs >= 4 and tried <= 5:
                return {"ok": False, "error": "Could not reach the login endpoint — check the URL and path.",
                        "tried": tried, "log": log[:10]}
            continue
        ok = (code == success)
        log.append({"pw": pw, "code": code, "ok": ok})
        if ok:
            found = {"username": username, "password": pw}
            break
        time.sleep(0.02)
    return {"ok": True, "tried": tried, "found": found,
            "elapsed": round(time.time() - t0, 1), "log": log[-50:]}
