"""Free threat-intelligence lookups from abuse.ch — no account, no key.

Two feeds:
  - Feodo Tracker  — botnet command-and-control IPs (ipblocklist.json)
  - URLhaus        — malware-distribution URLs → their hosts

Feeds are cached to data/ and refreshed on a cadence; check_many() flags any
graph node (IP / domain / URL host) that appears in them, so recon results get a
"known-bad" badge. Read-only intel — never contacts the flagged host itself.
"""
from __future__ import annotations

import json
import time
import urllib.request
from urllib.parse import urlparse

from .config import settings

_CACHE = settings.DATA_DIR / "threatintel.json"
_TTL = 6 * 3600          # refresh feeds at most every 6h
_UA = "RODE-Toolkit/1.0 (local security lab)"
_FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_URLHAUS = "https://urlhaus.abuse.ch/downloads/json_recent/"

_state: dict = {"loaded": 0, "feodo": {}, "urlhaus": {}}


def _fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _host_of(value: str) -> str:
    v = (value or "").strip().lower()
    if "://" in v:
        v = urlparse(v).hostname or v
    else:
        v = v.split("/")[0].split(":")[0]
    return v


def refresh(force: bool = False) -> dict:
    now = time.time()
    if not force:
        if _state.get("loaded") and now - _state["loaded"] < _TTL:
            return _state
        try:
            c = json.loads(_CACHE.read_text())
            if now - c.get("loaded", 0) < _TTL:
                _state.update(c)
                return _state
        except Exception:
            pass
    feodo: dict = {}
    try:
        for it in _fetch_json(_FEODO):
            if isinstance(it, dict) and it.get("ip_address"):
                feodo[it["ip_address"]] = it.get("malware") or "botnet C2"
    except Exception:
        pass
    urlhaus: dict = {}
    try:
        data = _fetch_json(_URLHAUS)
        if isinstance(data, dict):
            rows = data.get("urls") if "urls" in data else \
                [v for vals in data.values() for v in (vals if isinstance(vals, list) else [vals])]
        else:
            rows = data
        for u in (rows or []):
            if not isinstance(u, dict):
                continue
            host = (u.get("host") or _host_of(u.get("url", ""))).lower()
            if host:
                urlhaus[host] = u.get("threat") or "malware_url"
    except Exception:
        pass
    # keep whatever we already had if a feed failed this round
    if feodo:
        _state["feodo"] = feodo
    if urlhaus:
        _state["urlhaus"] = urlhaus
    _state["loaded"] = now
    try:
        _CACHE.write_text(json.dumps(_state))
    except Exception:
        pass
    return _state


def check_many(values) -> dict:
    st = refresh()
    feodo = st.get("feodo", {})
    urlhaus = st.get("urlhaus", {})
    out = {}
    for v in (values or []):
        host = _host_of(v)
        if v in feodo or host in feodo:
            out[v] = {"listed": True, "source": "Feodo Tracker",
                      "threat": feodo.get(v) or feodo.get(host), "kind": "botnet C2"}
        elif host in urlhaus:
            out[v] = {"listed": True, "source": "URLhaus",
                      "threat": urlhaus.get(host), "kind": "malware host"}
        else:
            out[v] = {"listed": False}
    return {"results": out, "updated": st.get("loaded"),
            "sources": {"feodo": len(feodo), "urlhaus": len(urlhaus)}}
