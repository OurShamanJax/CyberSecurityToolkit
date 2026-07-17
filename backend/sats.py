"""Satellite orbital elements (TLE) proxy for the Atlas globe.

Fetches free, no-account TLE data from Celestrak and caches it. The frontend
propagates positions with satellite.js and animates them in orbit.
"""
import time, urllib.request
from .config import settings

_CACHE = settings.DATA_DIR / "tle_cache.txt"
_URL = "https://celestrak.org/NORAD/elements/gp.php?GROUP=visual&FORMAT=tle"
_TTL = 3600  # 1 hour


def fetch_tle(limit: int = 140):
    txt = None
    try:
        if _CACHE.exists() and (time.time() - _CACHE.stat().st_mtime) < _TTL:
            txt = _CACHE.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if not txt:
        try:
            req = urllib.request.Request(_URL, headers={"User-Agent": "RODE-v4"})
            with urllib.request.urlopen(req, timeout=12) as r:
                txt = r.read().decode("utf-8", "replace")
            try:
                _CACHE.write_text(txt, encoding="utf-8")
            except Exception:
                pass
        except Exception:
            return []
    lines = [l.rstrip() for l in txt.splitlines() if l.strip()]
    sats, i = [], 0
    while i + 2 < len(lines) + 1 and len(sats) < limit:
        if i + 2 >= len(lines):
            break
        name, l1, l2 = lines[i], lines[i + 1], lines[i + 2]
        if l1.startswith("1 ") and l2.startswith("2 "):
            sats.append({"name": name.strip(), "l1": l1, "l2": l2})
            i += 3
        else:
            i += 1
    return sats
