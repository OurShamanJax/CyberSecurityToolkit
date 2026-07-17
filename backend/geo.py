"""Lightweight IP geolocation for the Map lens.

Uses the free, no-account, no-key ip-api.com endpoint and caches results to disk,
so each public IP is looked up once. Private/loopback IPs return None. If you drop
a MaxMind/DB-IP .mmdb into data/, we could read it offline instead (future).
"""
import json, re, socket, urllib.request
from .config import settings

_CACHE_FILE = settings.DATA_DIR / "geoip_cache.json"
_cache = None
_PRIV = re.compile(r'^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)')


def _load():
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(_CACHE_FILE.read_text())
        except Exception:
            _cache = {}
    return _cache


def _save():
    try:
        _CACHE_FILE.write_text(json.dumps(_cache))
    except Exception:
        pass


def _to_ip(value: str):
    v = re.sub(r'^\w+://', '', (value or '').strip()).split('/')[0].split(':')[0]
    if not v:
        return None
    try:
        socket.inet_aton(v)
        return v
    except OSError:
        pass
    try:
        return socket.gethostbyname(v)
    except Exception:
        return None


def locate(value: str):
    ip = _to_ip(value)
    if not ip or _PRIV.match(ip):
        return None
    c = _load()
    if ip in c:
        return c[ip]
    res = None
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,lat,lon",
                                    timeout=6) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        if d.get("status") == "success":
            res = {"lat": d["lat"], "lng": d["lon"]}
    except Exception:
        pass
    c[ip] = res
    _save()
    return res
