"""Public camera feed registry for the Atlas globe.

Sources are feeds *published for public viewing* (DOT traffic cams, city/tourism
webcams) — added by the user or seeded as examples. NOT device-exposure scanning.
The snapshot proxy only ever fetches URLs already in this list (no arbitrary SSRF).
"""
import json, urllib.request, urllib.error
from urllib.parse import urlparse
from .config import settings

_FILE = settings.DATA_DIR / "cameras.json"
_SECRETS = settings.DATA_DIR / "secrets.json"   # gitignored (inside data/): API keys etc.


def _load_secrets() -> dict:
    try:
        return json.loads(_SECRETS.read_text())
    except Exception:
        return {}


def set_secret(name: str, value: str) -> bool:
    d = _load_secrets()
    d[name] = (value or "").strip()
    try:
        _SECRETS.write_text(json.dumps(d))
    except Exception:
        pass
    return True


def get_secret(name: str) -> str:
    return _load_secrets().get(name) or ""

# Example points so the globe isn't empty on first run. URLs are intentionally
# blank — add your region's published public feeds (e.g. your state DOT 511 open
# data, or a public webcam snapshot URL). The globe renders these locations; set
# a URL to make a point viewable.
SEED = []   # populated on demand from public sources (see import_source)


def has_feeds():
    return any((r.get("url") or "").strip() for r in _load())


def _import_nyc() -> dict:
    """NYC DOT (NYCTMC) public traffic cameras — free, no account. Best-effort schema."""
    try:
        req = urllib.request.Request("https://webcams.nyctmc.org/api/cameras/",
                                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"ok": False, "error": str(e)[:140]}
    items = data if isinstance(data, list) else (data.get("cameras") or data.get("results") or [])
    rows = [r for r in _load() if (r.get("url") or "").strip() and "webcams.nyctmc.org" not in (r.get("url") or "")]
    seen = {r.get("url") for r in rows}
    nid = max([r.get("id", 0) for r in rows], default=0)
    added = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        lat = it.get("latitude") or it.get("lat")
        lng = it.get("longitude") or it.get("lng") or it.get("lon")
        cid = it.get("id") or it.get("cameraId") or it.get("uuid")
        img = it.get("imageUrl") or it.get("image") or (f"https://webcams.nyctmc.org/api/cameras/{cid}/image" if cid else None)
        nm = it.get("name") or it.get("roadway") or it.get("area") or "NYC cam"
        try:
            if not (lat and lng and img) or img in seen:
                continue
            nid += 1
            seen.add(img)
            rows.append({"id": nid, "name": str(nm)[:80], "lat": float(lat), "lng": float(lng),
                         "country": "US", "type": "traffic", "url": img, "video": "", "stream": "jpg"})
            added += 1
        except Exception:
            continue
    _save(rows)
    return {"ok": True, "added": added, "total": len(rows)}


_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"


def _next_id(rows):
    return max([r.get("id", 0) for r in rows], default=0)


_CALTRANS_DISTRICTS = ["01","02","03","04","05","06","07","08","09","10","11","12"]


def _import_caltrans() -> dict:
    """Caltrans (California DOT) district CCTV feeds - free, no account. Roughly
    statewide coverage across 12 districts. Best-effort per-district."""
    rows = [r for r in _load() if (r.get("url") or "").strip() and "dot.ca.gov" not in (r.get("url") or "")]
    seen = {r.get("url") for r in rows}
    nid = _next_id(rows); added = 0; errs = 0
    for d in _CALTRANS_DISTRICTS:
        url = f"https://cwwp2.dot.ca.gov/data/d{int(d)}/cctv/cctvStatusD{d}.json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            errs += 1; continue
        for item in (data.get("data") or []):
            c = item.get("cctv") or item
            loc = c.get("location") or {}
            img = ((c.get("imageData") or {}).get("static") or {}).get("currentImageURL")
            lat = loc.get("latitude"); lng = loc.get("longitude")
            nm = loc.get("locationName") or loc.get("nearbyPlace") or "Caltrans cam"
            try:
                lat = float(lat); lng = float(lng)
                if not img or img in seen or not (lat and lng):
                    continue
                nid += 1; seen.add(img)
                rows.append({"id": nid, "name": str(nm)[:80], "lat": lat, "lng": lng,
                             "country": "US", "type": "traffic", "url": img,
                             "video": "", "stream": "jpg", "src": "caltrans"})
                added += 1
            except Exception:
                continue
    _save(rows)
    if added == 0 and errs:
        return {"ok": False, "error": "Caltrans feeds unreachable", "added": 0, "total": len(rows)}
    return {"ok": True, "added": added, "total": len(rows)}


def import_windy(lat, lng, radius_km, key: str) -> dict:
    """Windy Webcams API v3 (global, ~70k cams) - needs a free API key. Queries
    webcams near a viewport centre so coverage follows wherever you look."""
    key = (key or "").strip() or get_secret("windy_key")
    if not key:
        return {"ok": False, "error": "no Windy API key set"}
    try:
        lat = float(lat); lng = float(lng); radius_km = max(5, min(int(radius_km), 250))
    except Exception:
        return {"ok": False, "error": "bad coordinates"}
    url = (f"https://api.windy.com/webcams/api/v3/webcams?nearby={lat},{lng},{radius_km}"
           "&limit=50&include=images,location")
    try:
        import requests   # sends the header with EXACT lowercase casing (urllib capitalises)
        resp = requests.get(url, headers={"x-windy-api-key": key, "User-Agent": _UA}, timeout=15)
        if resp.status_code == 401:
            return {"ok": False, "error": "401 — key not active yet (wait a few min) or not a Webcams-API key"}
        if resp.status_code != 200:
            return {"ok": False, "error": f"Windy API {resp.status_code}"}
        data = resp.json()
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}
    webcams = data.get("webcams") or []
    rows = _load()
    seen = {r.get("url") for r in rows if (r.get("url") or "").strip()}
    nid = _next_id(rows); added = 0
    for w in webcams:
        loc = w.get("location") or {}
        imgs = w.get("images") or {}
        cur = imgs.get("current") or {}
        img = cur.get("preview") or cur.get("thumbnail") or (imgs.get("daylight") or {}).get("preview")
        la = loc.get("latitude"); lo = loc.get("longitude")
        nm = w.get("title") or loc.get("city") or "webcam"
        try:
            la = float(la); lo = float(lo)
            if not img or img in seen or not (la and lo):
                continue
            nid += 1; seen.add(img)
            place = ", ".join([str(x) for x in (loc.get("city"), loc.get("region"), loc.get("country")) if x])
            rows.append({"id": nid, "name": str(nm)[:80], "lat": la, "lng": lo,
                         "country": loc.get("country") or "", "place": place, "type": "webcam",
                         "url": img, "video": "", "stream": "jpg", "src": "windy"})
            added += 1
        except Exception:
            continue
    if len(rows) > 4000:
        rows = rows[-4000:]
    _save(rows)
    return {"ok": True, "added": added, "total": len(rows)}


# ── "One Network" 511 family — a public, no-key camera API used by many US state
#    and Canadian provincial DOTs. Same JSON shape everywhere, so ONE importer
#    covers all of them; add a jurisdiction by adding a base URL here + a bounds
#    box in the frontend CAM_SOURCES. Endpoint: /api/v2/get/cameras
_ONE_NETWORK = {
    "on":     ("https://511on.ca",         "CA", "Ontario 511"),
    "ab":     ("https://511.alberta.ca",   "CA", "Alberta 511"),
    "ns":     ("https://511.novascotia.ca","CA", "Nova Scotia 511"),
    "sk":     ("https://hb.511.saskatchewan.ca", "CA", "Saskatchewan HB511"),
    "nv":     ("https://www.nvroads.com",   "US", "Nevada NDOT"),
    "wi":     ("https://511wi.gov",         "US", "Wisconsin 511"),
    "pa":     ("https://www.511pa.com",     "US", "Pennsylvania 511"),
    "ne_usa": ("https://newengland511.org", "US", "New England 511"),
    "neska":  ("https://511.nebraska.gov",  "US", "Nebraska 511"),
    "la":     ("https://www.511la.org",     "US", "Louisiana 511"),
}


def _import_onenetwork(code: str) -> dict:
    """Import one One-Network/511 jurisdiction's public traffic cameras."""
    base, country, label = _ONE_NETWORK[code]
    url = base + "/api/v2/get/cameras?format=json&lang=en"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"ok": False, "error": f"{label}: {str(e)[:120]}"}
    items = data if isinstance(data, list) else (data.get("cameras") or data.get("Cameras") or [])
    rows = [r for r in _load() if (r.get("url") or "").strip() and r.get("src") != code]
    seen = {r.get("url") for r in rows}
    nid = _next_id(rows); added = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        lat = it.get("Latitude", it.get("latitude"))
        lng = it.get("Longitude", it.get("longitude"))
        img = None
        for v in (it.get("Views") or it.get("views") or []):
            if isinstance(v, dict):
                u = v.get("Url") or v.get("url")
                if u and str(v.get("Status", "Enabled")).lower() != "disabled":
                    img = u; break
        if not img:
            img = it.get("ImageUrl") or it.get("imageUrl") or it.get("Url") or it.get("url")
        nm = (it.get("Location") or it.get("RoadwayName") or it.get("Roadway")
              or it.get("Name") or f"{label} cam")
        try:
            lat = float(lat); lng = float(lng)
            if not img or img in seen or not (lat and lng):
                continue
            nid += 1; seen.add(img)
            rows.append({"id": nid, "name": str(nm)[:80], "lat": lat, "lng": lng,
                         "country": country, "type": "traffic", "url": img,
                         "video": "", "stream": "jpg", "src": code})
            added += 1
        except Exception:
            continue
    if len(rows) > 6000:
        rows = rows[-6000:]
    _save(rows)
    if added == 0:
        return {"ok": False, "error": f"{label}: no cameras parsed", "added": 0, "total": len(rows)}
    return {"ok": True, "added": added, "total": len(rows)}


def import_source(name: str) -> dict:
    """Bulk-load real, published public cameras from a free/no-account source."""
    if name == "nyc":
        return _import_nyc()
    if name == "caltrans":
        return _import_caltrans()
    if name in _ONE_NETWORK:
        return _import_onenetwork(name)
    if name != "tfl":
        return {"ok": False, "error": "unknown source"}
    # Transport for London JamCams — ~900 public traffic cameras with live snapshots.
    try:
        req = urllib.request.Request("https://api.tfl.gov.uk/Place/Type/JamCam",
                                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"ok": False, "error": str(e)[:140]}
    # rebuild: drop empty placeholders + any prior TfL rows so they re-import WITH video
    rows = [r for r in _load() if (r.get("url") or "").strip() and "jamcams.tfl.gov.uk" not in (r.get("url") or "")]
    seen = {r.get("url") for r in rows}
    nid = max([r.get("id", 0) for r in rows], default=0)
    added = 0
    for pl in data:
        lat, lng = pl.get("lat"), pl.get("lon")
        img = vid = None
        for ap in pl.get("additionalProperties", []):
            if ap.get("key") == "imageUrl":
                img = ap.get("value")
            elif ap.get("key") == "videoUrl":
                vid = ap.get("value")
        if not (lat and lng and img) or img in seen:
            continue
        nid += 1
        seen.add(img)
        rows.append({"id": nid, "name": (pl.get("commonName") or "JamCam")[:80],
                     "lat": float(lat), "lng": float(lng), "country": "GB",
                     "type": "traffic", "url": img, "video": vid or "",
                     "stream": "video" if vid else "jpg"})
        added += 1
    _save(rows)
    return {"ok": True, "added": added, "total": len(rows)}


def _load():
    if not _FILE.exists():
        _FILE.write_text(json.dumps(SEED, indent=2))
        return [dict(r) for r in SEED]
    try:
        return json.loads(_FILE.read_text())
    except Exception:
        return [dict(r) for r in SEED]


def _save(rows):
    _FILE.write_text(json.dumps(rows, indent=2))


def list_cams():
    return _load()


def get_cam(cid):
    for r in _load():
        if r.get("id") == cid:
            return r
    return None


def add_cam(o):
    rows = _load()
    nid = (max([r.get("id", 0) for r in rows], default=0) or 0) + 1
    row = {"id": nid, "name": (o.get("name") or "camera")[:80],
           "lat": float(o.get("lat", 0)), "lng": float(o.get("lng", 0)),
           "country": (o.get("country") or "")[:4], "type": o.get("type", "webcam"),
           "url": (o.get("url") or "").strip(), "video": (o.get("video") or "").strip(),
           "stream": o.get("stream", "jpg")}
    rows.append(row)
    _save(rows)
    return row


def delete_cam(cid):
    rows = [r for r in _load() if r.get("id") != cid]
    _save(rows)
    return {"ok": True}


def snapshot(cid):
    """Fetch a single snapshot for a listed camera. Only listed URLs — no SSRF."""
    r = get_cam(cid)
    if not r or not r.get("url"):
        return None, None
    url = r["url"]
    if not (url.startswith("http://") or url.startswith("https://")):
        return None, None
    # block cloud-metadata SSRF target
    from urllib.parse import urlparse
    if (urlparse(url).hostname or "") in ("169.254.169.254", "metadata.google.internal"):
        return None, None
    try:
        from urllib.parse import urlparse as _up
        _o = _up(url)
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Referer": f"{_o.scheme}://{_o.netloc}/",
            "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read(2_500_000)  # cap 2.5MB
            ctype = resp.headers.get("Content-Type", "image/jpeg")
            if not ctype.lower().startswith("image/"):
                ctype = "application/octet-stream"   # never let a feed serve renderable HTML
            return data, ctype
    except Exception:
        return None, None
