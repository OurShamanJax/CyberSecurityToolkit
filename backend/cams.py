"""Public camera feed registry for the Atlas globe.

Sources are feeds *published for public viewing* (DOT traffic cams, city/tourism
webcams) — added by the user or seeded as examples. NOT device-exposure scanning.
The snapshot proxy only ever fetches URLs already in this list (no arbitrary SSRF).
"""
import json, urllib.request
from .config import settings

_FILE = settings.DATA_DIR / "cameras.json"

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
                                     headers={"User-Agent": "RODE-v4"})
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


def import_source(name: str) -> dict:
    """Bulk-load real, published public cameras from a free/no-account source."""
    if name == "nyc":
        return _import_nyc()
    if name != "tfl":
        return {"ok": False, "error": "unknown source"}
    # Transport for London JamCams — ~900 public traffic cameras with live snapshots.
    try:
        req = urllib.request.Request("https://api.tfl.gov.uk/Place/Type/JamCam",
                                     headers={"User-Agent": "RODE-v4"})
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
        req = urllib.request.Request(url, headers={"User-Agent": "RODE-v4"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = resp.read(2_500_000)  # cap 2.5MB
            ctype = resp.headers.get("Content-Type", "image/jpeg")
            if not ctype.lower().startswith("image/"):
                ctype = "application/octet-stream"   # never let a feed serve renderable HTML
            return data, ctype
    except Exception:
        return None, None
