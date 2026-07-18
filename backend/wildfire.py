"""NASA FIRMS active-fire overlay — free API key, no account resale.

FIRMS publishes near-real-time wildfire/hotspot detections (VIIRS/MODIS). We
fetch the last day or two for a bounding box and hand back points so the globe
can show where fires are actually burning, coloured by detection confidence and
fire radiative power (FRP ~ intensity). Get a free key at
https://firms.modaps.eosdis.nasa.gov/api/map_key/  — stored server-side like the
Windy key, never committed.
"""
from __future__ import annotations

import csv
import io
import urllib.request

from . import cams   # reuse the gitignored secret store (get_secret/set_secret)

_UA = "RODE-Toolkit/1.0 (local security lab)"
_SRC = "VIIRS_SNPP_NRT"     # 375m VIIRS, near-real-time


def fires(bbox=None, days: int = 1) -> dict:
    key = cams.get_secret("firms_key")
    if not key:
        return {"ok": False, "error": "no FIRMS key set"}
    area = "world"
    if bbox and len(bbox) == 4:
        try:
            w, s, e, n = [float(x) for x in bbox]
            # FIRMS wants west,south,east,north
            area = f"{w},{s},{e},{n}"
        except Exception:
            area = "world"
    days = max(1, min(int(days or 1), 3))
    url = f"https://firms.modaps.eosdis.nasa.gov/api/area/csv/{key}/{_SRC}/{area}/{days}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception as ex:
        return {"ok": False, "error": str(ex)[:120]}
    low = text.strip().lower()
    if low.startswith("invalid") or "invalid map_key" in low or "invalid mapkey" in low:
        return {"ok": False, "error": "invalid FIRMS key (get one free at firms.modaps.eosdis.nasa.gov)"}
    if "latitude" not in text[:200].lower():
        return {"ok": False, "error": "unexpected FIRMS response"}
    out = []
    try:
        for row in csv.DictReader(io.StringIO(text)):
            try:
                lat = float(row["latitude"]); lng = float(row["longitude"])
            except Exception:
                continue
            out.append({"lat": lat, "lng": lng,
                        "conf": (row.get("confidence", "") or "").strip(),
                        "frp": row.get("frp", ""),
                        "date": row.get("acq_date", ""), "time": row.get("acq_time", ""),
                        "sat": row.get("satellite", "")})
            if len(out) >= 6000:
                break
    except Exception as ex:
        return {"ok": False, "error": "parse: " + str(ex)[:80]}
    return {"ok": True, "fires": out, "count": len(out)}
