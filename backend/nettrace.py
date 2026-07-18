"""
Network geolocation helpers for the Atlas map lens:
  * locate_rich(value)  → geolocate one IP/domain (lat/lng + city/country)
  * traceroute(target)  → run the OS traceroute, geolocate each public hop

Uses the free, no-account ip-api.com endpoints (single + batch). Private/loopback
hops have no public location, so they're returned without coordinates. Traceroute
shells out to the real OS tool (tracert on Windows, traceroute on Linux) with a
fixed argv list (shell=False) and an overall deadline.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
import urllib.parse

_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_HOPNUM = re.compile(r"^\s*(\d+)")
_PRIV = re.compile(r"^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)")


def _to_ip(value: str):
    v = re.sub(r"^\w+://", "", (value or "").strip()).split("/")[0].split(":")[0]
    if not v:
        return None
    if _IPV4.fullmatch(v):
        return v
    try:
        return socket.gethostbyname(v)
    except Exception:
        return None


def _ip_api_batch(ips: list[str]) -> dict:
    """Geolocate up to 100 IPs in one call. Returns {ip: {lat,lng,city,country}}."""
    out: dict = {}
    pub = [ip for ip in dict.fromkeys(ips) if ip and not _PRIV.match(ip)]
    if not pub:
        return out
    try:
        body = json.dumps([{"query": ip, "fields": "status,query,lat,lon,city,country"}
                           for ip in pub[:100]]).encode()
        req = urllib.request.Request("http://ip-api.com/batch", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            arr = json.loads(r.read().decode("utf-8", "replace"))
        for d in arr:
            if d.get("status") == "success":
                out[d.get("query")] = {"lat": d["lat"], "lng": d["lon"],
                                       "city": d.get("city", ""), "country": d.get("country", "")}
    except Exception:
        pass
    return out


def locate_rich(value: str):
    """Geolocate a single IP/domain. Returns {ip,lat,lng,city,country} or None."""
    ip = _to_ip(value)
    if not ip:
        return None
    if _PRIV.match(ip):
        return {"ip": ip, "lat": None, "lng": None, "city": "", "country": "private/LAN"}
    got = _ip_api_batch([ip]).get(ip)
    if not got:
        return {"ip": ip, "lat": None, "lng": None, "city": "", "country": ""}
    return {"ip": ip, **got}


def geocode(q: str) -> dict:
    """Free place search (OpenStreetMap Nominatim) — name/state/country -> a point
    plus a bounding box so the globe can frame the area. No key; Nominatim asks
    for a valid User-Agent and light use, which fits a single-user local tool."""
    q = (q or "").strip()
    if not q:
        return {"ok": False}
    try:
        url = ("https://nominatim.openstreetmap.org/search?format=json&limit=1&q="
               + urllib.parse.quote(q))
        req = urllib.request.Request(url, headers={
            "User-Agent": "RODE-Toolkit/1.0 (local security lab; contact: local user)",
            "Accept-Language": "en"})
        with urllib.request.urlopen(req, timeout=8) as r:
            arr = json.loads(r.read().decode("utf-8", "replace"))
        if not arr:
            return {"ok": False}
        it = arr[0]
        out = {"ok": True, "name": (it.get("display_name") or q)[:140],
               "lat": float(it["lat"]), "lng": float(it["lon"])}
        bb = it.get("boundingbox")            # [south, north, west, east] (strings)
        if bb and len(bb) == 4:
            out.update({"south": float(bb[0]), "north": float(bb[1]),
                        "west": float(bb[2]), "east": float(bb[3])})
        return out
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}


def _traceroute_argv(target: str, max_hops: int) -> list[str] | None:
    if os.name == "nt":
        exe = shutil.which("tracert") or "tracert"
        return [exe, "-d", "-h", str(max_hops), "-w", "800", target]
    exe = shutil.which("traceroute")
    if not exe:
        return None
    return [exe, "-n", "-q", "1", "-m", str(max_hops), "-w", "2", target]


def _parse_hop(line: str):
    """Return (hop_no, ip_or_None) for a traceroute output line, or None."""
    m = _HOPNUM.match(line)
    if not m:
        return None
    hop = int(m.group(1))
    ipm = _IPV4.search(line)
    return hop, (ipm.group(1) if ipm else None)


def traceroute(target: str, max_hops: int = 18, deadline_s: int = 60) -> dict:
    """Run the OS traceroute to `target`, geolocate each public hop."""
    tip = _to_ip(target)
    argv = _traceroute_argv(target, max_hops)
    if argv is None:
        return {"ok": False, "error": "traceroute not installed (Linux: apt install traceroute).",
                "target": target, "resolved": tip, "hops": []}

    hops: list[dict] = []
    seen_hop = 0
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace",
                                bufsize=1, shell=False, creationflags=flags)
        start = time.time()
        for line in iter(proc.stdout.readline, ""):
            if time.time() - start > deadline_s:
                try:
                    proc.kill()
                except Exception:
                    pass
                break
            parsed = _parse_hop(line)
            if not parsed:
                continue
            hop, ip = parsed
            if hop <= seen_hop:      # tracert prints 3 probes per line; one line/hop already
                continue
            seen_hop = hop
            hops.append({"hop": hop, "ip": ip})
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
    except FileNotFoundError:
        return {"ok": False, "error": "traceroute binary not found.",
                "target": target, "resolved": tip, "hops": []}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "target": target, "resolved": tip, "hops": []}

    geo = _ip_api_batch([h["ip"] for h in hops if h["ip"]])
    for h in hops:
        g = geo.get(h["ip"]) if h["ip"] else None
        if g:
            h.update(g)
        elif h["ip"] and _PRIV.match(h["ip"]):
            h["country"] = "private/LAN"
    located = sum(1 for h in hops if h.get("lat") is not None)
    return {"ok": True, "target": target, "resolved": tip,
            "hops": hops, "count": len(hops), "located": located}
