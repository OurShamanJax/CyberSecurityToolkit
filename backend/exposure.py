"""Exposure lookup via Shodan InternetDB — free, no account, no key.

InternetDB is a per-IP *lookup* (not a search firehose): given one IP you specify,
it returns the ports, products (CPEs), and known CVEs already indexed for it. Point
it at your own public IP to see what the internet sees exposed on you. Because it's
one IP at a time and public, it can't be turned into a global targeting index.
"""
import socket, re, json, urllib.request, urllib.error


def _resolve(target: str):
    t = re.sub(r'^\w+://', '', (target or "").strip()).split('/')[0].split(':')[0]
    if not t:
        return None, target
    try:
        socket.inet_aton(t)
        return t, t
    except OSError:
        pass
    try:
        return socket.gethostbyname(t), t
    except Exception:
        return None, t


def lookup(target: str) -> dict:
    ip, host = _resolve(target)
    if not ip:
        return {"ok": False, "error": f"Could not resolve '{target}'."}
    try:
        req = urllib.request.Request(f"https://internetdb.shodan.io/{ip}",
                                     headers={"User-Agent": "RODE-v4"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        return {"ok": True, "ip": ip, "host": host,
                "ports": d.get("ports", []), "cpes": d.get("cpes", []),
                "vulns": d.get("vulns", []), "hostnames": d.get("hostnames", []),
                "tags": d.get("tags", [])}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ok": True, "ip": ip, "host": host, "ports": [], "cpes": [],
                    "vulns": [], "hostnames": [], "tags": [],
                    "note": "No exposure indexed for this IP — that's a good sign; InternetDB has nothing on it."}
        return {"ok": False, "error": f"InternetDB returned HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:140]}


def my_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                ip = r.read().decode().strip()
                socket.inet_aton(ip)
                return ip
        except Exception:
            continue
    return None
