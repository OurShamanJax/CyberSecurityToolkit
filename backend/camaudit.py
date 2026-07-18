"""
Camera & IoT security audit — find exposed cameras / IoT on YOUR OWN network and
your OWN public IP, then tell you how to lock them down. The defensive counterpart
to the camera globe.

Scope-locked by construction:
  * The LAN scan only ever touches RFC-1918 private addresses (10/172.16-31/192.168)
    and refuses anything else — it cannot reach another network.
  * The internet-exposure check ONLY looks at THIS machine's own auto-detected
    public IP. It takes no address argument, so it can't be pointed at a stranger.

It is non-intrusive: it detects *open services* and *missing authentication* — it
never brute-forces credentials and never connects to a device you don't own. When
it finds a problem it returns a plain-English fix checklist, and (educational only)
a responsible-disclosure template for the case where someone else's device is
exposed. A clearly-labelled SAMPLE audit lets you see the whole thing work without
owning a camera; sample data is never mixed into a real scan's results.
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor

# RFC-1918 private ranges + loopback. Everything else is out of scope, full stop.
_PRIV = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")

# Ports commonly exposed by cameras / DVRs / NVRs / IoT. (port -> (label, kind))
RISKY_PORTS = {
    23:    ("Telnet",              "telnet"),
    2323:  ("Telnet (alt)",        "telnet"),
    80:    ("Web admin (HTTP)",    "http"),
    81:    ("Web admin (HTTP)",    "http"),
    88:    ("Web admin (HTTP)",    "http"),
    443:   ("Web admin (HTTPS)",   "https"),
    554:   ("RTSP video stream",   "rtsp"),
    8000:  ("Web admin (HTTP)",    "http"),
    8080:  ("Web admin (HTTP)",    "http"),
    8081:  ("Web admin (HTTP)",    "http"),
    8443:  ("Web admin (HTTPS)",   "https"),
    8554:  ("RTSP video (alt)",    "rtsp"),
    8899:  ("DVR service",         "dvr"),
    9000:  ("Camera service",      "dvr"),
    34567: ("DVR (dvrip/Xiongmai)", "dvr"),
    37777: ("Dahua DVR/NVR",       "dvr"),
    37778: ("Dahua DVR/NVR (alt)", "dvr"),
    49152: ("UPnP device service", "http"),
}

# High-confidence camera / DVR vendor MAC prefixes (OUI -> brand).
_CAM_OUI = {
    "44:19:B6": "Hikvision", "4C:BD:8F": "Hikvision", "58:03:FB": "Hikvision",
    "BC:AD:28": "Hikvision", "C0:56:E3": "Hikvision", "28:57:BE": "Hikvision",
    "E0:50:8B": "Hikvision", "18:80:25": "Hikvision",
    "3C:EF:8C": "Dahua", "90:02:A9": "Dahua", "E4:24:6C": "Dahua",
    "14:A7:8B": "Dahua", "38:AF:29": "Dahua", "A0:BD:1D": "Dahua",
    "00:40:8C": "Axis", "AC:CC:8E": "Axis", "B8:A4:4F": "Axis",
    "EC:71:DB": "Reolink", "88:DE:A9": "Amcrest", "9C:8E:CD": "Amcrest",
    "00:62:6E": "Foscam", "C4:D6:55": "Vivotek", "00:0F:7C": "Mobotix",
    "2C:AA:8E": "Wyze", "7C:78:B2": "Wyze", "D0:3F:27": "Wyze",
    "B0:C5:54": "D-Link camera", "00:18:0A": "Ubiquiti cam", "FC:EC:DA": "Ubiquiti",
    "48:8B:0A": "Uniview", "A4:14:37": "Uniview", "54:C4:15": "Lorex",
}

REMEDIES = {
    "change-default": "Change the default password. Default / factory credentials are the #1 way cameras get taken over — use a long, unique password per device.",
    "set-password":   "Set an admin password immediately — the device is currently answering with no login at all.",
    "disable-telnet": "Disable Telnet in the device settings (and SSH if unused). Telnet is unencrypted and the primary target of IoT malware like Mirai.",
    "no-forward":     "Remove any port-forward for this device on your router. Camera/DVR ports should never be reachable from the internet.",
    "disable-upnp":   "Turn off UPnP on your router — many cameras silently open internet-facing ports through it without you knowing.",
    "vpn-instead":    "To view cameras away from home, use a VPN back into your network (R.O.D.E's VPN page generates one) instead of exposing the camera directly.",
    "segment":        "Put cameras/IoT on a separate VLAN or guest network so a compromised device can't reach your computers.",
    "update-fw":      "Update the device firmware — camera/DVR firmware is frequently vulnerable and vendors patch known holes.",
    "disable-cloud":  "Disable the vendor 'P2P' / cloud-relay feature if you don't use it — it can expose the device outside your control.",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def is_private(ip: str) -> bool:
    return bool(_PRIV.match((ip or "").strip()))


def camera_vendor(mac: str) -> str:
    if not mac:
        return ""
    oui = ":".join(mac.upper().split(":")[:3])
    return _CAM_OUI.get(oui, "")


# ── network primitives (injectable for tests) ────────────────────────────────
def _port_open(ip: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def _http_probe(ip: str, port: int, timeout: float = 1.4) -> dict:
    """Non-intrusive: one GET / to see whether the web UI demands a login.
    Returns {status, auth_required, server}. No credentials are ever sent."""
    scheme_https = RISKY_PORTS.get(port, ("", ""))[1] == "https"
    try:
        import urllib.request
        import ssl
        url = f"{'https' if scheme_https else 'http'}://{ip}:{port}/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "RODE-camaudit"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {"status": r.status, "auth_required": False,
                    "server": r.headers.get("Server", "")}
    except Exception as e:
        code = getattr(e, "code", 0)
        if code in (401, 403):
            hdrs = getattr(e, "headers", None)
            realm = hdrs.get("WWW-Authenticate", "") if hdrs else ""
            return {"status": code, "auth_required": True, "server": realm}
        if code:
            return {"status": code, "auth_required": False, "server": ""}
        return {"status": 0, "auth_required": None, "server": ""}


def probe_host(ip: str, ports=None, timeout: float = 0.6) -> dict:
    ports = ports or list(RISKY_PORTS)
    with ThreadPoolExecutor(max_workers=24) as ex:
        results = zip(ports, ex.map(lambda p: _port_open(ip, p, timeout), ports))
        open_ports = [p for p, ok in results if ok]
    http = {}
    for p in open_ports:
        if RISKY_PORTS[p][1] in ("http", "https"):
            http[p] = _http_probe(ip, p)
    return {"open": open_ports, "http": http}


# ── assessment ───────────────────────────────────────────────────────────────
def _finding(host: dict, severity: str, title: str, why: str, fix_keys) -> dict:
    return {"ip": host.get("ip", ""), "device": host.get("hostname") or host.get("ip", ""),
            "severity": severity, "title": title, "why": why,
            "fixes": [REMEDIES[k] for k in fix_keys if k in REMEDIES]}


def _worst(findings) -> str:
    if not findings:
        return "info"
    return min((f["severity"] for f in findings), key=lambda s: _SEV_ORDER.get(s, 9))


def assess(host: dict, info: dict) -> dict:
    """Turn one host + its probe result into a device record with findings."""
    mac = host.get("mac", "")
    cam_brand = camera_vendor(mac)
    open_ports = list(info.get("open", []))
    http = info.get("http", {})
    is_camera = bool(cam_brand) or any(p in open_ports for p in (554, 8554, 34567, 37777, 37778, 8899))
    has_web = any(p in open_ports for p in (80, 81, 88, 443, 8000, 8080, 8081, 8443, 49152))
    is_iot = is_camera or (has_web and host.get("role") == "device" and host.get("vendor")
                           in ("Espressif (IoT)", "SmartThings", "Philips Hue", "Nest"))
    label = cam_brand or host.get("vendor") or host.get("hostname") or "device"
    findings = []

    for p in (23, 2323):
        if p in open_ports:
            findings.append(_finding(host, "critical", f"Telnet ({p}) is open",
                "Telnet is unencrypted and the number-one target of IoT botnets. On a camera or DVR it usually means factory firmware with a known backdoor.",
                ["disable-telnet", "update-fw", "segment"]))

    for p in (554, 8554):
        if p in open_ports:
            findings.append(_finding(host, "high", f"RTSP video stream (port {p}) is open",
                "The live video stream is reachable on the network. If it accepts no password, anyone on the LAN — or the whole internet, if this device is port-forwarded — can watch it.",
                ["change-default", "no-forward", "segment"]))

    for p in (34567, 37777, 37778, 8899, 9000):
        if p in open_ports:
            findings.append(_finding(host, "high", f"DVR/NVR service port {p} is open",
                "This is a proprietary camera-recorder control port. Several of these protocols have had authentication-bypass bugs; it should not be reachable beyond the devices that need it.",
                ["update-fw", "no-forward", "segment"]))

    for p, hi in http.items():
        auth = hi.get("auth_required")
        status = hi.get("status", 0)
        if auth is False and status in (200, 301, 302):
            findings.append(_finding(host, "critical", f"Admin web UI on port {p} has NO login",
                "The device's configuration page answered without asking for a password — it is wide open to being reconfigured or watched by anyone who can reach it.",
                ["set-password", "update-fw"]))
        elif (is_camera or is_iot) and auth is True:
            findings.append(_finding(host, "medium", f"Admin web UI on port {p} (login present)",
                "A login page is present — good. Make sure it is NOT still using the factory default password, which is the most common way these devices are taken over.",
                ["change-default", "update-fw"]))

    if is_camera and not findings:
        findings.append(_finding(host, "low", "Camera / DVR device detected",
            "This looks like a camera or recorder. Nothing obviously exposed was found on the ports checked — still worth confirming it isn't using default credentials and isn't port-forwarded to the internet.",
            ["change-default", "no-forward", "disable-cloud"]))

    return {"ip": host.get("ip", ""), "mac": mac, "hostname": host.get("hostname", ""),
            "vendor": cam_brand or host.get("vendor", ""), "label": label,
            "role": host.get("role", "device"), "open_ports": open_ports,
            "is_camera": is_camera, "is_iot": is_iot, "worst": _worst(findings),
            "findings": findings}


def scan_lan(hint: str | None = None, *, discover=None, probe=None) -> dict:
    """Audit your OWN LAN for exposed cameras/IoT. Refuses non-private networks."""
    if hint and not is_private(hint):
        return {"ok": False,
                "error": "Refusing to scan a non-private network. Camera Guard only audits your own LAN (10/172.16-31/192.168)."}
    if discover is None:
        from . import lan
        discover = lambda: lan.discover(hint=hint)
    probe = probe or probe_host

    res = discover()
    subnet = res.get("subnet", "")
    if subnet and not is_private(subnet.split("/")[0]):
        return {"ok": False, "error": "Detected network is not private — nothing scanned."}

    hosts = [h for h in res.get("hosts", []) if is_private(h.get("ip", ""))]
    devices, findings = [], []
    for h in hosts:
        dev = assess(h, probe(h["ip"]))
        devices.append(dev)
        findings.extend(dev["findings"])
    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))

    cams = [d for d in devices if d["is_camera"]]
    return {"ok": True, "is_sample": False, "subnet": subnet,
            "self": res.get("self", ""), "gateway": res.get("gateway", ""),
            "device_count": len(hosts), "camera_count": len(cams),
            "checked_ports": sorted(RISKY_PORTS), "devices": devices,
            "findings": findings}


def check_exposure(*, my_ip=None, lookup=None) -> dict:
    """Is a camera/IoT port on YOUR home connection reachable from the internet?
    Uses this machine's own public IP only — takes no address argument."""
    if my_ip is None or lookup is None:
        from . import exposure
        my_ip = my_ip or exposure.my_ip
        lookup = lookup or exposure.lookup
    ip = my_ip()
    if not ip:
        return {"ok": False, "error": "Could not detect your public IP (are you online?)."}
    res = lookup(ip)
    if not res.get("ok"):
        return {"ok": False, "ip": ip, "error": res.get("error", "exposure lookup failed")}

    ports = res.get("ports", [])
    risky = [p for p in ports if p in RISKY_PORTS]
    findings = []
    for p in risky:
        label = RISKY_PORTS[p][0]
        crit = p in (23, 2323, 554, 8554, 34567, 37777, 37778, 8899)
        findings.append({"severity": "critical" if crit else "high", "port": p,
            "title": f"Port {p} ({label}) is exposed to the internet",
            "why": "This port is reachable from the public internet on your home connection. Camera/DVR/IoT services should never be internet-facing — this is exactly how strangers end up watching private cameras.",
            "fixes": [REMEDIES["no-forward"], REMEDIES["disable-upnp"], REMEDIES["vpn-instead"]]})
    return {"ok": True, "is_sample": False, "ip": ip, "exposed_ports": ports,
            "risky_ports": risky, "clean": not risky, "findings": findings,
            "note": res.get("note", "")}


def disclosure_template(brand: str = "the device", ip: str = "203.0.113.10",
                        finder: str = "") -> str:
    """A polite, non-accusatory responsible-disclosure note — educational.
    For the case where you legitimately discover SOMEONE ELSE's device is exposed:
    you report it, you do NOT access it."""
    who = f"\n\n— {finder}" if finder else ""
    return (
        "Subject: Security notice — an internet-exposed camera/device on your network\n\n"
        "Hello,\n\n"
        f"I'm reaching out because a device that appears to be {brand} at the public "
        f"address {ip} is reachable from the open internet. I did not log in to it or "
        "access any video/data — I only noticed that the service is publicly exposed, "
        "which puts it at risk of being accessed by others.\n\n"
        "To secure it, I'd suggest:\n"
        "  • Remove any port-forward for the device on your router.\n"
        "  • Disable UPnP if you don't need it.\n"
        "  • Change the device's default password and update its firmware.\n"
        "  • Use a VPN to reach the device remotely instead of exposing it.\n\n"
        "I'm not affiliated with any vendor and there's nothing you need to do for me — "
        "I just wanted you to be aware. Feel free to ignore this if it's intentional."
        f"{who}\n"
    )


def sample_audit() -> dict:
    """A realistic, clearly-labelled SAMPLE result so the audit can be seen working
    without owning a camera. NEVER merged into a real scan (is_sample=True)."""
    hosts = [
        {"ip": "192.168.1.64", "mac": "44:19:B6:12:34:56", "hostname": "DS-2CD2042",
         "role": "device", "vendor": "Hikvision"},
        {"ip": "192.168.1.108", "mac": "3C:EF:8C:AA:BB:CC", "hostname": "",
         "role": "device", "vendor": "Dahua"},
        {"ip": "192.168.1.7", "mac": "2C:AA:8E:11:22:33", "hostname": "wyze-cam",
         "role": "device", "vendor": "Wyze"},
        {"ip": "192.168.1.1", "mac": "50:C7:BF:00:11:22", "hostname": "router",
         "role": "gateway", "vendor": "TP-Link"},
    ]
    probes = {
        "192.168.1.64":  {"open": [80, 554], "http": {80: {"status": 200, "auth_required": False}}},
        "192.168.1.108": {"open": [37777, 554, 23], "http": {}},
        "192.168.1.7":   {"open": [80, 554], "http": {80: {"status": 401, "auth_required": True}}},
        "192.168.1.1":   {"open": [80, 443], "http": {80: {"status": 401, "auth_required": True}}},
    }
    devices, findings = [], []
    for h in hosts:
        dev = assess(h, probes.get(h["ip"], {"open": [], "http": {}}))
        devices.append(dev)
        findings.extend(dev["findings"])
    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))
    cams = [d for d in devices if d["is_camera"]]
    return {"ok": True, "is_sample": True, "subnet": "192.168.1.0/24",
            "self": "192.168.1.20", "gateway": "192.168.1.1",
            "device_count": len(hosts), "camera_count": len(cams),
            "checked_ports": sorted(RISKY_PORTS), "devices": devices,
            "findings": findings}
