"""
Local network discovery — find live hosts on YOUR OWN LAN.

Scoped to the local private /24 only (derived from this machine's address or an
explicit private hint); refuses anything that isn't RFC-1918. Technique: a
concurrent ping sweep merged with the OS ARP cache, enriched with reverse-DNS
and a best-effort MAC-vendor (OUI) lookup. Broadcast/multicast/network
artifacts are filtered out. Results are cached so other pages (e.g. Live
Traffic) can label an IP with the device it belongs to.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .config import settings

_PRIV = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
_MAC = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
_IP = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
_HOSTS = settings.DATA_DIR / "lan_hosts.json"

# A curated, high-confidence set of common consumer OUIs (MAC prefix -> vendor).
# Partial by design — unknown prefixes just return "". Randomized/private MACs
# (locally-administered bit) are detected separately and always win.
_OUI = {
    "E4:F0:42": "Google", "F4:F5:E8": "Google", "F8:8F:CA": "Google",
    "1C:F2:9A": "Google", "3C:5A:B4": "Google", "94:EB:2C": "Google",
    "A4:77:33": "Google", "D8:6C:63": "Google", "54:60:09": "Google",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "FC:F5:C4": "Espressif (IoT)", "24:6F:28": "Espressif (IoT)",
    "A0:20:A6": "Espressif (IoT)", "8C:AA:B5": "Espressif (IoT)",
    "3C:71:BF": "Espressif (IoT)", "84:CC:A8": "Espressif (IoT)",
    "AC:BC:32": "Apple", "A4:83:E7": "Apple", "F0:18:98": "Apple",
    "3C:15:C2": "Apple", "DC:A9:04": "Apple", "F4:F1:5A": "Apple",
    "88:66:5A": "Apple", "A8:66:7F": "Apple", "6C:40:08": "Apple",
    "FC:FC:48": "Apple", "F0:99:BF": "Apple",
    "FC:65:DE": "Amazon", "68:37:E9": "Amazon", "44:65:0D": "Amazon",
    "F0:27:2D": "Amazon", "50:DC:E7": "Amazon", "0C:47:C9": "Amazon",
    "34:D2:70": "Amazon", "A0:02:DC": "Amazon",
    "50:32:37": "Samsung", "8C:77:12": "Samsung", "5C:0A:5B": "Samsung",
    "C8:7E:75": "Samsung", "E8:50:8B": "Samsung", "34:23:BA": "Samsung",
    "B0:6F:E0": "Samsung",
    "00:04:4B": "NVIDIA", "48:B0:2D": "NVIDIA",
    "D0:52:A8": "SmartThings", "24:FD:5B": "SmartThings",
    "B0:C5:54": "D-Link", "C0:56:27": "Belkin/Wemo",
    "50:C7:BF": "TP-Link", "AC:84:C6": "TP-Link", "60:A4:B7": "TP-Link",
    "EC:08:6B": "TP-Link", "00:0C:43": "Ralink/TP-Link",
    "B8:27:EB0": "Raspberry Pi",
    "94:9F:3E": "Sonos", "48:A6:B8": "Sonos", "5C:AA:FD": "Sonos",
    "DC:56:E7": "Roku", "CC:6D:A0": "Roku", "B8:3E:59": "Roku", "AC:3A:7A": "Roku",
    "00:0E:58": "Sonos", "B4:FB:E4": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "74:AC:B9": "Ubiquiti", "78:8A:20": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
    "18:B4:30": "Nest", "64:16:66": "Nest",
    "00:1D:C9": "GainSpan/IoT", "B0:4E:26": "TP-Link",
}


def _mac_info(mac: str) -> tuple[str, bool]:
    """Return (vendor, is_randomized) for a MAC. Randomized (locally-administered)
    MACs are what modern phones/laptops use for privacy — they have no real vendor."""
    if not mac:
        return ("", False)
    parts = mac.lower().split(":")
    try:
        first = int(parts[0], 16)
    except Exception:
        return ("", False)
    if first & 0x02:                    # locally-administered = randomized/private
        return ("private (randomized)", True)
    oui = ":".join(parts[:3]).upper()
    return (_OUI.get(oui, ""), False)


def _skip_mac(mac: str) -> bool:
    """Broadcast / multicast / null MACs aren't real hosts."""
    m = (mac or "").lower()
    return m.startswith(("ff:ff:ff", "00:00:00", "01:00:5e", "33:33"))


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def _ping(ip: str) -> bool:
    cmd = (["ping", "-n", "1", "-w", "600", ip] if os.name == "nt"
           else ["ping", "-c", "1", "-W", "1", ip])
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=3, creationflags=_FLAGS)
        return r.returncode == 0
    except Exception:
        return False


def _arp_table() -> dict:
    out = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                           timeout=6, creationflags=_FLAGS)
        for line in r.stdout.splitlines():
            ipm = _IP.search(line)
            macm = _MAC.search(line)
            if ipm and macm:
                out[ipm.group(1)] = macm.group(1).replace("-", ":").lower()
    except Exception:
        pass
    return out


def _rdns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _save_hosts(hosts, subnet, self_ip, gw):
    try:
        _HOSTS.write_text(json.dumps({"hosts": hosts, "subnet": subnet,
                                      "self": self_ip, "gateway": gw}))
    except Exception:
        pass


def get_hosts() -> dict:
    """Last discovery result (for cross-referencing IPs elsewhere)."""
    try:
        return json.loads(_HOSTS.read_text())
    except Exception:
        return {"hosts": [], "subnet": "", "self": "", "gateway": ""}


def discover(cb=None, hint: str | None = None) -> dict:
    def emit(t):
        if cb:
            cb(t)

    base_ip = local_ip()
    if hint:
        h = re.sub(r"/\d+$", "", str(hint)).strip()
        if _PRIV.match(h):
            base_ip = h
    if not _PRIV.match(base_ip):
        emit("[RODE] No private LAN detected on this machine — are you on a local network?\n")
        return {"hosts": [], "subnet": "", "self": base_ip}

    net = ipaddress.ip_network(base_ip + "/24", strict=False)
    base = str(net.network_address).rsplit(".", 1)[0]
    self_ip = local_ip()
    gw = base + ".1"
    emit(f"[RODE] Sweeping {base}.0/24 (this machine: {self_ip}) — pinging 254 hosts…\n")

    candidates = [str(h) for h in net.hosts()]      # already excludes .0 and .255
    alive = set()
    with ThreadPoolExecutor(max_workers=64) as ex:
        for host, ok in zip(candidates, ex.map(_ping, candidates)):
            if ok:
                alive.add(host)
    arp = _arp_table()
    for aip in arp:
        if aip.startswith(base + ".") and not _skip_mac(arp[aip]):
            last = aip.rsplit(".", 1)[-1]
            if last not in ("0", "255"):
                alive.add(aip)
    alive.add(self_ip)
    alive = {ip for ip in alive if ip.rsplit(".", 1)[-1] not in ("0", "255")}

    ordered = sorted(alive, key=lambda x: tuple(int(o) for o in x.split(".")))
    with ThreadPoolExecutor(max_workers=32) as ex:
        names = dict(zip(ordered, ex.map(_rdns, ordered)))

    hosts = []
    for ip in ordered:
        mac = arp.get(ip, "")
        if _skip_mac(mac):
            continue
        role = "self" if ip == self_ip else ("gateway" if ip == gw else "device")
        vendor, _rand = _mac_info(mac)
        row = {"ip": ip, "mac": mac, "hostname": names.get(ip, ""),
               "role": role, "vendor": vendor}
        hosts.append(row)
        emit(f"[HOST] {ip} :: {row['hostname'] or '-'} :: {mac or '-'} :: {role} :: {vendor or '-'}\n")

    subnet = f"{base}.0/24"
    _save_hosts(hosts, subnet, self_ip, gw)
    emit(f"[RODE] Found {len(hosts)} live host(s) on {subnet} (broadcast/multicast filtered out).\n")
    return {"hosts": hosts, "subnet": subnet, "self": self_ip, "gateway": gw}
