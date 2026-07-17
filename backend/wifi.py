"""Read-only WiFi access-point discovery — netsh (Windows) / nmcli (Linux).

No monitor mode or special adapter needed; this just lists what your normal
adapter can already see. The deeper aircrack-ng capabilities come later and need
special hardware (documented on the page).
"""
import platform, subprocess, re


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=25).stdout


def parse_netsh(out: str):
    aps, cur = [], None
    for line in out.splitlines():
        m = re.match(r'\s*SSID\s+\d+\s*:\s*(.*)', line)
        if m:
            cur = {"ssid": m.group(1).strip() or "(hidden)", "auth": "", "bssids": []}
            aps.append(cur); continue
        if cur is None:
            continue
        a = re.match(r'\s*Authentication\s*:\s*(.*)', line)
        if a: cur["auth"] = a.group(1).strip()
        b = re.match(r'\s*BSSID\s+\d+\s*:\s*(.*)', line)
        if b: cur["bssids"].append({"bssid": b.group(1).strip(), "signal": "", "channel": ""})
        s = re.match(r'\s*Signal\s*:\s*(.*)', line)
        if s and cur["bssids"]: cur["bssids"][-1]["signal"] = s.group(1).strip()
        c = re.match(r'\s*Channel\s*:\s*(.*)', line)
        if c and cur["bssids"]: cur["bssids"][-1]["channel"] = c.group(1).strip()
    rows = []
    for ap in aps:
        if ap["bssids"]:
            for b in ap["bssids"]:
                rows.append({"ssid": ap["ssid"], "auth": ap["auth"], **b})
        else:
            rows.append({"ssid": ap["ssid"], "auth": ap["auth"], "bssid": "", "signal": "", "channel": ""})
    return rows


def parse_nmcli(out: str):
    rows = []
    for line in out.strip().splitlines():
        p = line.split(':')
        if len(p) >= 4:
            rows.append({"ssid": p[0] or "(hidden)", "bssid": p[1], "signal": p[2] + "%", "auth": p[3], "channel": ""})
    return rows


def scan() -> dict:
    sysname = platform.system()
    try:
        if sysname == "Windows":
            return {"available": True, "os": "Windows", "aps": parse_netsh(_run(["netsh", "wlan", "show", "networks", "mode=bssid"]))}
        try:
            return {"available": True, "os": sysname, "aps": parse_nmcli(_run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi"]))}
        except FileNotFoundError:
            return {"available": False, "os": sysname, "aps": [],
                    "reason": "No WiFi scanner (nmcli) here. Run on a host with a WiFi adapter; on Linux install NetworkManager."}
    except Exception as e:
        return {"available": False, "os": sysname, "aps": [], "reason": str(e)[:140]}


def connected():
    """The network you're currently on (SSID/BSSID) + its gateway IP."""
    info = {"ssid": None, "bssid": None, "gateway": gateway()}
    try:
        if platform.system() == "Windows":
            out = _run(["netsh", "wlan", "show", "interfaces"])
            m = re.search(r'^\s*SSID\s*:\s*(.+)$', out, re.M)
            b = re.search(r'^\s*BSSID\s*:\s*(.+)$', out, re.M)
            info["ssid"] = m.group(1).strip() if m else None
            info["bssid"] = b.group(1).strip() if b else None
    except Exception:
        pass
    return info


def gateway():
    try:
        if platform.system() == "Windows":
            m = re.search(r'Default Gateway[ .]*:\s*([\d.]+)', _run(["ipconfig"]))
        else:
            m = re.search(r'default via ([\d.]+)', _run(["ip", "route"]))
        return m.group(1) if m else None
    except Exception:
        return None
