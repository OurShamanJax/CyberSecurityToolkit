"""Live packet capture via tshark (the CLI behind Wireshark).

Streams line-buffered packets and runs cheap, explainable heuristic detectors.
Real capture needs tshark installed + capture privileges (admin/root, Npcap on
Windows); when unavailable the UI falls back to a clearly-labelled simulation.
"""
import os, re, glob, shutil, subprocess, math
from collections import Counter

FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
          "_ws.col.Protocol", "frame.len", "tcp.dstport", "dns.qry.name", "_ws.col.Info"]


def tshark_path():
    """Find tshark.exe even when Wireshark isn't on PATH (it usually isn't)."""
    p = shutil.which("tshark")
    if p:
        return p
    cands = []
    if os.name == "nt":
        for env in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            base = os.environ.get(env)
            if base:
                cands.append(os.path.join(base, "Wireshark", "tshark.exe"))
        la = os.environ.get("LOCALAPPDATA")
        if la:
            cands.append(os.path.join(la, "Programs", "Wireshark", "tshark.exe"))
            cands += glob.glob(os.path.join(la, "Microsoft", "WinGet", "Packages",
                                            "WiresharkFoundation.Wireshark*", "**", "tshark.exe"), recursive=True)
    else:
        cands += ["/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark",
                  "/Applications/Wireshark.app/Contents/MacOS/tshark"]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def available() -> bool:
    return tshark_path() is not None


def list_interfaces():
    tp = tshark_path()
    if not tp:
        return []
    try:
        out = subprocess.run([tp, "-D"], capture_output=True, text=True, timeout=8).stdout
        res = []
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            m = re.match(r'(\d+)\.\s+(.*)', ln)   # "1. \Device\NPF_{..} (Wi-Fi)"
            if m:
                num, rest = m.group(1), m.group(2)
                fm = re.search(r'\(([^)]+)\)\s*$', rest)   # friendly name in parens
                res.append({"id": num, "label": fm.group(1) if fm else rest})
            else:
                res.append({"id": ln, "label": ln})
        return res
    except Exception:
        return []


def build_cmd(iface: str):
    cmd = [tshark_path(), "-l", "-n", "-i", iface or "1", "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "occurrence=f"]
    return cmd


def parse_line(line: str):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(FIELDS):
        parts += [""] * (len(FIELDS) - len(parts))
    d = dict(zip(FIELDS, parts))
    if not (d["ip.src"] or d["ip.dst"] or d["_ws.col.Protocol"]):
        return None
    return {"num": d["frame.number"], "t": d["frame.time_relative"][:8],
            "src": d["ip.src"], "dst": d["ip.dst"], "proto": d["_ws.col.Protocol"],
            "len": d["frame.len"], "dstport": d["tcp.dstport"], "dns": d["dns.qry.name"],
            "info": d["_ws.col.Info"][:90]}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s); n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


class Detector:
    """Explainable heuristics — not a full IDS, but honest and teachable."""
    def __init__(self):
        self.ports = {}

    def check(self, pkt: dict):
        alerts = []
        src, dport = pkt.get("src"), pkt.get("dstport")
        if src and dport:
            seen = self.ports.setdefault(src, set())
            seen.add(dport)
            if len(seen) in (16, 30, 60):  # fire once per threshold
                alerts.append({"k": "Port scan", "why": f"{src} contacted {len(seen)} distinct ports"})
        q = pkt.get("dns")
        if q and (len(q) > 50 or _entropy(q) > 3.9):
            alerts.append({"k": "DNS anomaly", "why": f"long/high-entropy lookup: {q[:40]}"})
        return alerts
