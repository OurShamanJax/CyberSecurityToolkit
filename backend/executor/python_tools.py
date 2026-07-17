"""
Built-in Python tools — run inside the process, no external binary needed.
These make the lab useful even with nothing installed and no Docker.

log_analyzer is sandboxed: it can ONLY read files inside the workspace folder
(safety.safe_path). This closes v2's arbitrary-file-read hole.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request

from ..config import settings
from ..safety import safe_path, SandboxError


async def run_python_tool(handler: str, target: str, cb) -> dict:
    handlers = {
        "cve_lookup": cve_lookup,
        "log_analyzer": log_analyzer,
        "hash_identifier": hash_identifier,
        "binary_inspector": binary_inspector,
        "exploit_search": exploit_search,
    }
    fn = handlers.get(handler)
    if not fn:
        await cb(f"[RODE] Unknown built-in tool: {handler}\n")
        return {"raw": "", "exit_code": 1}
    return await fn(target, cb)


async def cve_lookup(target: str, cb) -> dict:
    """Query the public NVD database for CVEs matching a software + version."""
    out = []

    async def emit(t):
        out.append(t)
        await cb(t)

    await emit(f"[RODE] CVE lookup for: {target}\n{'-' * 48}\n")
    keyword = urllib.parse.quote(" ".join(target.split()[:2]))
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={keyword}&resultsPerPage=15")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RODE-v4"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        await emit(f"Found {data.get('totalResults', 0)} CVEs (showing {len(vulns)})\n\n")
        for item in vulns:
            cve = item.get("cve", {})
            cid = cve.get("id", "?")
            desc = next((d["value"] for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")[:140]
            score, sev = "N/A", "UNKNOWN"
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in cve.get("metrics", {}):
                    m = cve["metrics"][k][0].get("cvssData", {})
                    score = m.get("baseScore", "N/A")
                    sev = m.get("baseSeverity", "UNKNOWN")
                    break
            await emit(f"[{sev}] {cid}  CVSS {score}\n   {desc}\n\n")
    except Exception as e:
        await emit(f"[ERROR] NVD request failed: {e}\n")
    return {"raw": "".join(out), "exit_code": 0}


async def log_analyzer(target: str, cb) -> dict:
    """Scan a log file (inside the workspace sandbox) for attack patterns."""
    out = []

    async def emit(t):
        out.append(t)
        await cb(t)

    await emit(f"[RODE] Log analyzer: {target}\n{'-' * 48}\n")
    try:
        path = safe_path(target, settings.WORKSPACE_DIR)
    except SandboxError as e:
        await emit(f"[BLOCKED] {e}\n")
        return {"raw": "".join(out), "exit_code": 1}
    if not path.exists():
        await emit(f"[ERROR] Not found in workspace: {target}\n"
                   f"Place the log file in: {settings.WORKSPACE_DIR}\n")
        return {"raw": "".join(out), "exit_code": 1}

    patterns = {
        "SQL injection": re.compile(r"union\s+select|or\s+1=1|drop\s+table|'--", re.I),
        "Path traversal": re.compile(r"\.\./|etc/passwd", re.I),
        "XSS": re.compile(r"<script|onerror=|javascript:", re.I),
        "Scanner": re.compile(r"nikto|sqlmap|nmap|gobuster|masscan", re.I),
    }
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ip_counts: dict = {}
    hits = 0
    for i, line in enumerate(path.read_text(errors="replace").splitlines()):
        m = ip_re.search(line)
        if m:
            ip_counts[m.group()] = ip_counts.get(m.group(), 0) + 1
        for name, rx in patterns.items():
            if rx.search(line):
                hits += 1
                await emit(f"  line {i + 1}: [{name}] {line.strip()[:90]}\n")
                break
    top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    await emit("\nTop IPs:\n" + "".join(f"  {c:5d}  {ip}\n" for ip, c in top))
    await emit(f"\n{hits} attack-pattern hit(s) total.\n")
    return {"raw": "".join(out), "exit_code": 0}


async def hash_identifier(target: str, cb) -> dict:
    """Identify a hash by length and try to crack it against common passwords."""
    out = []

    async def emit(t):
        out.append(t)
        await cb(t)

    h = target.strip().lower()
    types = {32: "MD5 / NTLM", 40: "SHA-1", 56: "SHA-224",
             64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
    await emit(f"[RODE] Hash identifier\n{'-' * 48}\n"
               f"Length: {len(h)} -> likely {types.get(len(h), 'unknown')}\n\n")
    common = ["password", "123456", "admin", "letmein", "qwerty", "welcome",
              "monkey", "dragon", "abc123", "iloveyou", "password1", "root"]
    for pw in common:
        for algo, fn in (("MD5", hashlib.md5), ("SHA-1", hashlib.sha1),
                         ("SHA-256", hashlib.sha256)):
            if fn(pw.encode()).hexdigest() == h:
                await emit(f"CRACKED: {algo}('{pw}')  ->  {pw}\n")
                return {"raw": "".join(out), "exit_code": 0}
    await emit("Not in the common-password list. Use hashcat/john for real cracking.\n")
    return {"raw": "".join(out), "exit_code": 0}


# Windows/Linux API names grouped by what they let a program DO.
_CAP_SIGS = {
    "Memory read/write & process injection (Cheat-Engine-like)":
        ["ReadProcessMemory", "WriteProcessMemory", "VirtualAllocEx", "VirtualProtectEx",
         "CreateRemoteThread", "NtWriteVirtualMemory", "OpenProcess", "SetThreadContext",
         "ptrace", "process_vm_writev"],
    "Anti-debugging / anti-cheat evasion":
        ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
         "OutputDebugString", "QueryPerformanceCounter", "NtSetInformationThread"],
    "Keylogging / input capture":
        ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow",
         "GetRawInputData"],
    "Networking":
        ["WSAStartup", "WSASocket", "InternetOpen", "InternetConnect", "URLDownloadToFile",
         "HttpSendRequest", "socket", "connect", "recv", "send", "getaddrinfo"],
    "Dynamic code loading":
        ["LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "dlopen", "dlsym"],
    "Persistence / autostart":
        ["CurrentVersion\\Run", "RegSetValue", "RegCreateKey", "schtasks", "CreateService"],
    "Cryptography":
        ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt", "EVP_EncryptInit"],
    "Process / command execution":
        ["CreateProcess", "ShellExecute", "WinExec", "system", "popen", "execve"],
    "Screen capture":
        ["BitBlt", "GetDC", "CreateCompatibleBitmap", "PrintWindow"],
}

_STR_RE = re.compile(rb'[\x20-\x7e]{5,}')
_WSTR_RE = re.compile(rb'(?:[\x20-\x7e]\x00){5,}')


async def binary_inspector(target, cb) -> dict:
    """Static look at a file/executable: type, capabilities, and interesting strings.

    Runs on the host (no Docker), reads the file directly, and reports what the
    program is CAPABLE of based on the API names and strings inside it. It never
    dumps raw file contents - only the analysis.
    """
    out = []

    async def emit(t):
        out.append(t)
        if cb:
            await cb(t)

    if not os.path.exists(target):
        await emit(f"[RODE] File not found: {target}\n")
        return {"raw": "".join(out), "exit_code": 1}
    if os.path.isdir(target):
        await emit(f"[RODE] That's a folder. Use the Trivy directory scanner for folders.\n")
        return {"raw": "".join(out), "exit_code": 1}

    name = os.path.basename(target)
    size = os.path.getsize(target)
    with open(target, "rb") as fh:
        data = fh.read(40 * 1024 * 1024)   # cap at 40 MB

    magic = "Unknown / data"
    if data[:2] == b"MZ":
        magic = "PE (Windows .exe / .dll)"
    elif data[:4] == b"\x7fELF":
        magic = "ELF (Linux executable)"
    elif data[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        magic = "Mach-O (macOS executable)"

    strings = {m.group().decode("latin-1") for m in _STR_RE.finditer(data)}
    strings |= {m.group().decode("utf-16-le", "ignore") for m in _WSTR_RE.finditer(data)}
    blob = "\n".join(strings)

    await emit(f"[RODE] Binary Inspector - {name}\n{'-'*52}\n")
    await emit(f"File type: {magic}\nSize: {size/1048576:.2f} MB   Strings extracted: {len(strings)}\n\n")
    await emit("CAPABILITIES DETECTED (what this program appears able to do):\n")

    found = False
    for group, apis in _CAP_SIGS.items():
        hits = sorted({a for a in apis
                       if re.search(r'(?i)(?<![A-Za-z0-9])' + re.escape(a) + r'(?![A-Za-z0-9])', blob)})
        if hits:
            found = True
            await emit(f"[CAP] {group} :: {', '.join(hits[:10])}\n")
    if not found:
        await emit("  (no notable capability signatures matched - may be packed/obfuscated or benign)\n")

    urls = sorted({s for s in strings if s.lower().startswith(("http://", "https://"))})[:20]
    if urls:
        await emit("\nURLs referenced (feed these into web recon):\n")
        for u in urls:
            await emit(f"  {u}\n")

    ips = sorted({m.group() for s in strings
                  for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s)}
                 - {"0.0.0.0", "127.0.0.1"})[:20]
    if ips:
        await emit("\nIP addresses referenced:\n")
        for ip in ips:
            await emit(f"  {ip}\n")

    await emit("\n[RODE] Note: capabilities are STATIC hints from the file's contents, not proof of behaviour.\n")
    return {"raw": "".join(out), "exit_code": 0}


async def exploit_search(target, cb) -> dict:
    """Search the PUBLIC Exploit-DB index for known exploits matching a product,
    version, or CVE. Downloads the free index once, then searches it offline.
    Returns references to public advisories - not exploit code."""
    out = []

    async def emit(t):
        out.append(t)
        if cb:
            await cb(t)

    term = (target or "").strip()
    if not term:
        await emit("[RODE] Give a product, version, or CVE (e.g. Apache 2.4.49 or CVE-2021-41773).\n")
        return {"raw": "".join(out), "exit_code": 1}
    await emit(f"[RODE] Exploit-DB search: {term}\n" + "-" * 48 + "\n")
    csv_path = settings.DATA_DIR / "exploitdb.csv"
    if not csv_path.exists() or csv_path.stat().st_size < 100000:
        await emit("[RODE] Fetching the public Exploit-DB index (one-time, ~a few MB)...\n")
        ok = False
        for url in (
            "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
            "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
        ):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "RODE-v4"})
                with urllib.request.urlopen(req, timeout=40) as r:
                    csv_path.write_bytes(r.read())
                ok = True
                break
            except Exception:
                continue
        if not ok:
            await emit("[ERROR] Could not download the Exploit-DB index (need internet).\n")
            return {"raw": "".join(out), "exit_code": 1}
    import csv as _csv
    t = term.lower()
    is_cve = t.startswith("cve-")
    matches = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in _csv.DictReader(fh):
                desc = row.get("description") or ""
                codes = row.get("codes") or ""
                hay = (desc + " " + codes).lower() if is_cve else desc.lower()
                if t in hay:
                    matches.append(row)
                    if len(matches) >= 60:
                        break
    except Exception as e:
        await emit(f"[ERROR] index read failed: {e}\n")
        return {"raw": "".join(out), "exit_code": 1}
    await emit(f"{len(matches)} matching public exploit(s):\n\n")
    for m in matches[:40]:
        eid = m.get("id", "?")
        desc = (m.get("description") or "")[:120]
        plat = m.get("platform", "?")
        typ = m.get("type", "?")
        cve = ";".join(c for c in (m.get("codes") or "").split(";") if c.upper().startswith("CVE"))[:60]
        tail = (" :: " + cve) if cve else ""
        await emit(f"[EXPLOIT] {eid} :: {desc} :: {plat}/{typ}{tail}\n")
        await emit(f"   https://www.exploit-db.com/exploits/{eid}\n")
    if not matches:
        await emit("No public exploits indexed for that term. Try the exact product + version, or a CVE id.\n")
    await emit("\n[RODE] References to PUBLIC exploits (Exploit-DB). Only use against systems you own or are authorized to test.\n")
    return {"raw": "".join(out), "exit_code": 0}
