"""
Execution engine - runs a tool and streams its output line by line.

Resolution order for a tool's exec modes:
  1. python  (built-in, always available)
  2. local   (binary on PATH)
  3. docker  (if the daemon is running)

Blocking subprocesses run in a worker thread (asyncio.to_thread) so the
WebSocket stays responsive; each line is pushed to the async callback.
Everything is a fixed argument LIST - never a shell string.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import time
from typing import Callable, Optional

from ..config import settings
from ..logger import get_logger
from .command import build_command

log = get_logger("runner")

_ANSI = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_active: dict[int, subprocess.Popen] = {}
_containers: dict[int, str] = {}
_docker_ok: Optional[bool] = None
_docker_ts: float = 0.0


def docker_available(force: bool = False) -> bool:
    """Is the Docker daemon reachable? Cached for a few seconds so listing 20
    tools doesn't shell out 20 times, but re-checked often enough that starting
    Docker after launch is picked up (no restart needed). force=True re-checks now."""
    global _docker_ok, _docker_ts
    now = time.time()
    if force or _docker_ok is None or (now - _docker_ts) > 5:
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            r = subprocess.run(["docker", "info"], capture_output=True,
                               timeout=8, creationflags=flags)
            _docker_ok = r.returncode == 0
        except Exception:
            _docker_ok = False
        _docker_ts = now
    return _docker_ok


def resolve_mode(tool: dict) -> tuple[Optional[str], str]:
    """Choose an exec mode. Returns (mode, human_reason)."""
    modes = tool.get("exec", {})
    if "python" in modes:
        return "python", "built-in"
    if "local" in modes:
        binary = modes["local"]["cmd"][0]
        if shutil.which(binary):
            return "local", f"local binary '{binary}'"
    if "docker" in modes:
        if docker_available():
            return "docker", f"docker image {modes['docker']['image']}"
        return None, "needs Docker (daemon not running)"
    if "local" in modes:
        return None, f"'{modes['local']['cmd'][0]}' not installed and no Docker image"
    return None, "no runnable exec mode"


def tool_status(tool: dict) -> dict:
    mode, reason = resolve_mode(tool)
    return {"runnable": mode is not None, "mode": mode, "reason": reason}


def _run_blocking(cmd, emit, loop, run_id):
    log.info("exec: %s", " ".join(cmd))
    code = 1
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            bufsize=1, shell=False, creationflags=flags,
        )
        if run_id is not None:
            _active[run_id] = proc
        for line in iter(proc.stdout.readline, ""):
            asyncio.run_coroutine_threadsafe(emit(_ANSI.sub("", line).replace("\r", "")), loop)
        proc.wait()
        code = proc.returncode or 0
    except FileNotFoundError:
        asyncio.run_coroutine_threadsafe(emit(f"[RODE ERROR] Not found: {cmd[0]}\n"), loop)
        code = 127
    except Exception as e:
        asyncio.run_coroutine_threadsafe(emit(f"[RODE ERROR] {type(e).__name__}: {e}\n"), loop)
    finally:
        if run_id is not None:
            _active.pop(run_id, None)
    return code


async def run_tool(tool, target, callback, run_id=None, wordlist=None):
    """Run `tool` against `target`, streaming output through `callback`."""
    loop = asyncio.get_event_loop()
    mode, reason = resolve_mode(tool)
    started = time.time()
    parts = []

    async def emit(text):
        parts.append(text)
        await callback(text)

    if mode is None:
        await emit(f"[RODE] Cannot run {tool['id']}: {reason}.\n")
        return {"raw": "".join(parts), "exit_code": 1, "duration_ms": 0, "mode": "unavailable"}

    if mode == "python":
        from .python_tools import run_python_tool
        handler = tool["exec"]["python"]["handler"]
        result = await run_python_tool(handler, target, emit)
        return {"raw": result.get("raw", "".join(parts)),
                "exit_code": result.get("exit_code", 0),
                "duration_ms": int((time.time() - started) * 1000), "mode": "python"}

    docker_spec = json.dumps(tool.get("exec", {}).get("docker", {}))
    mounts: list[str] = []
    target_for_cmd = target

    # Path-input tools (e.g. Trivy): mount the user's file/dir into /scan (read-only).
    if mode == "docker" and tool.get("input_type") == "path":
        host = os.path.abspath(target)
        if not os.path.exists(host):
            await emit(f"[RODE] Path not found on disk: {target}\n")
            return {"raw": "".join(parts), "exit_code": 1,
                    "duration_ms": int((time.time() - started) * 1000), "mode": mode}
        if os.path.isdir(host):
            mounts.append(f"{host.replace(chr(92), '/')}:/scan:ro")
            target_for_cmd = "/scan"
        else:
            mounts.append(f"{os.path.dirname(host).replace(chr(92), '/')}:/scan:ro")
            target_for_cmd = "/scan/" + os.path.basename(host)

    # Wordlist mount only for tools that actually reference {wordlist}.
    wl_for_cmd = None
    if "{wordlist}" in docker_spec:
        wl = wordlist or (str(settings.WORDLISTS_DIR / "common.txt")
                          if (settings.WORDLISTS_DIR / "common.txt").exists() else None)
        if mode == "docker" and wl:
            host_dir = os.path.dirname(os.path.abspath(wl)).replace(chr(92), "/")
            mounts.append(f"{host_dir}:/wordlists:ro")
            wl_for_cmd = f"/wordlists/{os.path.basename(wl)}"
        else:
            wl_for_cmd = wl

    container_name = f"rode-run-{run_id}" if (mode == "docker" and run_id is not None) else None
    if container_name:
        _containers[run_id] = container_name
    cmd = build_command(tool, mode, target_for_cmd, wl_for_cmd,
                        docker_mounts=mounts or None, container_name=container_name)

    # Command echo as a tidy meta line (frontend shows it only in Learn mode).
    # Sent via callback (not emit) so it never lands in the saved/parsed output.
    await callback(f"[CMD] {' '.join(cmd)}\n")

    code = await asyncio.to_thread(_run_blocking, cmd, emit, loop, run_id)
    if run_id is not None:
        _containers.pop(run_id, None)
    dur_ms = int((time.time() - started) * 1000)

    # A network tool that returns almost nothing, almost instantly, probably
    # could not reach the target from inside the container.
    body = "".join(parts)
    if (mode == "docker" and tool.get("input_type") in {"url", "domain", "ip", "host"}
            and tool.get("id") != "reachability" and dur_ms < 4000 and len(body) < 400):
        await callback("[RODE] Finished very fast with little output - the container may not "
                       "have reached the target. Try the Connectivity Test.\n")
    return {"raw": body, "exit_code": code, "duration_ms": dur_ms, "mode": mode}


def cancel(run_id: int) -> bool:
    """Stop a run for real: kill the client process AND the docker container it
    launched (killing the `docker run` client alone leaves the container scanning)."""
    ok = False
    name = _containers.pop(run_id, None)
    if name:
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            subprocess.run(["docker", "kill", name], capture_output=True,
                           timeout=8, creationflags=flags)
            ok = True
        except Exception:
            pass
    proc = _active.get(run_id)
    if proc:
        try:
            proc.kill()
            _active.pop(run_id, None)
            ok = True
        except Exception:
            pass
    return ok
