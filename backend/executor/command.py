"""
Command builder - turns a tool spec + target into a safe argument LIST.

A list is handed straight to the OS with shell=False, so there is no shell to
trick - this structurally removes command-injection bugs.

Docker networking (RODE_DOCKER_NETWORK env):
  * "host"  (DEFAULT, what v2.3 used): `--network host`, target passed literally.
            The container shares the host's network namespace, so 127.0.0.1:3000
            reaches a service on the host. Works on Linux and Docker Desktop's
            WSL2 backend - this is the proven default.
  * "bridge": default bridge + `--add-host=host.docker.internal:host-gateway`,
            and loopback targets are rewritten to host.docker.internal. Use this
            only if `--network host` does not reach your host (some Docker
            Desktop Hyper-V setups).
"""
from __future__ import annotations

import os
import re


class ExecModeError(Exception):
    pass


_LOOPBACK_RE = re.compile(r'(?<![\w.])(127\.0\.0\.1|localhost|0\.0\.0\.0)(?![\w.])', re.I)


def _network_mode() -> str:
    return os.getenv("RODE_DOCKER_NETWORK", "host").strip().lower()


def _docker_prefix(container_name: str | None = None) -> list[str]:
    base = ["docker", "run", "--rm"]
    if container_name:
        base += ["--name", container_name]
    # Allocate a pseudo-TTY so line-buffered tools (Nikto, Perl/Ruby tools) stream
    # output live instead of dumping it all at the end. Disable with RODE_DOCKER_TTY=0.
    if os.getenv("RODE_DOCKER_TTY", "1").strip() != "0":
        base.append("-t")
    if _network_mode() == "bridge":
        return base + ["--add-host=host.docker.internal:host-gateway"]
    return base + ["--network", "host"]


def rewrite_loopback_for_docker(target: str) -> str:
    """In bridge mode, rewrite loopback to host.docker.internal. In host mode
    (default) leave the target untouched - the shared host network reaches it."""
    if _network_mode() == "bridge":
        return _LOOPBACK_RE.sub("host.docker.internal", target or "", count=1)
    return target


def _substitute(parts: list[str], subs: dict[str, str]) -> list[str]:
    out = []
    for part in parts:
        for key, val in subs.items():
            part = part.replace(key, val)
        out.append(part)
    return out


def build_command(tool: dict, mode: str, target: str,
                  wordlist: str | None = None,
                  docker_mounts: list[str] | None = None,
                  container_name: str | None = None) -> list[str]:
    """Build the argv list for `tool` in the given exec mode."""
    spec = (tool.get("exec") or {}).get(mode)
    if not spec:
        raise ExecModeError(f"Tool '{tool.get('id')}' has no '{mode}' exec mode")

    if mode == "docker":
        target = rewrite_loopback_for_docker(target)
    subs = {"{target}": target, "{wordlist}": wordlist or ""}

    if mode == "docker":
        mounts: list[str] = []
        for m in (docker_mounts or []):
            mounts += ["-v", m]
        template = [*mounts, spec["image"], *spec.get("args", [])]
        return [*_docker_prefix(container_name), *_substitute(template, subs)]
    if mode == "local":
        return _substitute(list(spec["cmd"]), subs)
    if mode == "python":
        return []
    raise ExecModeError(f"Unknown exec mode '{mode}'")
