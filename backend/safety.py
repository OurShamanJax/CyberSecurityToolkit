"""
Safety layer - the ethical + technical guardrails of the lab.

Pure standard-library Python so it is trivial to test and reason about:
  1. Is this target allowed to be scanned?   -> target_in_scope / ensure_in_scope
  2. Is this file path allowed to be read?    -> safe_path
  3. Does this tool need a confirmation click? -> requires_confirmation
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

NOISE_ORDER = ["silent", "whisper", "moderate", "loud", "aggressive"]
# Hostnames that all mean "this machine". Scanning your own box is always OK
# in a local-first lab, so these never require an explicit scope entry.
LOCAL_ALIASES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class ScopeError(Exception):
    """Raised when a target is not in the investigation's declared scope."""


class SandboxError(Exception):
    """Raised when a file path escapes the workspace sandbox."""


def normalize_target(target: str) -> str:
    """Reduce a user target to a bare host: strip scheme, path, and port."""
    t = (target or "").strip().lower()
    if "://" in t:
        parsed = urlparse(t)
        t = parsed.netloc or parsed.path
    t = t.split("/")[0].rstrip(":")
    if t.count(":") == 1:          # host:port -> host (IPv6 has >1 colon, left alone)
        t = t.split(":")[0]
    return t


def is_loopback(target: str) -> bool:
    """True if the target points at this machine (loopback)."""
    host = normalize_target(target)
    if host in LOCAL_ALIASES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _matches(host: str, entry: str) -> bool:
    entry = (entry or "").strip().lower()
    if "/" in entry:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    entry = normalize_target(entry)
    if entry in LOCAL_ALIASES and host in LOCAL_ALIASES:
        return True
    if host == entry:
        return True
    if host.endswith("." + entry):
        return True
    return False


def target_in_scope(target: str, scope_entries: list[str]) -> bool:
    """True if the target may be scanned.

    Loopback (your own machine) is ALWAYS allowed - no scope needed. Any other
    target must match a declared scope entry.
    """
    host = normalize_target(target)
    if not host:
        return False
    if is_loopback(target):
        return True
    if not scope_entries:
        return False
    return any(_matches(host, e) for e in scope_entries if e)


def ensure_in_scope(target: str, scope_entries: list[str]) -> None:
    """Raise ScopeError unless the target is allowed."""
    if not target_in_scope(target, scope_entries):
        raise ScopeError(
            f"'{target}' is a remote target that isn't in this investigation's scope. "
            f"Click the scope chip to add it. Allowed: {scope_entries or '(none)'}"
        )


def safe_path(user_path: str, workspace_dir) -> Path:
    """Resolve a path and guarantee it stays inside the workspace sandbox."""
    base = Path(workspace_dir).resolve()
    candidate = Path(user_path)
    resolved = (candidate if candidate.is_absolute() else base / candidate).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise SandboxError(
            f"Path '{user_path}' is outside the workspace sandbox ({base}). Refused."
        )
    return resolved


def requires_confirmation(noise: str, threshold: str = "loud") -> bool:
    """True if a tool at this noise level needs explicit confirmation (fail safe)."""
    try:
        return NOISE_ORDER.index(noise) >= NOISE_ORDER.index(threshold)
    except ValueError:
        return True
