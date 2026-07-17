"""Tests for the safety layer — the guardrails that make this a *safe* lab."""
import pytest

from backend.safety import (
    ScopeError, SandboxError,
    normalize_target, target_in_scope, ensure_in_scope,
    safe_path, requires_confirmation,
)


# ── normalize_target ──────────────────────────────────────────────────────
def test_normalize_strips_scheme_path_port():
    assert normalize_target("https://Sub.Example.com:8443/login") == "sub.example.com"
    assert normalize_target("http://127.0.0.1:3000") == "127.0.0.1"


# ── scope ─────────────────────────────────────────────────────────────────
def test_localhost_aliases_match():
    assert target_in_scope("http://localhost:3000", ["127.0.0.1"]) is True

def test_wildcard_subdomain_in_scope():
    assert target_in_scope("api.example.com", ["example.com"]) is True

def test_cidr_range_in_scope():
    assert target_in_scope("192.168.1.50", ["192.168.1.0/24"]) is True
    assert target_in_scope("10.0.0.5", ["192.168.1.0/24"]) is False

def test_out_of_scope_rejected():
    assert target_in_scope("evil.com", ["example.com"]) is False

def test_empty_scope_denies_everything():
    assert target_in_scope("example.com", []) is False

def test_ensure_in_scope_raises():
    with pytest.raises(ScopeError):
        ensure_in_scope("evil.com", ["example.com"])
    ensure_in_scope("example.com", ["example.com"])  # should not raise


# ── file sandbox (blocks the v2 arbitrary-read bug) ───────────────────────
def test_safe_path_allows_inside(tmp_path):
    (tmp_path / "notes.txt").write_text("hi")
    assert safe_path("notes.txt", tmp_path).name == "notes.txt"

def test_safe_path_blocks_traversal(tmp_path):
    with pytest.raises(SandboxError):
        safe_path("../../etc/passwd", tmp_path)

def test_safe_path_blocks_absolute_outside(tmp_path):
    with pytest.raises(SandboxError):
        safe_path("/etc/passwd", tmp_path)


# ── noise gate ────────────────────────────────────────────────────────────
def test_confirmation_only_for_loud_and_up():
    assert requires_confirmation("silent") is False
    assert requires_confirmation("moderate") is False
    assert requires_confirmation("loud") is True
    assert requires_confirmation("aggressive") is True

def test_unknown_noise_fails_safe():
    assert requires_confirmation("???") is True


# ── loopback is always in scope (local-first lab) ─────────────────────────
def test_loopback_always_allowed_without_scope():
    assert target_in_scope("http://127.0.0.1:3000", []) is True
    assert target_in_scope("localhost", []) is True
    assert target_in_scope("http://localhost:3000/rest", []) is True

def test_remote_still_needs_scope():
    assert target_in_scope("192.168.1.50", []) is False
    assert target_in_scope("192.168.1.50", ["192.168.1.0/24"]) is True
