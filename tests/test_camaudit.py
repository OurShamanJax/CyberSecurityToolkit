"""Tests for the Camera & IoT audit — proves it stays scope-locked to your own
network / own public IP, classifies devices sensibly, and never mixes sample data
into real results."""
import pytest

from backend import camaudit as ca


# ── scope lock ────────────────────────────────────────────────────────────
def test_is_private_matches_rfc1918():
    for ip in ("10.0.0.5", "192.168.1.64", "172.16.9.9", "127.0.0.1"):
        assert ca.is_private(ip) is True
    for ip in ("8.8.8.8", "203.0.113.5", "1.1.1.1", "172.32.0.1"):
        assert ca.is_private(ip) is False


def test_scan_lan_refuses_public_hint():
    r = ca.scan_lan(hint="8.8.8.8")
    assert r["ok"] is False and "private" in r["error"].lower()


def test_scan_lan_refuses_public_discovered_subnet():
    def fake_discover():
        return {"subnet": "203.0.113.0/24", "hosts": [{"ip": "203.0.113.5"}]}
    r = ca.scan_lan(discover=fake_discover, probe=lambda ip: {"open": [], "http": {}})
    assert r["ok"] is False


def test_scan_lan_drops_nonprivate_hosts():
    def fake_discover():
        return {"subnet": "192.168.1.0/24",
                "hosts": [{"ip": "192.168.1.10", "mac": ""}, {"ip": "8.8.8.8", "mac": ""}]}
    r = ca.scan_lan(discover=fake_discover, probe=lambda ip: {"open": [], "http": {}})
    assert r["ok"] is True
    ips = [d["ip"] for d in r["devices"]]
    assert "192.168.1.10" in ips and "8.8.8.8" not in ips


# ── classification / findings ─────────────────────────────────────────────
def test_camera_vendor_from_oui():
    assert ca.camera_vendor("44:19:B6:12:34:56") == "Hikvision"
    assert ca.camera_vendor("3C:EF:8C:AA:BB:CC") == "Dahua"
    assert ca.camera_vendor("AA:BB:CC:DD:EE:FF") == ""


def test_open_rtsp_flags_camera_high():
    host = {"ip": "192.168.1.64", "mac": "44:19:B6:00:00:00", "role": "device"}
    dev = ca.assess(host, {"open": [554], "http": {}})
    assert dev["is_camera"] is True
    assert any(f["severity"] == "high" and "RTSP" in f["title"] for f in dev["findings"])


def test_no_auth_web_ui_is_critical():
    host = {"ip": "192.168.1.64", "mac": "44:19:B6:00:00:00", "role": "device"}
    dev = ca.assess(host, {"open": [80], "http": {80: {"status": 200, "auth_required": False}}})
    assert dev["worst"] == "critical"
    assert any("NO login" in f["title"] for f in dev["findings"])


def test_telnet_is_critical():
    host = {"ip": "192.168.1.108", "mac": "3C:EF:8C:00:00:00", "role": "device"}
    dev = ca.assess(host, {"open": [23], "http": {}})
    assert any(f["severity"] == "critical" and "Telnet" in f["title"] for f in dev["findings"])


def test_login_present_is_only_medium():
    host = {"ip": "192.168.1.7", "mac": "2C:AA:8E:00:00:00", "role": "device"}
    dev = ca.assess(host, {"open": [80], "http": {80: {"status": 401, "auth_required": True}}})
    sevs = {f["severity"] for f in dev["findings"]}
    assert "critical" not in sevs and "medium" in sevs


def test_findings_carry_fix_checklist():
    host = {"ip": "192.168.1.64", "mac": "44:19:B6:00:00:00", "role": "device"}
    dev = ca.assess(host, {"open": [554], "http": {}})
    assert all(f["fixes"] for f in dev["findings"])


# ── exposure check: own IP only ───────────────────────────────────────────
def test_exposure_uses_own_ip_and_flags_risky_ports():
    r = ca.check_exposure(my_ip=lambda: "203.0.113.9",
                          lookup=lambda ip: {"ok": True, "ports": [554, 8080, 443]})
    assert r["ok"] is True and r["ip"] == "203.0.113.9"
    assert 554 in r["risky_ports"] and r["clean"] is False
    assert any(f["port"] == 554 for f in r["findings"])


def test_exposure_clean_when_no_risky_ports():
    r = ca.check_exposure(my_ip=lambda: "203.0.113.9",
                          lookup=lambda ip: {"ok": True, "ports": []})
    assert r["clean"] is True and r["findings"] == []


def test_exposure_takes_no_target_argument():
    import inspect
    params = inspect.signature(ca.check_exposure).parameters
    # only keyword-only injectables; no positional 'ip'/'target' the UI could pass
    assert "ip" not in params and "target" not in params


# ── sample audit ──────────────────────────────────────────────────────────
def test_sample_is_flagged_and_populated():
    r = ca.sample_audit()
    assert r["ok"] is True and r["is_sample"] is True
    assert r["camera_count"] >= 2 and len(r["findings"]) >= 3


def test_real_scan_is_not_sample():
    def fake_discover():
        return {"subnet": "192.168.1.0/24", "hosts": []}
    r = ca.scan_lan(discover=fake_discover, probe=lambda ip: {"open": [], "http": {}})
    assert r["is_sample"] is False


# ── disclosure template: responsible + non-accusatory ─────────────────────
def test_disclosure_template_is_responsible():
    t = ca.disclosure_template(brand="a Hikvision camera", ip="203.0.113.10")
    assert "did not log in" in t.lower()
    assert "203.0.113.10" in t
    for word in ("hack", "exploit", "breach"):
        assert word not in t.lower()
