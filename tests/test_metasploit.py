"""Tests for the Metasploit wrapper - validation guardrails + safe argv building.

These assert the *safety properties*: only allowlisted payloads/formats/encoders,
range-checked ports, public-LHOST warnings, and shell-free argv lists.
"""
from backend.metasploit import (
    PAYLOADS, FORMATS, ENCODERS, validate_build, build_argv, display_command,
)

VALID = {
    "payload": "linux/x64/meterpreter/reverse_tcp",
    "lhost": "192.168.1.50", "lport": 4444,
    "format": "elf", "encoder": "none", "iterations": 0,
}


def test_valid_lab_build_passes():
    v = validate_build(VALID)
    assert v["ok"] and not v["errors"]


def test_display_command_shape():
    cmd = display_command(VALID)
    assert cmd.startswith("msfvenom -p linux/x64/meterpreter/reverse_tcp")
    assert "LHOST=192.168.1.50" in cmd and "LPORT=4444" in cmd and "-f elf" in cmd


def test_public_lhost_warns_but_not_blocked():
    v = validate_build({**VALID, "lhost": "8.8.8.8"})
    assert v["ok"]
    assert any("NOT a private" in w for w in v["warnings"])


def test_unknown_payload_rejected():
    v = validate_build({**VALID, "payload": "evil/custom/thing"})
    assert not v["ok"]


def test_port_range_enforced():
    assert not validate_build({**VALID, "lport": 99999})["ok"]
    assert not validate_build({**VALID, "lport": 0})["ok"]


def test_format_and_encoder_allowlisted():
    assert not validate_build({**VALID, "format": "; rm -rf /"})["ok"]
    assert not validate_build({**VALID, "encoder": "$(evil)"})["ok"]


def test_iterations_capped():
    assert not validate_build({**VALID, "iterations": 999})["ok"]


def test_encoder_warns_about_av():
    v = validate_build({**VALID, "encoder": "x86/shikata_ga_nai", "iterations": 3})
    assert any("evade" in w for w in v["warnings"])


def test_bind_payload_needs_no_lhost():
    v = validate_build({"payload": "windows/x64/meterpreter/bind_tcp",
                        "lport": 4444, "format": "exe",
                        "encoder": "none", "iterations": 0})
    assert v["ok"]


def test_argv_is_shell_free_list():
    argv = build_argv(VALID, "local", out_container_path=None)
    assert isinstance(argv, list)
    assert argv[0] == "msfvenom"
    # no shell metacharacters smuggled into a single arg
    assert all(";" not in a and "|" not in a and "&" not in a for a in argv)


def test_docker_argv_mounts_out_dir():
    opts = {**VALID, "_host_out_dir": "/home/u/ws/payloads"}
    argv = build_argv(opts, "docker", out_container_path="/out/p.elf")
    assert argv[0] == "docker" and "run" in argv and "--rm" in argv
    assert "-v" in argv and "/out/p.elf" in argv
    assert argv[-2] == "-o"


def test_catalog_wellformed():
    assert len(PAYLOADS) >= 8
    for p in PAYLOADS:
        assert p["id"] and p["severity"] in {"low", "medium", "high", "critical"}
        assert 1 <= p["loudness"] <= 5
        assert p["connect"] in {"reverse", "bind"}
    assert "elf" in FORMATS and "exe" in FORMATS
    assert "none" in ENCODERS
