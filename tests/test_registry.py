"""Tests that tools.yaml is valid and internally consistent."""
from backend.parsers.registry import get_parser
from backend.parsers.generic import GenericParser
from backend.safety import NOISE_ORDER
from backend.tools.registry import load_tools, list_tools, get_tool
from backend.executor.command import build_command


def test_tools_yaml_loads():
    tools = load_tools()
    assert tools, "tools.yaml produced no tools"


def test_every_tool_is_well_formed():
    for tool in load_tools().values():
        assert tool["noise"] in NOISE_ORDER
        assert tool["category"] in {"recon", "exploit", "defensive", "analysis"}
        assert tool["exec"], f"{tool['id']} has no exec modes"


def test_every_parser_reference_resolves():
    # A tool naming a missing parser must still resolve (to generic) — never crash.
    for tool in load_tools().values():
        assert get_parser(tool["parser"]) is not None


def test_get_and_list():
    assert get_tool("nmap")["name"] == "Nmap"
    assert get_tool("does-not-exist") is None
    assert all(t["category"] == "recon" for t in list_tools("recon"))


def test_build_command_substitutes_target_and_is_a_list():
    cmd = build_command(get_tool("nmap"), "docker", "scanme.example.com")
    assert isinstance(cmd, list)
    assert "scanme.example.com" in cmd          # remote target passes through
    assert "{target}" not in " ".join(cmd)
    assert cmd[:3] == ["docker", "run", "--rm"]


def test_docker_default_uses_host_network_and_literal_target(monkeypatch):
    # DEFAULT (v2.3 behaviour): --network host, target passed literally
    monkeypatch.delenv("RODE_DOCKER_NETWORK", raising=False)
    cmd = " ".join(build_command(get_tool("nikto"), "docker", "http://127.0.0.1:3000"))
    assert "--network host" in cmd
    assert "http://127.0.0.1:3000" in cmd


def test_docker_bridge_mode_rewrites_loopback(monkeypatch):
    # opt-in bridge mode for Docker Desktop Hyper-V setups
    monkeypatch.setenv("RODE_DOCKER_NETWORK", "bridge")
    cmd = " ".join(build_command(get_tool("nikto"), "docker", "http://127.0.0.1:3000"))
    assert "host.docker.internal:3000" in cmd
    assert "--add-host=host.docker.internal:host-gateway" in cmd


def test_unknown_parser_falls_back_to_generic():
    assert isinstance(get_parser("no-such-parser"), GenericParser)
