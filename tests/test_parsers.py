"""Tests for the normalization parsers."""
from backend.parsers.nmap import NmapParser
from backend.parsers.generic import GenericParser

NMAP_SAMPLE = """
Starting Nmap scan...
22/tcp  open  ssh     OpenSSH 8.0
80/tcp  open  http    Apache httpd 2.4.41
443/tcp closed https
"""


def test_nmap_extracts_only_open_ports():
    result = NmapParser().parse(NMAP_SAMPLE, "10.0.0.1")
    services = [e for e in result.entities if e.type == "service"]
    assert len(services) == 2                      # ssh + http, not the closed one
    values = {s.value for s in services}
    assert "10.0.0.1:22/tcp" in values
    assert "10.0.0.1:80/tcp" in values
    assert len(result.relationships) == 2


def test_nmap_captures_version_metadata():
    result = NmapParser().parse(NMAP_SAMPLE, "10.0.0.1")
    http = next(e for e in result.entities if e.value.endswith("80/tcp"))
    assert "Apache" in http.metadata["version"]


def test_generic_extracts_mixed_artifacts():
    text = "contact admin@site.com or visit https://site.com from 8.8.8.8"
    result = GenericParser().parse(text, "site.com")
    types = {e.type for e in result.entities}
    assert {"email", "url", "ip"}.issubset(types)
