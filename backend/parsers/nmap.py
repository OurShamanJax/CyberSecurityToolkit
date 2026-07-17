"""Nmap parser: extracts open ports/services as entities linked to the host."""
import re

from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

PORT_RE = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?')


class NmapParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("ip", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        for m in PORT_RE.finditer(raw or ""):
            port, proto, service, version = m.groups()
            value = f"{target}:{port}/{proto}"
            meta = {"port": port, "proto": proto, "service": service,
                    "version": (version or "").strip()}
            entities.append(ParsedEntity("service", value, 0.95, f"{service} :{port}", meta))
            rels.append(ParsedRelationship(target, "ip", "OPEN_PORT", value, "service", 0.95))
        n = len(rels)
        return ParseResult(entities, rels, f"Nmap found {n} open port(s) on {target}")
