"""theHarvester parser: pulls emails, subdomains and IPs for a domain."""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

RE_EMAIL = re.compile(r'[\w.+\-]+@[\w\-]+\.[\w.]+')
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_HOST = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I)


class TheHarvesterParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("domain", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        seen = {target.lower()}
        raw = raw or ""
        for e in {m.group().lower() for m in RE_EMAIL.finditer(raw)}:
            if e in seen:
                continue
            seen.add(e)
            entities.append(ParsedEntity("email", e, 0.9, None, {"source": "theharvester"}))
            rels.append(ParsedRelationship(target, "domain", "HAS_EMAIL", e, "email", 0.9))
        for ip in {m.group() for m in RE_IP.finditer(raw)}:
            if ip in seen or ip.startswith(("127.", "0.")):
                continue
            seen.add(ip)
            entities.append(ParsedEntity("ip", ip, 0.8, None, {"source": "theharvester"}))
            rels.append(ParsedRelationship(target, "domain", "RESOLVES_TO", ip, "ip", 0.8))
        for sub in {m.group().lower().rstrip('.') for m in RE_HOST.finditer(raw)}:
            if sub in seen or not sub.endswith("." + target):
                continue
            seen.add(sub)
            entities.append(ParsedEntity("domain", sub, 0.85, "subdomain", {"source": "theharvester"}))
            rels.append(ParsedRelationship(target, "domain", "HAS_SUBDOMAIN", sub, "domain", 0.85))
        return ParseResult(entities, rels, f"Harvested {len(rels)} artifact(s) from {target}")
