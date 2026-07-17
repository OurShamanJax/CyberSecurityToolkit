"""Fallback parser: pull IPs / emails / URLs / domains out of any text."""
import re

from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

RE_EMAIL = re.compile(r'[\w.+\-]+@[\w\-]+\.[\w.]+')
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_URL = re.compile(r'https?://[^\s\'"<>]+')
RE_DOMAIN = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+'
    r'(?:com|org|net|io|gov|edu|co|dev|app|uk|de|info|xyz|me)\b', re.I)


class GenericParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("target", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        seen = {target.lower()}
        for pattern, etype in ((RE_EMAIL, "email"), (RE_IP, "ip"),
                               (RE_URL, "url"), (RE_DOMAIN, "domain")):
            for m in pattern.finditer(raw or ""):
                v = m.group().lower().rstrip('.,')
                if v in seen or len(v) < 4:
                    continue
                seen.add(v)
                entities.append(ParsedEntity(etype, v, 0.55, None, {"source": "generic"}))
                rels.append(ParsedRelationship(target, "target", "EXTRACTED", v, etype, 0.55))
        return ParseResult(entities, rels, f"Extracted {len(rels)} artifact(s)")
