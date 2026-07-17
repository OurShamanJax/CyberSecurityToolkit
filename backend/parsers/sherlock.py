"""Sherlock / Maigret parser: '[+] Platform: https://url' -> profile entities."""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

FOUND_RE = re.compile(r'\[\+\]\s*(.+?):\s*(https?://\S+)', re.I)


class SherlockParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("username", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        for m in FOUND_RE.finditer(raw or ""):
            platform = m.group(1).strip()
            url = m.group(2).strip().rstrip('.,')
            entities.append(ParsedEntity("url", url, 0.95, f"{platform} profile",
                                         {"platform": platform}))
            rels.append(ParsedRelationship(target, "username", "HAS_PROFILE_ON",
                                           url, "url", 0.95))
        return ParseResult(entities, rels,
                           f"Found {len(rels)} profile(s) for '{target}'")
