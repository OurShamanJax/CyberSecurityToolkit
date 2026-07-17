"""Gobuster parser: '/path (Status: 200)' -> discovered path entities."""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

LINE_RE = re.compile(r'(/\S+)\s+\(Status:\s*(\d+)\)')


class GobusterParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("url", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        for m in LINE_RE.finditer(raw or ""):
            path, status = m.group(1), m.group(2)
            full = target.rstrip('/') + path
            w = 0.9 if status.startswith('2') else (0.7 if status.startswith('3') else 0.5)
            entities.append(ParsedEntity("url", full, w, f"HTTP {status}: {path}",
                                         {"status": status, "path": path}))
            rels.append(ParsedRelationship(target, "url", "HAS_PATH", full, "url", w))
        return ParseResult(entities, rels, f"Gobuster found {len(rels)} path(s) on {target}")
