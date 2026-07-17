"""HTTPx parser: 'url [status] [title] [tech]' -> live url + technology entities."""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

LINE_RE = re.compile(r'(https?://\S+)\s+\[(\d+)\](?:\s+\[([^\]]*)\])?(?:\s+\[([^\]]*)\])?')


class HttpxParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("domain", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        for m in LINE_RE.finditer(raw or ""):
            url, status, title, tech = m.groups()
            w = 0.9 if status.startswith('2') else 0.7
            meta = {"status": status}
            if title:
                meta["title"] = title
            entities.append(ParsedEntity("url", url, w, f"HTTP {status}", meta))
            rels.append(ParsedRelationship(target, "domain", "HAS_URL", url, "url", w))
            if tech:
                entities.append(ParsedEntity("technology", tech, 0.8, tech, {"on": url}))
                rels.append(ParsedRelationship(url, "url", "USES_TECH", tech, "technology", 0.8))
        return ParseResult(entities, rels, f"Probed {len(rels)} service(s) on {target}")
