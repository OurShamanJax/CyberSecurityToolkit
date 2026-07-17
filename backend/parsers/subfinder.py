"""Subfinder / Amass parser: one subdomain per line."""
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult


class SubfinderParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("domain", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        seen = {target.lower()}
        for line in (raw or "").splitlines():
            sub = line.strip().lower()
            if not sub or sub in seen or not sub.endswith("." + target):
                continue
            seen.add(sub)
            entities.append(ParsedEntity("domain", sub, 0.9, "subdomain", {"source": "subfinder"}))
            rels.append(ParsedRelationship(target, "domain", "HAS_SUBDOMAIN", sub, "domain", 0.9))
        return ParseResult(entities, rels, f"Found {len(rels)} subdomain(s) for {target}")
