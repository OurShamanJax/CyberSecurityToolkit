"""Nuclei parser (real -silent format): [template] [protocol] [severity] url.

Findings are attached to the SPECIFIC endpoint Nuclei matched, not the root
target. So http://host:3000/metrics becomes its own node and the vulnerability
hangs off it:  target -> HAS_ENDPOINT -> /metrics -> HAS_VULNERABILITY -> vuln.
This keeps the affected location visible and lets the graph tell the story.
"""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

LINE_RE = re.compile(
    r'\[([^\]]+)\]\s+\[[a-z0-9]+\]\s+\[(critical|high|medium|low|info|unknown)\]\s+(\S+)',
    re.I,
)
WEIGHTS = {"critical": 1.0, "high": 0.9, "medium": 0.75, "low": 0.6, "info": 0.4, "unknown": 0.4}


class NucleiParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        entities = [ParsedEntity("url", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        seen_ep, n = set(), 0
        for m in LINE_RE.finditer(raw or ""):
            tmpl, sev = m.group(1).strip(), m.group(2).lower()
            url = m.group(3).strip().rstrip('.,')
            w = WEIGHTS.get(sev, 0.5)
            n += 1

            # Where the finding actually lives: a distinct endpoint gets its own node.
            anchor_val = target
            if url and url.lower() != target.lower().rstrip('/'):
                if url.lower() not in seen_ep:
                    seen_ep.add(url.lower())
                    entities.append(ParsedEntity("url", url, 0.9, url, {"source": "nuclei"}))
                    rels.append(ParsedRelationship(target, "url", "HAS_ENDPOINT", url, "url", 0.85))
                anchor_val = url

            entities.append(ParsedEntity("vulnerability", tmpl, w, f"[{sev.upper()}] {tmpl}",
                                         {"severity": sev, "template": tmpl, "url": url}))
            rels.append(ParsedRelationship(anchor_val, "url", "HAS_VULNERABILITY", tmpl, "vulnerability", w))
        return ParseResult(entities, rels, f"Nuclei found {n} issue(s) on {target}")
