"""Binary Inspector parser: turns capability lines + referenced hosts into nodes."""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

CAP_RE = re.compile(r'^\[CAP\]\s*(.+?)\s*::\s*(.+)$', re.M)
RE_URL = re.compile(r'https?://[^\s\'"<>]+')
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


class BinaryParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        name = target.replace("\\", "/").split("/")[-1] or target
        entities = [ParsedEntity("file", target, 1.0, name)]
        rels, seen = [], set()
        for m in CAP_RE.finditer(raw or ""):
            group, detail = m.group(1).strip(), m.group(2).strip()
            if group in seen:
                continue
            seen.add(group)
            entities.append(ParsedEntity("capability", group, 0.8, group, {"apis": detail}))
            rels.append(ParsedRelationship(target, "file", "HAS_CAPABILITY", group, "capability", 0.8))
        for pat, etype in ((RE_URL, "url"), (RE_IP, "ip")):
            for mm in pat.finditer(raw or ""):
                v = mm.group().lower().rstrip('.,')
                if v in seen or v in ("127.0.0.1", "0.0.0.0"):
                    continue
                seen.add(v)
                entities.append(ParsedEntity(etype, v, 0.6, None, {"source": "binary"}))
                rels.append(ParsedRelationship(target, "file", "REFERENCES", v, etype, 0.6))
        return ParseResult(entities, rels, f"Inspected {name}: {len(seen)} artifact(s)")
