"""SQLMap parser: pull the vulnerable parameter(s) and the back-end DBMS.

Models the story:  target --HAS_VULNERABILITY--> "SQL injection (param)"
                   target --USES_TECH-->        the database engine (e.g. SQLite)
so the graph shows exactly WHICH input is injectable and WHAT sits behind it.
"""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

PARAM_RE = re.compile(r'Parameter:\s*([^\s(]+)\s*\((GET|POST|COOKIE|URI|JSON)\)', re.I)
PARAM_RE2 = re.compile(r"(?:GET|POST|URI|Cookie|JSON)\s+parameter\s+'([^']+)'\s+(?:is|appears)", re.I)
DBMS_RE = re.compile(r'back-end DBMS:?\s*(?:is\s+)?(.+)', re.I)
TYPE_RE = re.compile(r'^\s*Type:\s*(.+?)\s*$', re.M)


class SqlmapParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        raw = raw or ""
        entities = [ParsedEntity("url", target, 1.0, target)]
        rels = []

        params = set()
        for rx in (PARAM_RE, PARAM_RE2):
            for m in rx.finditer(raw):
                params.add(m.group(1).strip())
        types = [t.strip() for t in TYPE_RE.findall(raw)][:4]

        for p in sorted(params):
            vid = f"sqli:{p}"
            entities.append(ParsedEntity("vulnerability", vid, 0.95,
                                         f"[HIGH] SQL injection ({p})",
                                         {"severity": "high", "parameter": p,
                                          "types": types, "source": "sqlmap"}))
            rels.append(ParsedRelationship(target, "url", "HAS_VULNERABILITY", vid, "vulnerability", 0.95))

        dbms = None
        dm = DBMS_RE.search(raw)
        if dm:
            dbms = re.split(r'\s{2,}|\n', dm.group(1).strip())[0].strip().rstrip('.').strip()
            if dbms:
                entities.append(ParsedEntity("technology", dbms, 0.9, dbms, {"source": "sqlmap"}))
                rels.append(ParsedRelationship(target, "url", "USES_TECH", dbms, "technology", 0.9))

        summ = f"SQLMap: {len(params)} vulnerable parameter(s)" + (f", DBMS: {dbms}" if dbms else "")
        return ParseResult(entities, rels, summ or "SQLMap: no injection confirmed")
