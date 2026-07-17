"""Trivy parser: reads Trivy JSON (fs scan) -> vulnerability + secret entities."""
import json
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

WEIGHTS = {"critical": 1.0, "high": 0.9, "medium": 0.75, "low": 0.6, "unknown": 0.5}


class TrivyParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        name = target.replace("\\", "/").split("/")[-1] or target
        entities = [ParsedEntity("target", target, 1.0, name)]
        rels = []
        raw = raw or ""
        try:
            data = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
        except (ValueError, json.JSONDecodeError):
            return ParseResult(entities, rels, "Trivy: no parseable JSON output")
        for res in data.get("Results", []) or []:
            for v in res.get("Vulnerabilities") or []:
                vid = v.get("VulnerabilityID", "?")
                sev = (v.get("Severity") or "unknown").lower()
                pkg = v.get("PkgName", "")
                w = WEIGHTS.get(sev, 0.5)
                label = f"[{sev.upper()}] {vid} ({pkg})"
                meta = {"severity": sev, "pkg": pkg, "version": v.get("InstalledVersion", ""),
                        "title": v.get("Title", "")}
                entities.append(ParsedEntity("vulnerability", f"{vid}:{pkg}", w, label, meta))
                rels.append(ParsedRelationship(target, "target", "HAS_VULNERABILITY",
                                               f"{vid}:{pkg}", "vulnerability", w))
            for s in res.get("Secrets") or []:
                rid = s.get("RuleID", "secret")
                sev = (s.get("Severity") or "high").lower()
                title = s.get("Title", rid)
                entities.append(ParsedEntity("secret", f"{rid}:{res.get('Target','')}", 0.9,
                                             title, {"severity": sev, "rule": rid, "match": s.get("Match", "")[:80]}))
                rels.append(ParsedRelationship(target, "target", "HAS_SECRET",
                                               f"{rid}:{res.get('Target','')}", "secret", 0.9))
        n = len(rels)
        return ParseResult(entities, rels, f"Trivy found {n} issue(s) in {name}")
