"""Lynis parser — host security-audit output → findings + a hardening score.

Lynis writes lines like:
    [WARNING]: Found some information ...
    [SUGGESTION]: Consider hardening SSH ...
    Hardening index : 67 [############        ]
We turn warnings into medium findings, suggestions into low, and the hardening
index into a `capability`-style score node for the host.
"""
from __future__ import annotations

import re

from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

_WARN = re.compile(r"\[WARNING\]:?\s*(.+)", re.I)
_SUGG = re.compile(r"\[SUGGESTION\]:?\s*(.+)", re.I)
_INDEX = re.compile(r"[Hh]ardening index\s*[:=]\s*(\d{1,3})")


class LynisParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        res = ParseResult()
        host = target or "this host"
        res.entities.append(ParsedEntity(type="host", value=host, confidence=0.9, label=host))

        seen = set()
        warns = suggs = 0
        for line in (raw or "").splitlines():
            m = _WARN.search(line)
            if m:
                txt = m.group(1).strip().rstrip("[]").strip()
                if txt and txt.lower() not in seen:
                    seen.add(txt.lower()); warns += 1
                    res.entities.append(ParsedEntity(
                        type="vulnerability", value=f"lynis-warn: {txt[:120]}",
                        confidence=0.6, label=txt[:80],
                        metadata={"severity": "medium", "source": "lynis", "kind": "warning"}))
                    res.relationships.append(ParsedRelationship(
                        host, "host", "HAS_ISSUE", f"lynis-warn: {txt[:120]}", "vulnerability", 0.6))
                continue
            m = _SUGG.search(line)
            if m:
                txt = m.group(1).strip().rstrip("[]").strip()
                if txt and txt.lower() not in seen:
                    seen.add(txt.lower()); suggs += 1
                    res.entities.append(ParsedEntity(
                        type="vulnerability", value=f"lynis-suggest: {txt[:120]}",
                        confidence=0.5, label=txt[:80],
                        metadata={"severity": "low", "source": "lynis", "kind": "suggestion"}))
                    res.relationships.append(ParsedRelationship(
                        host, "host", "HAS_ISSUE", f"lynis-suggest: {txt[:120]}", "vulnerability", 0.5))
                continue
            mi = _INDEX.search(line)
            if mi:
                score = mi.group(1)
                res.entities.append(ParsedEntity(
                    type="capability", value=f"hardening-index-{host}", confidence=0.95,
                    label=f"Hardening index {score}/100",
                    metadata={"source": "lynis", "score": score}))
                res.relationships.append(ParsedRelationship(
                    host, "host", "HAS_SCORE", f"hardening-index-{host}", "capability", 0.9))

        res.summary = f"Lynis: {warns} warning(s), {suggs} suggestion(s)."
        return res
