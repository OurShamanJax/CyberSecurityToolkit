"""Plain-English finding explanations, shared by the report generator and API.

lookup(template, severity) returns {title?, plain, why?, fix[]} - a template-
specific entry if we have one (matched by substring), else a severity fallback.
"""
from __future__ import annotations

import json
from pathlib import Path

_KB = json.loads((Path(__file__).with_name("knowledge.json")).read_text(encoding="utf-8"))


def lookup(template: str, severity: str = "info") -> dict:
    t = (template or "").lower()
    for key, entry in _KB["templates"].items():
        if key in t:
            return entry
    return _KB["generic"].get((severity or "info").lower(), _KB["generic"]["info"])
