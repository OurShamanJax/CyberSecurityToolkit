"""Correlation engine — the intelligence glue.

Individually a vuln, an open service, a threat-intel hit, or a recovered credential
is just a node. Together they tell a story. This reads an investigation's graph and
emits **escalated correlation findings** when signals combine — the thing that makes
the graph feel smart instead of like a collector. Read-only; no network scanning
(it only re-uses the cached abuse.ch feeds for known-bad lookups).
"""
from __future__ import annotations

from .models import Entity, Relationship


def correlations(db, inv_id: int) -> dict:
    ents = db.query(Entity).filter(Entity.investigation_id == inv_id).all()
    ids = {e.id for e in ents}
    rels = db.query(Relationship).filter(
        Relationship.source_id.in_(ids), Relationship.target_id.in_(ids)).all() if ids else []
    out = []

    # 1) discovered software/service that has a matched public exploit → attack path
    has_exploit = {r.source_id for r in rels if r.relation_type == "HAS_EXPLOIT"}
    for e in ents:
        if e.id in has_exploit and e.type != "exploit":
            out.append({"level": "high", "title": "Exploitable: " + (e.label or e.value),
                        "why": "A public exploit was matched to this discovered software — a concrete, "
                               "validate-then-test attack path, not just a version string.",
                        "entities": [e.value], "attack": ["T1190", "T1588"]})

    # 2) known-bad infrastructure (cached abuse.ch feeds), if any IPs/domains present
    ipdoms = [e for e in ents if e.type in ("ip", "domain", "host", "url")]
    if ipdoms:
        try:
            from . import threatintel
            ti = threatintel.check_many([e.value for e in ipdoms]).get("results", {})
        except Exception:
            ti = {}
        for e in ipdoms:
            info = ti.get(e.value)
            if info and info.get("listed"):
                out.append({"level": "critical", "title": "Known-bad: " + (e.label or e.value),
                            "why": info.get("source", "threat intel") + " flags this as "
                                   + (info.get("threat") or "malicious") + ". Treat any link to it as suspect.",
                            "entities": [e.value], "attack": ["T1071"], "geo": True})

    # 3) a host that carries both an open service and a severity vulnerability
    by_id = {e.id: e for e in ents}
    adj = {}
    for r in rels:
        adj.setdefault(r.source_id, []).append(r.target_id)
        adj.setdefault(r.target_id, []).append(r.source_id)
    for e in ents:
        if e.type not in ("ip", "host"):
            continue
        neigh = [by_id[n] for n in adj.get(e.id, []) if n in by_id]
        has_service = any(n.type == "service" for n in neigh)
        vulns = [n for n in neigh if n.type == "vulnerability"]
        sev = [v for v in vulns if (v.metadata_dict().get("severity") in ("high", "critical"))]
        if has_service and sev:
            out.append({"level": "high", "title": "Exposed + vulnerable: " + (e.label or e.value),
                        "why": f"This host has an open service and {len(sev)} high/critical "
                               "vulnerability(ies) — prioritise it.",
                        "entities": [e.value], "attack": ["T1046", "T1190"], "geo": True})

    # 4) recovered credentials → valid-accounts risk
    creds = [e for e in ents if e.type == "credential"]
    if creds:
        out.append({"level": "high", "title": f"{len(creds)} credential(s) recovered",
                    "why": "Recovered credentials enable Valid-Accounts access — rotate them and check reuse.",
                    "entities": [c.value for c in creds[:6]], "attack": ["T1078", "T1110"]})

    # de-dup by title, keep the most severe
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    best = {}
    for c in out:
        cur = best.get(c["title"])
        if not cur or order.get(c["level"], 5) < order.get(cur["level"], 5):
            best[c["title"]] = c
    result = sorted(best.values(), key=lambda x: order.get(x["level"], 5))
    return {"correlations": result, "count": len(result)}
