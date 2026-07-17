"""
Graph brain - turns a finished run into graph nodes, edges and findings,
answers "what should I run next on this node?", and handles delete/reset.

Confidence rules:
  * first sighting        -> the parser's confidence
  * seen again            -> +0.05 per sighting (capped at 1.0)
  * user confirms a node  -> pinned to 1.0
"""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from collections import Counter

from ..models import Entity, Relationship, Finding, Run
from ..parsers.registry import get_parser
from ..tools.registry import list_tools

REPEAT_BOOST = 0.05

INPUT_TYPE_FOR_ENTITY = {
    "ip": {"ip", "host"},
    "domain": {"domain"},
    "url": {"url"},
    "service": {"software", "host"},
    "vulnerability": set(),
    "email": set(),
    "username": {"username"},
    "technology": {"software"},
    "file": {"path"},
    "capability": set(),
    "secret": set(),
    "category": set(),
    "credential": set(),
    "access_point": set(),
    "alert": set(),
    "exploit": set(),
}


def ingest(db: Session, run, raw: str, parser_name: str) -> dict:
    result = get_parser(parser_name).parse(raw, run.target)
    inv_id = run.investigation_id
    id_by_key: dict[tuple, Entity] = {}
    for pe in result.entities:
        ent = _upsert_entity(db, inv_id, run.id, pe)
        id_by_key[(pe.type, pe.value.lower())] = ent
    for pr in result.relationships:
        src = id_by_key.get((pr.source_type, pr.source_value.lower()))
        tgt = id_by_key.get((pr.target_type, pr.target_value.lower()))
        if src and tgt:
            _upsert_relationship(db, src, tgt, pr)
    findings = _extract_findings(db, run, result)
    db.commit()
    return {"summary": result.summary, "entities": len(result.entities),
            "relationships": len(result.relationships), "findings": findings}


def _upsert_entity(db: Session, inv_id, run_id, pe) -> Entity:
    ent = db.query(Entity).filter(
        Entity.investigation_id == inv_id,
        Entity.type == pe.type,
        Entity.value == pe.value.lower(),
    ).first()
    if ent:
        ent.times_seen += 1
        if not ent.user_confirmed:
            ent.confidence = min(1.0, ent.confidence + REPEAT_BOOST)
        meta = {**(pe.metadata or {}), **ent.metadata_dict()}
        ent.metadata_json = json.dumps(meta)
        return ent
    ent = Entity(investigation_id=inv_id, source_run_id=run_id, type=pe.type,
                 value=pe.value.lower(), label=pe.label,
                 metadata_json=json.dumps(pe.metadata or {}),
                 confidence=pe.confidence, times_seen=1)
    db.add(ent)
    db.flush()
    return ent


def _upsert_relationship(db: Session, src: Entity, tgt: Entity, pr):
    existing = db.query(Relationship).filter(
        Relationship.source_id == src.id, Relationship.target_id == tgt.id,
        Relationship.relation_type == pr.relation_type,
    ).first()
    if existing:
        existing.weight = min(1.0, existing.weight + REPEAT_BOOST)
        return
    db.add(Relationship(source_id=src.id, target_id=tgt.id,
                        relation_type=pr.relation_type, weight=pr.weight))


def _extract_findings(db: Session, run, result) -> list[dict]:
    """Record noteworthy results as Findings, de-duplicated per investigation.

    Entities are upserted (deduped) on every run, so findings must be too -
    otherwise re-running a tool would append the same finding again and again.
    """
    out = []
    existing = {t[0] for t in db.query(Finding.title)
                .filter(Finding.investigation_id == run.investigation_id).all()}
    for pe in result.entities:
        if pe.type not in ("vulnerability", "secret"):
            continue
        title = pe.label or pe.value
        if title in existing:
            continue
        existing.add(title)
        sev = (pe.metadata or {}).get("severity", "info")
        db.add(Finding(investigation_id=run.investigation_id, run_id=run.id,
                       severity=sev, title=title, detail=json.dumps(pe.metadata or {})))
        out.append({"severity": sev, "title": title})
    return out


def add_manual(db: Session, inv_id: int, o: dict) -> dict:
    """Add a node (and optional linked node) to a graph from any tool page."""
    from ..parsers.base import ParsedEntity, ParsedRelationship
    ent = _upsert_entity(db, inv_id, None, ParsedEntity(
        o["type"], o["value"], float(o.get("confidence", 0.9)),
        o.get("label") or o["value"], o.get("metadata") or {}))
    if o.get("link_value"):
        lt = o.get("link_type") or "target"
        link = _upsert_entity(db, inv_id, None, ParsedEntity(lt, o["link_value"], 1.0, o["link_value"]))
        _upsert_relationship(db, link, ent, ParsedRelationship(
            o["link_value"], lt, o.get("relation", "RELATED_TO"), o["value"], o["type"], 0.9))
    # credentials/secrets are also findings
    if o["type"] in ("credential", "secret"):
        db.add(Finding(investigation_id=inv_id, run_id=None,
                       severity=(o.get("metadata") or {}).get("severity", "high"),
                       title=o.get("label") or o["value"], detail=json.dumps(o.get("metadata") or {})))
    db.commit()
    return {"ok": True, "entity_id": ent.id}


def confirm_entity(db: Session, entity_id: int, confirmed: bool = True) -> Entity:
    ent = db.query(Entity).filter(Entity.id == entity_id).first()
    if not ent:
        raise ValueError("entity not found")
    ent.user_confirmed = confirmed
    if confirmed:
        ent.confidence = 1.0
    db.commit()
    return ent


def delete_entity(db: Session, entity_id: int) -> None:
    """Delete a node and every relationship touching it."""
    db.query(Relationship).filter(
        (Relationship.source_id == entity_id) | (Relationship.target_id == entity_id)
    ).delete(synchronize_session=False)
    ent = db.query(Entity).filter(Entity.id == entity_id).first()
    if ent:
        db.delete(ent)
    db.commit()


def reset_graph(db: Session, inv_id: int) -> None:
    """Wipe all nodes, edges and findings for an investigation (keeps the case)."""
    ids = [e.id for e in db.query(Entity.id).filter(Entity.investigation_id == inv_id).all()]
    if ids:
        flat = [i[0] if isinstance(i, tuple) else i for i in ids]
        db.query(Relationship).filter(
            Relationship.source_id.in_(flat) | Relationship.target_id.in_(flat)
        ).delete(synchronize_session=False)
    db.query(Entity).filter(Entity.investigation_id == inv_id).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.investigation_id == inv_id).delete(synchronize_session=False)
    db.commit()


def graph_data(db: Session, inv_id: int) -> dict:
    ents = db.query(Entity).filter(Entity.investigation_id == inv_id).all()
    ids = {e.id for e in ents}
    rels = db.query(Relationship).filter(
        Relationship.source_id.in_(ids), Relationship.target_id.in_(ids)
    ).all()
    nodes = [{"data": {"id": f"e{e.id}", "entity_id": e.id, "type": e.type,
                       "label": e.label or e.value[:36], "value": e.value,
                       "confidence": round(e.confidence, 2),
                       "confirmed": e.user_confirmed, "times_seen": e.times_seen,
                       "lat": e.lat, "lng": e.lng,
                       "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                       "last_seen": e.last_seen.isoformat() if e.last_seen else None}}
             for e in ents]
    edges = [{"data": {"id": f"r{r.id}", "source": f"e{r.source_id}",
                       "target": f"e{r.target_id}", "label": r.relation_type}}
             for r in rels]
    return {"nodes": nodes, "edges": edges}


def geolocate(db: Session, inv_id: int) -> dict:
    """Fill lat/lng for network entities that don't have coordinates yet."""
    from ..geo import locate
    ents = db.query(Entity).filter(
        Entity.investigation_id == inv_id,
        Entity.type.in_(("ip", "host", "url", "domain", "service")),
        Entity.lat.is_(None),
    ).all()
    n = 0
    for e in ents:
        r = locate(e.value)
        if r:
            e.lat, e.lng = r["lat"], r["lng"]
            n += 1
    db.commit()
    return {"geolocated": n, "checked": len(ents)}


def suggest_tools(entity_type: str) -> list[dict]:
    wanted = INPUT_TYPE_FOR_ENTITY.get(entity_type, set())
    return [{"id": t["id"], "name": t["name"], "noise": t["noise"], "category": t["category"]}
            for t in list_tools() if t["input_type"] in wanted]


# Detectability tiers -> how full the footprint bar should read.
_NOISE_FILL = {"silent": 0.12, "whisper": 0.32, "moderate": 0.55, "loud": 0.78, "aggressive": 1.0}
_NOISE_ORDER = ["silent", "whisper", "moderate", "loud", "aggressive"]


def compute_footprint(db: Session, inv_id: int) -> dict:
    """Footprint = how detectable this investigation's activity has been.

    Driven by the LOUDEST tool actually run (you can't un-ring that bell), not a
    runaway sum. Per-investigation, computed from the real run history.
    """
    tiers = [r.noise for r in db.query(Run.noise).filter(Run.investigation_id == inv_id).all()
             if r.noise in _NOISE_ORDER]
    if not tiers:
        return {"level": "silent", "fill": 0.0, "runs": 0, "counts": {}}
    loudest = max(tiers, key=lambda t: _NOISE_ORDER.index(t))
    return {"level": loudest, "fill": _NOISE_FILL[loudest],
            "runs": len(tiers), "counts": dict(Counter(tiers))}
