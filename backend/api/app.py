"""
FastAPI application - local-first, single-user.
Serves the JSON API, the WebSocket tool runner, and the single-file frontend.
Binds to 127.0.0.1 (see backend/run.py). CORS restricted to loopback.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import settings
from ..db import Base, SessionLocal, engine, get_db, migrate
from ..logger import get_logger
from ..models import Investigation, Run, Finding, Entity, Relationship
from ..safety import target_in_scope, requires_confirmation
from ..tools.registry import get_tool, list_tools
from ..executor.runner import run_tool, cancel, tool_status
from ..graph import entity_service
from ..report.generator import build_html
from ..report.knowledge import lookup as kb_lookup

log = get_logger("api")
FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"
SCOPED_INPUT_TYPES = {"ip", "domain", "url", "host"}


def _ws_origin_ok(ws) -> bool:
    """Only accept WebSocket handshakes from the local UI. Browsers always send
    Origin, so a malicious external page is rejected; native clients (no Origin)
    are allowed so tooling/tests keep working."""
    from urllib.parse import urlparse
    origin = ws.headers.get("origin")
    if not origin:
        return True
    try:
        return urlparse(origin).hostname in ("127.0.0.1", "localhost", "::1")
    except Exception:
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    migrate()
    log.info("R.O.D.E v4 started (host=%s port=%s)", settings.HOST, settings.PORT)
    yield


app = FastAPI(title="R.O.D.E v4", version="4.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://127.0.0.1:{settings.PORT}", f"http://localhost:{settings.PORT}"],
    allow_methods=["*"], allow_headers=["*"],
)


class InvestigationIn(BaseModel):
    name: str
    description: str = ""
    scope: list[str] = []
    mode: str = "infra"


class InvestigationPatch(BaseModel):
    name: str | None = None
    scope: list[str] | None = None
    mode: str | None = None


class CredAuditIn(BaseModel):
    base_url: str
    login_path: str = "/rest/user/login"
    user_field: str = "email"
    pass_field: str = "password"
    username: str
    mode: str = "json"
    success_status: int = 200
    wordlist: str = "passwords-top.txt"
    max_tries: int = 300


class VpnIn(BaseModel):
    endpoint: str = "vpn.example.com"
    port: int = 51820
    subnet: str = "10.8.0"
    dns: str = "1.1.1.1"
    peers: int = 1


class EntityAddIn(BaseModel):
    investigation_id: int
    type: str
    value: str
    label: str | None = None
    metadata: dict = {}
    link_type: str | None = None
    link_value: str | None = None
    relation: str = "RELATED_TO"


class MsfBuildIn(BaseModel):
    payload: str
    lhost: str = ""
    lport: int = 4444
    format: str = "raw"
    encoder: str = "none"
    iterations: int = 0
    lab_ack: bool = False   # UI confirms this is an authorized lab target


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "4.0.0", "time": datetime.utcnow().isoformat()}


@app.get("/api/tools")
def api_tools(category: str | None = None):
    out = []
    for t in list_tools(category):
        out.append({"id": t["id"], "name": t["name"], "category": t["category"],
                    "input_type": t["input_type"], "noise": t["noise"],
                    "teach": t.get("teach", {}), "status": tool_status(t)})
    return {"tools": out}


@app.get("/api/investigations")
def list_inv(db: Session = Depends(get_db)):
    rows = db.query(Investigation).order_by(Investigation.updated_at.desc()).all()
    return [{"id": i.id, "name": i.name, "scope": i.scope(), "mode": i.mode, "description": i.description}
            for i in rows]


@app.post("/api/investigations")
def create_inv(body: InvestigationIn, db: Session = Depends(get_db)):
    inv = Investigation(name=body.name, description=body.description,
                        scope_json=json.dumps(body.scope), mode=body.mode)
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return {"id": inv.id, "name": inv.name, "scope": inv.scope(), "mode": inv.mode}


@app.get("/api/investigations/{inv_id}")
def get_inv(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "not found")
    return {"id": inv.id, "name": inv.name, "scope": inv.scope(), "mode": inv.mode, "description": inv.description}


@app.delete("/api/investigations/{inv_id}")
def del_inv(inv_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if inv:
        db.delete(inv)
        db.commit()
    return {"ok": True}


@app.post("/api/investigations/{inv_id}/reset")
def reset_inv(inv_id: int, db: Session = Depends(get_db)):
    entity_service.reset_graph(db, inv_id)
    return {"ok": True}


@app.patch("/api/investigations/{inv_id}")
def patch_inv(inv_id: int, body: InvestigationPatch, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "not found")
    if body.name is not None:
        inv.name = body.name
    if body.scope is not None:
        inv.scope_json = json.dumps(body.scope)
    if body.mode is not None:
        inv.mode = body.mode
    db.commit()
    return {"id": inv.id, "name": inv.name, "scope": inv.scope(), "mode": inv.mode}


@app.post("/api/investigations/{inv_id}/geolocate")
def api_geolocate(inv_id: int, db: Session = Depends(get_db)):
    return entity_service.geolocate(db, inv_id)


@app.get("/api/graph/{inv_id}")
def api_graph(inv_id: int, db: Session = Depends(get_db)):
    return entity_service.graph_data(db, inv_id)


@app.post("/api/entities/{entity_id}/confirm")
def api_confirm(entity_id: int, confirmed: bool = True, db: Session = Depends(get_db)):
    try:
        e = entity_service.confirm_entity(db, entity_id, confirmed)
        return {"id": e.id, "confirmed": e.user_confirmed, "confidence": e.confidence}
    except ValueError as ex:
        raise HTTPException(404, str(ex))


@app.delete("/api/entities/{entity_id}")
def api_delete_entity(entity_id: int, db: Session = Depends(get_db)):
    entity_service.delete_entity(db, entity_id)
    return {"ok": True}


@app.post("/api/entities/add")
def api_entity_add(body: EntityAddIn, db: Session = Depends(get_db)):
    d = body.model_dump()
    return entity_service.add_manual(db, d.pop("investigation_id"), d)


@app.get("/api/findings/{inv_id}")
def api_findings(inv_id: int, db: Session = Depends(get_db)):
    rows = db.query(Finding).filter(Finding.investigation_id == inv_id) \
             .order_by(Finding.created_at.desc()).all()
    return [{"severity": f.severity, "title": f.title} for f in rows]


@app.get("/api/attack/{inv_id}")
def api_attack(inv_id: int, db: Session = Depends(get_db)):
    """MITRE ATT&CK coverage for an investigation (tactics + techniques touched)."""
    from .. import attack
    return attack.coverage(db, inv_id)


@app.get("/api/correlate/{inv_id}")
def api_correlate(inv_id: int, db: Session = Depends(get_db)):
    """Escalated correlation findings from combined signals in the graph."""
    from .. import correlate
    return correlate.correlations(db, inv_id)


@app.get("/api/investigations/{inv_id}/runs")
def api_run_history(inv_id: int, db: Session = Depends(get_db)):
    """Run history for an investigation (newest first), with prev-same-tool links for diff."""
    rows = db.query(Run).filter(Run.investigation_id == inv_id) \
             .order_by(Run.created_at.desc()).all()
    seen_prev = {}
    out = []
    for r in rows:
        key = (r.tool_id, r.target)
        prev = seen_prev.get(key)         # the newer one we already emitted → this is its predecessor
        out.append({"id": r.id, "tool": r.tool_id, "target": r.target, "noise": r.noise,
                    "status": r.status, "exit_code": r.exit_code, "duration_ms": r.duration_ms,
                    "when": r.created_at.strftime("%Y-%m-%d %H:%M"),
                    "has_output": bool(r.output_file), "prev_id": prev})
        seen_prev[key] = r.id
    # link each run to its *previous* same-tool run (for a diff)
    latest = {}
    for r in reversed(out):  # oldest first
        key = (r["tool"], r["target"])
        r["prev_id"] = latest.get(key)
        latest[key] = r["id"]
    return out


@app.get("/api/runs/diff")
def api_run_diff(a: int, b: int, db: Session = Depends(get_db)):
    """Line-level diff between two runs' saved output (what changed since last time)."""
    ra = db.query(Run).filter(Run.id == a).first()
    rb = db.query(Run).filter(Run.id == b).first()
    if not ra or not rb:
        raise HTTPException(404, "run not found")

    def read(r):
        try:
            return open(r.output_file, encoding="utf-8", errors="replace").read().splitlines() if r.output_file else []
        except Exception:
            return []
    la, lb = read(ra), read(rb)
    sa, sb = set(la), set(lb)
    added = [l for l in lb if l not in sa and l.strip()]
    removed = [l for l in la if l not in sb and l.strip()]
    return {"a": {"id": ra.id, "when": ra.created_at.strftime("%Y-%m-%d %H:%M")},
            "b": {"id": rb.id, "when": rb.created_at.strftime("%Y-%m-%d %H:%M")},
            "added": added[:300], "removed": removed[:300],
            "added_count": len(added), "removed_count": len(removed)}


@app.get("/api/investigations/{inv_id}/export")
def api_export(inv_id: int, format: str = "json", db: Session = Depends(get_db)):
    """Export the whole investigation as JSON or a CSV of entities (shareable case file)."""
    from fastapi.responses import Response
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(404, "not found")
    ents = db.query(Entity).filter(Entity.investigation_id == inv_id).all()
    ids = {e.id for e in ents}
    rels = db.query(Relationship).filter(Relationship.source_id.in_(ids)).all() if ids else []
    finds = db.query(Finding).filter(Finding.investigation_id == inv_id).all()
    runs = db.query(Run).filter(Run.investigation_id == inv_id).all()
    safe = "".join(c if c.isalnum() else "_" for c in inv.name)[:40] or "investigation"
    if format == "csv":
        import io, csv
        buf = io.StringIO(); w = csv.writer(buf)
        w.writerow(["type", "value", "label", "confidence", "confirmed"])
        for e in ents:
            w.writerow([e.type, e.value, e.label or "", round(e.confidence, 2), e.user_confirmed])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="RODE_{safe}_entities.csv"'})
    data = {"investigation": {"id": inv.id, "name": inv.name, "scope": inv.scope(), "mode": inv.mode},
            "entities": [{"type": e.type, "value": e.value, "label": e.label,
                          "confidence": round(e.confidence, 2), "confirmed": e.user_confirmed,
                          "metadata": e.metadata_dict()} for e in ents],
            "relationships": [{"source": r.source_id, "target": r.target_id, "type": r.relation_type} for r in rels],
            "findings": [{"severity": f.severity, "title": f.title} for f in finds],
            "runs": [{"tool": r.tool_id, "target": r.target, "when": r.created_at.isoformat(),
                      "status": r.status} for r in runs]}
    return Response(json.dumps(data, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="RODE_{safe}.json"'})


@app.get("/api/entity/{entity_id}")
def api_entity(entity_id: int, db: Session = Depends(get_db)):
    """Full detail for one node — powers the inspector card."""
    e = db.query(Entity).filter(Entity.id == entity_id).first()
    if not e:
        raise HTTPException(404, "not found")
    meta = e.metadata_dict()
    explain = None
    if e.type in ("vulnerability", "secret"):
        explain = kb_lookup(e.label or e.value, meta.get("severity", "info"))
    children = db.query(Relationship).filter(Relationship.source_id == e.id).count()
    from .. import attack
    tech = attack.techniques_for(meta.get("source", "") or meta.get("tool", ""), e.type)
    return {"id": e.id, "type": e.type, "value": e.value, "label": e.label,
            "confidence": round(e.confidence, 2), "confirmed": e.user_confirmed,
            "times_seen": e.times_seen, "metadata": meta, "explain": explain,
            "children": children, "attack": tech}


@app.get("/api/processes")
def api_processes():
    """Running executables, for the Analyzer 'pick a running app' picker."""
    try:
        import psutil
    except Exception:
        return {"available": False, "processes": []}
    seen: dict[str, dict] = {}
    for pr in psutil.process_iter(["pid", "name", "exe", "memory_info"]):
        try:
            info = pr.info
            exe = info.get("exe") or ""
            if not exe:
                continue
            mem = info.get("memory_info")
            mb = round((mem.rss if mem else 0) / 1048576, 1)
            row = {"pid": info["pid"], "name": info.get("name") or "", "exe": exe, "mb": mb}
            if exe not in seen or mb > seen[exe]["mb"]:
                seen[exe] = row
        except Exception:
            continue
    procs = sorted(seen.values(), key=lambda x: -x["mb"])[:80]
    return {"available": True, "processes": procs}


@app.post("/api/credaudit")
def api_credaudit(body: CredAuditIn):
    """Login auditor for YOUR OWN systems (e.g. local Juice Shop)."""
    from ..credaudit import run_audit
    return run_audit(body.model_dump())


@app.post("/api/vpn/generate")
def api_vpn(body: VpnIn):
    from ..vpn import generate
    return generate(body.model_dump())


@app.get("/api/wifi/scan")
def api_wifi_scan():
    from ..wifi import scan
    return scan()


@app.get("/api/wifi/gateway")
def api_wifi_gateway():
    from ..wifi import gateway
    return {"gateway": gateway()}


class CamIn(BaseModel):
    name: str = "camera"
    lat: float = 0.0
    lng: float = 0.0
    country: str = ""
    type: str = "webcam"
    url: str = ""
    video: str = ""
    stream: str = "jpg"


@app.get("/api/cams")
def api_cams():
    from ..cams import list_cams
    return {"cameras": list_cams()}


@app.post("/api/cams")
def api_cams_add(body: CamIn):
    from ..cams import add_cam
    return add_cam(body.model_dump())


class CamImportIn(BaseModel):
    source: str = "tfl"


class WindyIn(BaseModel):
    lat: float
    lng: float
    radius: int = 100
    key: str = ""


class SecretIn(BaseModel):
    key: str


@app.post("/api/cams/import")
def api_cams_import(body: CamImportIn):
    from ..cams import import_source
    return import_source(body.source)


@app.post("/api/cams/windy")
def api_cams_windy(body: WindyIn):
    """Load Windy webcams near a viewport centre (global coverage; free key)."""
    from ..cams import import_windy
    return import_windy(body.lat, body.lng, body.radius, body.key)


@app.get("/api/secrets")
def api_secrets():
    """Which secrets are configured (booleans only - never returns the values)."""
    from ..cams import get_secret
    return {"windy": bool(get_secret("windy_key")), "firms": bool(get_secret("firms_key")),
            "mapillary": bool(get_secret("mapillary_token"))}


@app.post("/api/secrets/mapillary")
def api_set_mapillary(body: SecretIn):
    """Persist the free Mapillary access token in data/secrets.json (gitignored)."""
    from ..cams import set_secret
    k = body.key.strip()
    set_secret("mapillary_token", k)
    return {"ok": True, "mapillary": bool(k)}


@app.get("/api/streetview")
def api_streetview(lat: float, lng: float):
    """Nearest Mapillary street-level image to a point (free, crowd-sourced)."""
    from ..cams import get_secret
    import urllib.request, urllib.parse
    tok = get_secret("mapillary_token")
    if not tok:
        return {"ok": False, "error": "no Mapillary token set"}
    d = 0.0025      # ~250 m box around the point
    bbox = f"{lng - d},{lat - d},{lng + d},{lat + d}"
    url = ("https://graph.mapillary.com/images?access_token=" + urllib.parse.quote(tok)
           + "&fields=id,thumb_1024_url,captured_at,compass_angle,geometry&bbox=" + bbox + "&limit=10")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RODE-Toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"ok": False, "error": str(e)[:140]}
    imgs = data.get("data") or []
    if not imgs:
        return {"ok": True, "found": False}

    def dist(im):
        try:
            c = im["geometry"]["coordinates"]
            return (c[0] - lng) ** 2 + (c[1] - lat) ** 2
        except Exception:
            return 1e9
    best = min(imgs, key=dist)
    # the client token is a public browser token (like a maps key) — the interactive
    # mapillary-js viewer needs it client-side; fine for a local single-user app.
    return {"ok": True, "found": True, "id": best.get("id"), "thumb": best.get("thumb_1024_url"),
            "captured_at": best.get("captured_at"), "compass": best.get("compass_angle"),
            "token": tok}


@app.post("/api/secrets/windy")
def api_set_windy(body: SecretIn):
    """Persist the Windy key in data/secrets.json (gitignored, never committed)."""
    from ..cams import set_secret
    k = body.key.strip()
    set_secret("windy_key", k)
    return {"ok": True, "windy": bool(k)}


@app.post("/api/secrets/firms")
def api_set_firms(body: SecretIn):
    """Persist the NASA FIRMS key in data/secrets.json (gitignored)."""
    from ..cams import set_secret
    k = body.key.strip()
    set_secret("firms_key", k)
    return {"ok": True, "firms": bool(k)}


@app.post("/api/pwned")
def api_pwned(body: SecretIn):
    """Have I Been Pwned k-anonymity check — the password NEVER leaves this machine;
    only the first 5 chars of its SHA-1 hash are sent, and the match is done locally."""
    import hashlib
    import urllib.request
    pw = body.key or ""
    if not pw:
        return {"ok": False, "error": "empty"}
    h = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    try:
        req = urllib.request.Request("https://api.pwnedpasswords.com/range/" + prefix,
                                     headers={"User-Agent": "RODE-Toolkit/1.0", "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}
    count = 0
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            try:
                count = int(parts[1].strip())
            except Exception:
                count = 1
            break
    return {"ok": True, "pwned": count > 0, "count": count}


@app.get("/api/fires")
def api_fires(bbox: str = "", days: int = 1):
    """Active wildfire detections (NASA FIRMS) for a bbox 'w,s,e,n'."""
    from .. import wildfire
    bb = bbox.split(",") if bbox else None
    return wildfire.fires(bb, days)


@app.get("/api/data/output/info")
def api_output_info():
    """Size + file count of data/output (saved tool run text)."""
    d = settings.DATA_DIR / "output"
    files = [f for f in d.iterdir() if f.is_file()] if d.exists() else []
    return {"count": len(files), "bytes": sum(f.stat().st_size for f in files)}


@app.post("/api/data/output/clear")
def api_output_clear():
    """Delete saved tool-run output files in data/output (does not touch the DB)."""
    d = settings.DATA_DIR / "output"
    removed = 0
    if d.exists():
        for f in d.iterdir():
            try:
                if f.is_file():
                    f.unlink(); removed += 1
            except Exception:
                pass
    return {"ok": True, "removed": removed}


@app.delete("/api/cams/{cid}")
def api_cams_del(cid: int):
    from ..cams import delete_cam
    return delete_cam(cid)


@app.get("/api/cams/{cid}/snapshot")
def api_cam_snapshot(cid: int):
    from ..cams import snapshot
    from fastapi.responses import Response
    data, ctype = snapshot(cid)
    if data is None:
        return JSONResponse({"error": "feed unavailable"}, status_code=404)
    return Response(content=data, media_type=ctype or "image/jpeg",
                    headers={"Cache-Control": "no-store"})


@app.get("/api/wifi/connected")
def api_wifi_connected():
    from ..wifi import connected
    return connected()


@app.get("/api/myip")
def api_myip():
    from ..exposure import my_ip
    return {"ip": my_ip()}


@app.get("/api/lan/hosts")
def api_lan_hosts():
    """The last LAN-discovery result (for labelling IPs in Live Traffic, etc.)."""
    from .. import lan
    return lan.get_hosts()


@app.get("/api/lanip")
def api_lanip():
    """The machine's primary LAN IP - used to pre-fill the payload listener (LHOST)
    so a reverse callback points at this box on the local network. No packets sent."""
    import socket
    ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        pass
    return {"ip": ip}


@app.get("/api/locate")
def api_locate(q: str):
    """Geolocate one IP/domain for the Atlas locate tool."""
    from .. import nettrace
    r = nettrace.locate_rich(q)
    if not r:
        raise HTTPException(404, "could not resolve target")
    return r


@app.get("/api/traceroute")
def api_traceroute(target: str):
    """Run the OS traceroute to target and geolocate each public hop."""
    from .. import nettrace
    return nettrace.traceroute(target)


@app.get("/api/geocode")
def api_geocode(q: str):
    """Free place search (name/state/country) -> point + bbox for the globe."""
    from .. import nettrace
    return nettrace.geocode(q)


class ThreatCheckIn(BaseModel):
    values: list[str] = []


@app.post("/api/threatintel/check")
def api_threat_check(body: ThreatCheckIn):
    """Flag graph nodes (IP/domain/URL host) against free abuse.ch feeds."""
    from .. import threatintel
    return threatintel.check_many(body.values)


@app.post("/api/threatintel/refresh")
def api_threat_refresh():
    from .. import threatintel
    st = threatintel.refresh(force=True)
    return {"ok": True, "updated": st.get("loaded"),
            "sources": {"feodo": len(st.get("feodo", {})), "urlhaus": len(st.get("urlhaus", {}))}}


@app.get("/api/exposure")
def api_exposure(target: str):
    from ..exposure import lookup
    return lookup(target)


@app.get("/api/satellites")
def api_satellites():
    from ..sats import fetch_tle
    return {"sats": fetch_tle()}


@app.get("/api/capabilities")
def api_capabilities():
    from ..executor.runner import docker_available
    from .. import capture
    return {"docker": docker_available(force=True), "tshark": capture.available()}


@app.get("/api/msf/status")
def api_msf_status():
    from .. import metasploit
    return metasploit.status(force=True)


@app.get("/api/msf/payloads")
def api_msf_payloads():
    from .. import metasploit
    return {"payloads": metasploit.PAYLOADS, "formats": metasploit.FORMATS,
            "encoders": metasploit.ENCODERS}


@app.post("/api/msf/preview")
def api_msf_preview(body: MsfBuildIn):
    """Validate a build request and return the exact command (without running).
    Powers the live 'recipe' preview - safe, produces no artifact."""
    from .. import metasploit
    opts = body.model_dump()
    v = metasploit.validate_build(opts)
    return {**v, "command": metasploit.display_command(opts) if v["ok"] else ""}


@app.get("/api/suggest")
def api_suggest(type: str):
    return {"tools": entity_service.suggest_tools(type)}


@app.get("/api/footprint/{inv_id}")
def api_footprint(inv_id: int, db: Session = Depends(get_db)):
    return entity_service.compute_footprint(db, inv_id)


@app.get("/api/report/{inv_id}")
def api_report(inv_id: int, db: Session = Depends(get_db)):
    html_doc, filename = build_html(db, inv_id)
    return {"html": html_doc, "filename": filename}


@app.websocket("/ws/run")
async def ws_run(ws: WebSocket):
    if not _ws_origin_ok(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        while True:
            msg = json.loads(await ws.receive_text())
            if msg.get("action") == "cancel":
                cancel(msg.get("run_id"))
                continue

            tool_id = (msg.get("tool_id") or "").strip()
            target = (msg.get("target") or "").strip()
            inv_id = msg.get("investigation_id")
            confirmed = bool(msg.get("confirmed"))

            tool = get_tool(tool_id)
            if not tool or not target:
                await ws.send_json({"type": "error", "message": "tool and target required"})
                continue

            db = SessionLocal()
            try:
                inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
                scope = inv.scope() if inv else []

                if (tool["input_type"] in SCOPED_INPUT_TYPES
                        and not target_in_scope(target, scope)):
                    await ws.send_json({"type": "advisory", "message":
                        f"'{target}' is outside this investigation's declared scope. "
                        f"Only test systems you own or are authorized to test."})

                if requires_confirmation(tool["noise"], settings.CONFIRM_FROM_NOISE) and not confirmed:
                    await ws.send_json({"type": "confirm_required",
                                        "tool_id": tool_id, "noise": tool["noise"]})
                    continue

                run = Run(investigation_id=inv_id, tool_id=tool_id, target=target,
                          noise=tool["noise"], status="running")
                db.add(run)
                db.commit()
                db.refresh(run)

                safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
                out_file = settings.DATA_DIR / "output" / f"{tool_id}_{safe}_{run.id}.txt"
                out_file.parent.mkdir(parents=True, exist_ok=True)

                await ws.send_json({"type": "started", "run_id": run.id})
                await ws.send_json({"type": "command", "teach": tool.get("teach", {}),
                                    "noise": tool["noise"]})

                async def emit(text):
                    try:
                        await ws.send_json({"type": "output", "data": text})
                    except Exception:
                        pass

                result = await run_tool(tool, target, emit, run_id=run.id)
                out_file.write_text(result["raw"], encoding="utf-8", errors="replace")

                run.status = "done"
                run.exit_code = result["exit_code"]
                run.duration_ms = result["duration_ms"]
                run.output_file = str(out_file)
                db.commit()

                if inv_id:
                    ing = entity_service.ingest(db, run, result["raw"], tool["parser"])
                    await ws.send_json({"type": "parsed", **ing})

                await ws.send_json({"type": "done", "run_id": run.id,
                                    "exit_code": result["exit_code"],
                                    "duration_ms": result["duration_ms"], "noise": tool["noise"]})
            except Exception as e:
                log.exception("run error")
                await ws.send_json({"type": "error", "message": str(e)})
            finally:
                db.close()
    except WebSocketDisconnect:
        pass


@app.websocket("/ws/capture")
async def ws_capture(ws: WebSocket):
    """Live packet capture stream (tshark). Sends {type:caps} then packets."""
    import asyncio, threading, subprocess as _sp
    from .. import capture as cap
    if not _ws_origin_ok(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    await ws.send_json({"type": "caps", "available": cap.available(), "interfaces": cap.list_interfaces()})
    loop = asyncio.get_event_loop()
    proc = {"p": None}
    det = cap.Detector()
    try:
        while True:
            msg = json.loads(await ws.receive_text())
            act = msg.get("action")
            if act == "start":
                if not cap.available():
                    await ws.send_json({"type": "error", "message": "tshark not found on the server"})
                    continue
                if proc["p"]:
                    try: proc["p"].kill()
                    except Exception: pass

                def reader(cmd):
                    try:
                        p = _sp.Popen(cmd, stdout=_sp.PIPE, stderr=_sp.PIPE, text=True, bufsize=1)
                    except Exception as e:
                        asyncio.run_coroutine_threadsafe(ws.send_json({"type": "error", "message": str(e)}), loop)
                        return
                    proc["p"] = p
                    stats = {"pkts": 0}
                    errbuf = []

                    def errpump():
                        # Keep the whole stderr tail so we can explain a silent early exit
                        # (e.g. an invalid -e field prints "Some fields aren't valid" and
                        # tshark quits — no packets, and it matches no obvious keyword).
                        for el in iter(p.stderr.readline, ""):
                            el = el.strip()
                            if not el:
                                continue
                            errbuf.append(el)
                            del errbuf[:-8]
                            if any(k in el.lower() for k in
                                   ("permission", "error", "npcap", "no interface", "not found",
                                    "couldn", "denied", "invalid", "aren't valid", "not a valid",
                                    "unknown", "unrecognized", "syntax", "no such")):
                                asyncio.run_coroutine_threadsafe(ws.send_json({"type": "error", "message": el[:180]}), loop)
                    threading.Thread(target=errpump, daemon=True).start()
                    for line in iter(p.stdout.readline, ""):
                        pkt = cap.parse_line(line)
                        if not pkt:
                            continue
                        stats["pkts"] += 1
                        alerts = det.check(pkt)
                        asyncio.run_coroutine_threadsafe(ws.send_json({"type": "pkt", "pkt": pkt, "alerts": alerts}), loop)
                    # tshark exited. If we never saw a packet, say why instead of a silent empty feed.
                    if stats["pkts"] == 0:
                        try: p.wait(timeout=2)
                        except Exception: pass
                        import time as _t; _t.sleep(0.2)
                        tail = " | ".join(errbuf[-3:]) if errbuf else ""
                        msg2 = ("Capture ended with 0 packets. "
                                + (("tshark said: " + tail) if tail else
                                   "Likely no capture privileges (run R.O.D.E as administrator / with Npcap) "
                                   "or the wrong interface was selected.")
                                + "  If you just updated R.O.D.E, restart the server so the new capture code loads.")
                        asyncio.run_coroutine_threadsafe(ws.send_json({"type": "error", "message": msg2[:240]}), loop)

                threading.Thread(target=reader, args=(cap.build_cmd(msg.get("iface")),), daemon=True).start()
                await ws.send_json({"type": "started"})
            elif act == "stop":
                if proc["p"]:
                    try: proc["p"].kill()
                    except Exception: pass
                    proc["p"] = None
                await ws.send_json({"type": "stopped"})
    except WebSocketDisconnect:
        if proc["p"]:
            try: proc["p"].kill()
            except Exception: pass


@app.websocket("/ws/msf")
async def ws_msf(ws: WebSocket):
    """One socket for the Metasploit page. Actions:
      {action:'build', ...opts}  -> stream msfvenom output (+ optional artifact)
      {action:'console_exec', cmd} -> run one msfconsole command, stream output
    Runs only real upstream tools; refuses a build that fails validation."""
    import asyncio
    if not _ws_origin_ok(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    from .. import metasploit
    loop = asyncio.get_event_loop()

    async def emit(text):
        try:
            await ws.send_json({"type": "output", "data": text})
        except Exception:
            pass

    try:
        while True:
            msg = json.loads(await ws.receive_text())
            act = msg.get("action")

            if act == "build":
                opts = {k: msg.get(k) for k in
                        ("payload", "lhost", "lport", "format", "encoder", "iterations")}
                if not msg.get("lab_ack"):
                    await ws.send_json({"type": "error", "message":
                        "Confirm this is your authorized lab first."})
                    continue
                v = metasploit.validate_build(opts)
                for w in v["warnings"]:
                    await emit("[WARN] " + w + "\n")
                if not v["ok"]:
                    await ws.send_json({"type": "error", "message": "; ".join(v["errors"])})
                    continue
                out_dir = str(settings.WORKSPACE_DIR / "payloads")
                await ws.send_json({"type": "started"})
                res = await metasploit.run_venom(opts, emit, out_dir=out_dir)
                await ws.send_json({"type": "done", "exit_code": res["exit_code"],
                                    "artifact": res.get("artifact")})

            elif act == "console_exec":
                cmd = (msg.get("cmd") or "").strip()
                if cmd:
                    await ws.send_json({"type": "console_running"})
                    await metasploit.run_console_cmd(cmd, emit)
                    await ws.send_json({"type": "console_done"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.exception("msf ws error")
        try:
            await ws.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


# ---- static frontend (multi-page app shell) -------------------------------
@app.middleware("http")
async def _security(request, call_next):
    resp = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".html", ".js", ".css")):
        resp.headers["Cache-Control"] = "no-store, max-age=0"
    # defense-in-depth headers (safe subset that won't break the local app)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'; object-src 'none'"
    return resp


app.mount("/", StaticFiles(directory=str(FRONTEND), html=True), name="static")
