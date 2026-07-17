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
    return {"id": e.id, "type": e.type, "value": e.value, "label": e.label,
            "confidence": round(e.confidence, 2), "confirmed": e.user_confirmed,
            "times_seen": e.times_seen, "metadata": meta, "explain": explain,
            "children": children}


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
    return {"windy": bool(get_secret("windy_key"))}


@app.post("/api/secrets/windy")
def api_set_windy(body: SecretIn):
    """Persist the Windy key in data/secrets.json (gitignored, never committed)."""
    from ..cams import set_secret
    k = body.key.strip()
    set_secret("windy_key", k)
    return {"ok": True, "windy": bool(k)}


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

                    def errpump():
                        for el in iter(p.stderr.readline, ""):
                            el = el.strip()
                            if el and any(k in el.lower() for k in
                                          ("permission", "error", "npcap", "no interface", "not found", "couldn", "denied", "capture")):
                                asyncio.run_coroutine_threadsafe(ws.send_json({"type": "error", "message": el[:180]}), loop)
                    threading.Thread(target=errpump, daemon=True).start()
                    for line in iter(p.stdout.readline, ""):
                        pkt = cap.parse_line(line)
                        if not pkt:
                            continue
                        alerts = det.check(pkt)
                        asyncio.run_coroutine_threadsafe(ws.send_json({"type": "pkt", "pkt": pkt, "alerts": alerts}), loop)

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
      {action:'console_start'}   -> launch a live msfconsole
      {action:'console_input', line}
      {action:'console_stop'}
    Runs only real upstream tools; refuses a build that fails validation."""
    import asyncio
    if not _ws_origin_ok(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    from .. import metasploit
    loop = asyncio.get_event_loop()
    console = metasploit.Console()

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

            elif act == "console_start":
                await ws.send_json({"type": "console_starting"})
                ok = await asyncio.to_thread(console.start, loop, emit)
                await ws.send_json({"type": "console_started" if ok else "error",
                                    "message": "" if ok else "could not start msfconsole"})

            elif act == "console_input":
                console.send(msg.get("line", ""))

            elif act == "console_stop":
                console.stop()
                await ws.send_json({"type": "console_stopped"})
    except WebSocketDisconnect:
        console.stop()
    except Exception as e:
        log.exception("msf ws error")
        try:
            await ws.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
        console.stop()


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
