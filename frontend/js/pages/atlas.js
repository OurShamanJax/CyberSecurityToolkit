// pages/atlas.js — Atlas v2: a geospatial lens on your investigation.
// The globe is aimed at YOUR data: locate an IP/domain, traceroute a target
// across the world, and plot the investigation's geolocated entities with
// relationship arcs. Cameras + satellites remain as optional layers (off by
// default). Free/no-account sources (ESRI imagery, ip-api.com, Celestrak).
import { $, API, S, COLOR, escapeHtml, toast } from '../core.js';

let viewer=null, baseLayer=null, labelLayer=null, hillLayer=null, camHandler=null, camDS=null, atlasKey=null;
let timer=null, satTimer=null, mediaHls=null, viewChangeTimer=null, rainLayer=null;
let firmsSaved=false, fireDS=null, fireTimer=null, _hoverSat=null;
let camWindows=[], _camZ=20;
let cams=[], camEntities=[], satEntities=[], overlayEntities=[], traceEntities=[], locateEntities=[];
let importedSources=new Set();
let spinOn=true, spinSpeed=1, lastInteract=0, modalOpen=false;
let satView=false, satViewSat=null, satViewAlt=700000, satSpeed=0.25, satViewTime=null, satLastFrame=0, satHudLast=0;
const layers={ inv:true, trace:true, cam:false, sat:false };
function saveLayers(){ try{ localStorage.setItem('rode.atlasLayers', JSON.stringify(layers)); }catch(e){} }
const ESRI='https://services.arcgisonline.com/ArcGIS/rest/services/';
function esri(path){ return new Cesium.ArcGisMapServerImageryProvider({url:ESRI+path+'/MapServer'}); }
function typeColor(t){ return COLOR[t] || '#5aa9e6'; }
// little satellite glyph (body + two solar wings) as an inline data-URI billboard
const SAT_ICON="data:image/svg+xml,"+encodeURIComponent(
  "<svg xmlns='http://www.w3.org/2000/svg' width='26' height='26' viewBox='0 0 24 24'>"+
  "<g fill='#8fe9ff' stroke='#8fe9ff' stroke-width='1' stroke-linejoin='round'>"+
  "<rect x='10.1' y='10.1' width='3.8' height='3.8' rx='0.6'/>"+
  "<rect x='2.3' y='9.3' width='5' height='5.4' fill='#2f93b3'/>"+
  "<rect x='16.7' y='9.3' width='5' height='5.4' fill='#2f93b3'/>"+
  "<line x1='7.3' y1='12' x2='10.1' y2='12'/><line x1='13.9' y1='12' x2='16.7' y2='12'/>"+
  "<line x1='12' y1='10.1' x2='12' y2='6.4'/><circle cx='12' cy='5.5' r='1.3'/>"+
  "</g></svg>");

function shell(){ return `
<div class="page" style="height:100%">
<div class="page-body" style="padding:0;position:relative;height:100%">
  <div id="cesiumViz" style="width:100%;height:100%;min-height:420px;background:#05070b"></div>
  <div id="glbFallback"></div>

  <div id="atlasPanel">
    <div id="apHead">
      <svg class="ic" viewBox="0 0 24 24" style="width:14px;height:14px;color:var(--accent)"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>
      <b style="flex:1;font-size:11px;letter-spacing:.4px">GLOBE</b>
      <button id="apCollapse" title="Collapse / expand" style="background:transparent;border:0;color:var(--mut);cursor:pointer;font-size:13px;line-height:1;padding:0 4px">▾</button>
    </div>
    <div class="ap-search">
      <input id="placeInput" placeholder="fly to place or lat,lng — e.g. Tokyo / 35.68,139.76"/>
      <button class="sm primary" id="placeGo" title="Fly there"><svg class="ic" viewBox="0 0 24 24" style="width:14px;height:14px"><path d="M12 2 2 22l10-6 10 6z"/></svg></button>
    </div>
    <div class="ap-search">
      <input id="locInput" placeholder="locate IP / domain — e.g. 1.1.1.1"/>
      <button class="sm" id="locGo" title="Locate"><svg class="ic" viewBox="0 0 24 24" style="width:14px;height:14px"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg></button>
    </div>
    <div class="ap-row" style="gap:6px"><button class="sm ghost" id="homeBtn" style="flex:1">Home view</button><button class="sm ghost" id="clearBtn" style="flex:1">Clear pins</button></div>
    <label class="ap-row" title="Camera auto-orbit only — satellites keep moving on real time"><input type="checkbox" id="spin" checked/> <span>Auto-rotate globe</span>
      <select id="spd" class="sm" style="font-size:10px;padding:2px 4px"><option value="1">1×</option><option value="600">10m/s</option><option value="3600">1h/s</option><option value="21600">6h/s</option></select></label>

    <div class="ap-sec"><div class="ap-lbl">Layers</div>
      <label class="ap-row"><input type="checkbox" id="lyInv" checked/> <span>Investigation</span><span class="ap-c" id="cInv"></span></label>
      <label class="ap-row"><input type="checkbox" id="lyTrace" checked/> <span>Traceroute paths</span></label>
      <label class="ap-row"><input type="checkbox" id="lyCam"/> <span>Public cameras</span></label>
      <div id="camLegend" style="display:none;padding:2px 0 2px 22px;font-size:10.5px;color:var(--mut);line-height:1.9"></div>
      <div class="ap-row" style="padding-left:22px;gap:5px"><input id="windyKey" placeholder="Windy key (optional)" style="flex:1;min-width:0;font-size:11px;padding:4px 7px"/><button class="sm" id="windyGo">Load</button></div>
      <label class="ap-row"><input type="checkbox" id="lySat"/> <span>Satellites</span></label>
    </div>

    <div class="ap-sec"><div class="ap-lbl">Traceroute</div>
      <div class="ap-search">
        <input id="trInput" placeholder="host / IP to trace"/>
        <button class="sm" id="trGo"><svg class="ic" viewBox="0 0 24 24" style="width:14px;height:14px"><path d="M4 20 20 4M14 4h6v6"/></svg></button>
      </div>
    </div>

    <div class="ap-sec"><div class="ap-lbl ap-toggle" id="globeOptsHdr">Globe options ▸</div>
      <div id="globeOpts" style="display:none">
        <select id="base" class="sm" style="width:100%;margin-bottom:6px"><option value="satellite">Satellite imagery</option><option value="streets">Streets</option></select>
        <label class="ap-row"><input type="checkbox" id="hill"/> <span>Terrain shading (hillshade)</span></label>
        <label class="ap-row"><input type="checkbox" id="labels" checked/> <span>Labels</span></label>
        <label class="ap-row"><input type="checkbox" id="sun" checked/> <span>Sunlight day/night</span></label>
        <label class="ap-row" title="HDR + anti-aliasing — richer light &amp; smoother edges. Turn off if the globe feels sluggish."><input type="checkbox" id="cine" checked/> <span>Cinematic quality (HDR)</span></label>
        <div class="ap-lbl" style="margin-top:9px">Living Earth</div>
        <label class="ap-row" title="Live global precipitation radar (RainViewer, free)"><input type="checkbox" id="lyRain"/> <span>Precipitation — live radar</span></label>
        <label class="ap-row" title="Active wildfire detections — NASA FIRMS (free key)"><input type="checkbox" id="lyFire"/> <span>Wildfires — active (NASA FIRMS)</span></label>
        <div class="ap-row" style="padding-left:22px;gap:5px"><input id="firmsKey" placeholder="FIRMS key (free, optional)" style="flex:1;min-width:0;font-size:11px;padding:4px 7px"/><button class="sm" id="firmsGo">Save</button></div>
        <div class="muted" style="font-size:10px;padding-left:22px;line-height:1.5">Day/night &amp; seasons already track real time.</div>
      </div>
    </div>

    <div class="ap-sec" id="atlasInfoSec"><div class="ap-lbl">Selection</div>
      <div id="atlasInfo" class="ap-info muted">Click a pin, or locate / trace a target.</div>
    </div>
    <div class="ap-meta" id="cmeta"></div>
  </div>

  <div id="rainKey" style="display:none;position:absolute;top:14px;right:14px;z-index:7;background:rgba(13,17,23,.85);border:1px solid rgba(255,255,255,.12);border-radius:10px;padding:11px 13px;pointer-events:none;font-size:11px;color:#cdd6e0;min-width:118px">
    <div style="font-weight:600;margin-bottom:8px;display:flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:#4aa3ff;box-shadow:0 0 6px #4aa3ff"></span>Precipitation</div>
    <div style="display:flex;gap:9px">
      <div style="width:13px;border-radius:3px;background:linear-gradient(to top,#7ec8ff,#3b7cff,#39c46a,#e8e35a,#f0a53a,#e0454a,#c14ad0)"></div>
      <div style="display:flex;flex-direction:column;justify-content:space-between;font-size:10px;color:#aeb8c4"><span>Intense</span><span>Heavy</span><span>Moderate</span><span>Light</span></div>
    </div>
    <div style="font-size:9.5px;color:#8b97a5;margin-top:8px">live radar · RainViewer</div>
  </div>
  <div id="compass" title="Drag to move · drag the corner to resize · double-click for north-up" style="position:absolute;bottom:74px;left:14px;width:82px;height:82px;z-index:8;cursor:grab;resize:both;overflow:hidden;min-width:58px;min-height:58px;max-width:220px;max-height:220px">
    <svg viewBox="0 0 100 100" style="width:100%;height:100%;display:block;pointer-events:none">
      <circle cx="50" cy="50" r="46" fill="rgba(13,17,23,.72)" stroke="rgba(255,255,255,.18)" stroke-width="1.5"/>
      <g id="compassRose">
        <polygon points="50,9 43,50 57,50" fill="#e0454a"/>
        <polygon points="50,91 43,50 57,50" fill="#c9d3df"/>
        <circle cx="50" cy="50" r="3" fill="#e7ebf0"/>
        <text x="50" y="25" text-anchor="middle" fill="#ff6b6f" font-size="13" font-weight="bold" font-family="sans-serif">N</text>
        <text x="50" y="89" text-anchor="middle" fill="#8b97a5" font-size="9" font-family="sans-serif">S</text>
        <text x="84" y="54" text-anchor="middle" fill="#8b97a5" font-size="9" font-family="sans-serif">E</text>
        <text x="16" y="54" text-anchor="middle" fill="#8b97a5" font-size="9" font-family="sans-serif">W</text>
      </g>
    </svg>
  </div>
  <div id="fireKey" style="display:none;position:absolute;bottom:20px;right:14px;z-index:7;background:rgba(13,17,23,.85);border:1px solid rgba(255,255,255,.12);border-radius:10px;padding:11px 13px;pointer-events:none;font-size:11px;color:#cdd6e0;min-width:130px">
    <div style="font-weight:600;margin-bottom:8px;display:flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:#ff3b30;box-shadow:0 0 6px #ff3b30"></span>Active wildfires</div>
    <div style="display:flex;flex-direction:column;gap:4px;font-size:10.5px">
      <span><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:#ff3b30;margin-right:6px;vertical-align:middle"></span>high confidence</span>
      <span><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:#ff8c1a;margin-right:6px;vertical-align:middle"></span>nominal</span>
      <span><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:#ffd23a;margin-right:6px;vertical-align:middle"></span>low</span>
    </div>
    <div id="fireCount" style="font-size:9.5px;color:#8b97a5;margin-top:8px">NASA FIRMS · last 24h</div>
  </div>
  <div id="satView" style="position:absolute;inset:0;display:none;pointer-events:none;z-index:6">
    <div id="satFx">
      <div class="sv-drift"><div class="sv-vig"></div><div class="sv-scan"></div><div class="sv-grain"></div></div>
      <div class="sv-bracket tl"></div><div class="sv-bracket tr"></div><div class="sv-bracket bl"></div><div class="sv-bracket br"></div>
      <div class="sv-cross"></div>
      <div class="sv-hud sv-tl"><span class="sv-rec"></span>REC · <span id="svClock">--:--:--</span></div>
      <div class="sv-hud sv-tr" id="svTelem"></div>
      <div class="sv-hud sv-bl">SIM · optical downlink · rendered from map imagery</div>
    </div>
    <div style="position:absolute;top:14px;left:50%;transform:translateX(-50%);pointer-events:auto;background:rgba(224,164,65,.12);border:1px solid rgba(224,164,65,.42);color:#e3c078;padding:7px 13px;border-radius:9px;font-size:12px;max-width:80%;text-align:center">
      <b id="satViewName"></b> — <b>SIMULATED viewpoint</b> · rendered from map imagery. <b>Not a live camera feed.</b> <button class="sm ghost" id="svExitTop" style="margin-left:8px">Exit ⎋</button></div>
    <div style="position:absolute;bottom:22px;left:50%;transform:translateX(-50%);pointer-events:auto;display:flex;gap:8px">
      <span class="muted" style="align-self:center">speed</span>
      <select id="svSpeed" class="sm"><option value="0.05">0.05×</option><option value="0.1">0.1×</option><option value="0.25" selected>0.25×</option><option value="0.5">0.5×</option><option value="1">real-time</option></select>
      <button class="sm ghost" id="svZoomIn">Zoom in</button><button class="sm ghost" id="svZoomOut">Zoom out</button><button class="sm primary" id="svExit">Exit view</button></div>
  </div>
</div></div>
<div class="cammodal-bg" id="cmBg"></div>
<div class="cammodal" id="cmModal">
  <div class="cmhead"><div style="flex:1"><div id="cmTitle" style="font-weight:600"></div><div class="mono" id="cmSub" style="font-size:11px;color:var(--dim)"></div></div>
    <button class="sm ghost" id="cmClose">Close</button></div>
  <div id="cmBody" style="padding:14px"></div>
</div>`; }

function initCesium(){
  try{ Cesium.Ion.defaultAccessToken=''; }catch(e){}
  viewer=new Cesium.Viewer('cesiumViz',{
    baseLayerPicker:false, geocoder:false, homeButton:false, sceneModePicker:false,
    navigationHelpButton:false, animation:false, timeline:false, fullscreenButton:false,
    infoBox:false, selectionIndicator:false, requestRenderMode:false,
    imageryProvider: esri('World_Imagery'),
    terrainProvider: new Cesium.EllipsoidTerrainProvider(),
  });
  baseLayer=viewer.imageryLayers.get(0);
  setLabels(true);
  const g=viewer.scene.globe; g.enableLighting=true; g.showGroundAtmosphere=true; g.maximumScreenSpaceError=1.4;
  viewer.scene.backgroundColor=Cesium.Color.fromCssColorString('#05070b');
  try{ viewer.clock.currentTime=Cesium.JulianDate.now(); viewer.clock.multiplier=1; viewer.clock.shouldAnimate=true;
        g.dynamicAtmosphereLighting=true; g.atmosphereLightIntensity=8.0; }catch(e){}
  // realism: richer atmosphere + depth fog (cheap; always on)
  try{ const sc=viewer.scene;
    sc.fog.enabled=true; sc.fog.density=0.00016; sc.fog.screenSpaceErrorFactor=4;
    if(sc.skyAtmosphere){ sc.skyAtmosphere.saturationShift=0.12; sc.skyAtmosphere.brightnessShift=0.05;
      try{ sc.skyAtmosphere.atmosphereLightIntensity=12; }catch(_){} }
    try{ g.atmosphereBrightnessShift=0.08; g.atmosphereSaturationShift=0.12; }catch(_){}
    try{ g.showGroundAtmosphere=true; }catch(_){}
  }catch(e){}
  let cine=true; try{ const c=localStorage.getItem('rode.atlasCine'); if(c!==null)cine=c==='1'; }catch(e){}
  setCinematic(cine);
  viewer.scene.preRender.addEventListener(()=>{
    updateCompass();
    cullOccluded();
    if(satView){ followSat(); return; }
    if(!spinOn || modalOpen) return;
    if(Date.now()-lastInteract < 1500) return;
    const ang=(2*Math.PI/86400)*spinSpeed/60;
    try{ viewer.camera.rotate(Cesium.Cartesian3.UNIT_Z, ang); }catch(e){}
  });
  ['mousedown','wheel','touchstart','pointerdown'].forEach(ev=>
    viewer.scene.canvas.addEventListener(ev, ()=>{ lastInteract=Date.now(); }, {passive:true}));
  viewer.scene.canvas.addEventListener('wheel', (e)=>{
    if(!satView) return; e.preventDefault();
    satViewAlt=Math.max(150, Math.min(satViewAlt*(e.deltaY>0?1.15:0.86), 9000000));
  }, {passive:false});
  camDS=new Cesium.CustomDataSource('cams'); viewer.dataSources.add(camDS);
  const cl=camDS.clustering; cl.enabled=true; cl.pixelRange=48; cl.minimumClusterSize=2;
  cl.clusterEvent.addEventListener((ents,cluster)=>{
    cluster.label.show=true; cluster.label.text=String(ents.length);
    cluster.label.font='bold 11px sans-serif'; cluster.label.fillColor=Cesium.Color.WHITE;
    cluster.label.disableDepthTestDistance=Number.POSITIVE_INFINITY;
    cluster.point.show=true; cluster.point.pixelSize=Math.min(30, 14+ents.length*0.25);
    cluster.point.color=Cesium.Color.fromCssColorString('#2f7d57');
    cluster.point.outlineColor=Cesium.Color.BLACK; cluster.point.outlineWidth=1;
    cluster.point.disableDepthTestDistance=Number.POSITIVE_INFINITY;
    if(cluster.billboard) cluster.billboard.show=false;
  });
  camHandler=new Cesium.ScreenSpaceEventHandler(viewer.scene.canvas);
  camHandler.setInputAction(m=>{ const p=viewer.scene.pick(m.position); if(!p||!p.id)return;
    const id=p.id;
    if(Array.isArray(id)){ try{ viewer.flyTo(id,{duration:1.2}); }catch(e){} return; }
    if(id._cam)openCamWindow(id._cam); else if(id._sat)openSat(id._sat);
    else if(id._fire)showFire(id._fire);
    else if(id._hop)showHop(id._hop); else if(id._node)showNode(id._node); else if(id._loc)showLoc(id._loc);
  }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
  // hover a satellite → show just its name (labels are hidden by default to declutter)
  camHandler.setInputAction(m=>{
    if(_hoverSat){ try{ _hoverSat.label.show=false; }catch(e){} _hoverSat=null; }
    const p=viewer.scene.pick(m.endPosition);
    if(p&&p.id&&p.id._sat&&p.id.label){ p.id.label.show=true; _hoverSat=p.id; }
  }, Cesium.ScreenSpaceEventType.MOUSE_MOVE);
  viewer.camera.moveEnd.addEventListener(onViewChanged);
}
function setBase(kind){
  if(!viewer)return;
  if(baseLayer){ viewer.imageryLayers.remove(baseLayer,true); baseLayer=null; }
  baseLayer=viewer.imageryLayers.addImageryProvider(kind==='streets'?esri('World_Street_Map'):esri('World_Imagery'));
  viewer.imageryLayers.lowerToBottom(baseLayer);
}
function setLabels(on){
  if(!viewer)return;
  if(labelLayer){ viewer.imageryLayers.remove(labelLayer,true); labelLayer=null; }
  // "Alternate" reference layer is designed for imagery bases — dark haloed text,
  // far more legible over the satellite globe than the plain boundaries layer.
  if(on){ labelLayer=viewer.imageryLayers.addImageryProvider(esri('Reference/World_Boundaries_and_Places_Alternate'));
    labelLayer.brightness=1.35; }
}
function setHill(on){
  if(!viewer)return;
  if(hillLayer){ viewer.imageryLayers.remove(hillLayer,true); hillLayer=null; }
  if(on){ hillLayer=viewer.imageryLayers.addImageryProvider(esri('Elevation/World_Hillshade'));
    hillLayer.alpha=0.28;                                    // subtle relief, not a gray sheet
    if(labelLayer) viewer.imageryLayers.raiseToTop(labelLayer);  // keep labels crisp on top
  }
}

// ── Living Earth: real-data imagery layers (free, no key) ──
async function setRain(on){ if(!viewer)return;
  if(rainLayer){ try{ viewer.imageryLayers.remove(rainLayer,true); }catch(e){} rainLayer=null; }
  const key=$('#rainKey');
  if(!on){ if(key)key.style.display='none'; return; }
  try{
    const meta=await (await fetch('https://api.rainviewer.com/public/weather-maps.json')).json();
    const host=meta.host, past=(meta.radar&&meta.radar.past)||[]; const fr=past[past.length-1];
    if(!host||!fr){ toast('No radar frames right now','warn'); const c=$('#lyRain'); if(c)c.checked=false; if(key)key.style.display='none'; return; }
    // cap at RainViewer's radar resolution — beyond this Cesium upsamples the last
    // good tiles instead of requesting "Zoom Level Not Supported" placeholders.
    const p=new Cesium.UrlTemplateImageryProvider({ url:host+fr.path+'/256/{z}/{x}/{y}/2/1_1.png', maximumLevel:7, credit:'RainViewer' });
    rainLayer=viewer.imageryLayers.addImageryProvider(p); rainLayer.alpha=0.72;
    if(labelLayer) viewer.imageryLayers.raiseToTop(labelLayer);
    if(key)key.style.display='block';
  }catch(e){ toast('Precipitation radar unavailable (needs internet)','warn'); const c=$('#lyRain'); if(c)c.checked=false; if(key)key.style.display='none'; }
}

// ── wildfires (NASA FIRMS, optional free key) ──
async function initFirms(){ try{ const st=await API('/secrets'); firmsSaved=!!(st&&st.firms); }catch(e){}
  const fk=$('#firmsKey'); if(fk&&firmsSaved) fk.placeholder='FIRMS key saved ✓'; }
function fireColor(conf){ const c=(conf||'').toString().toLowerCase();
  if(c==='h'||c==='high') return '#ff3b30';
  if(c==='l'||c==='low') return '#ffd23a';
  if(c==='n'||c==='nominal') return '#ff8c1a';
  const n=parseFloat(c); if(!isNaN(n)) return n>=80?'#ff3b30':(n>=40?'#ff8c1a':'#ffd23a');
  return '#ff8c1a'; }
const _fireIconCache={};
function fireIcon(col){ if(_fireIconCache[col]) return _fireIconCache[col];
  const uri="data:image/svg+xml,"+encodeURIComponent(
    "<svg xmlns='http://www.w3.org/2000/svg' width='22' height='22' viewBox='0 0 24 24'>"+
    "<path d='M12 23c4.4 0 7-2.9 7-6.4 0-2.6-1.6-4.2-3-6.1-0.9 1.9-1.9 2.4-2.8 1.9 0.6-2.6-0.6-5.2-3.2-7.4-0.3 3-1.9 4.6-2.9 6.6C6.4 12 6 13.4 6 15.1 6 20 8.6 23 12 23z' fill='"+col+"' stroke='#2a0800' stroke-width='1' stroke-linejoin='round'/>"+
    "<path d='M12 20.6c1.9 0 3.2-1.3 3.2-2.9 0-1.5-1.2-2.4-2-3.6-0.9 1.6-1.7 1.7-2.4 1.2 0.2 1.6-0.9 2.6-1.6 3.3-0.3 0.4-0.4 0.8-0.4 1.1 0 1.1 1.3 1.8 3.2 1.8z' fill='#ffe08a' opacity='0.92'/></svg>");
  _fireIconCache[col]=uri; return uri; }
async function setFires(on){ if(!viewer)return;
  if(!fireDS){ fireDS=new Cesium.CustomDataSource('fires'); viewer.dataSources.add(fireDS); }
  const key=$('#fireKey');
  if(!on){ fireDS.entities.removeAll(); if(key)key.style.display='none'; return; }
  if(!firmsSaved){ toast('Save your free FIRMS key first','warn'); const c=$('#lyFire'); if(c)c.checked=false; return; }
  await loadFires(true);
}
async function loadFires(explicit){
  const on=$('#lyFire'); if(!viewer||!fireDS||!on||!on.checked) return;
  const v=viewRectDeg(); if(!v) return;
  const bbox=v[0].toFixed(3)+','+v[1].toFixed(3)+','+v[2].toFixed(3)+','+v[3].toFixed(3);
  let r; try{ r=await (await fetch('/api/fires?days=1&bbox='+encodeURIComponent(bbox))).json(); }
  catch(e){ if(explicit)toast('FIRMS request failed','warn'); return; }
  if(!r||!r.ok){ if(explicit)toast('FIRMS: '+((r&&r.error)||'error'),'warn');
    if(r&&/key/i.test(r.error||'')){ const c=$('#lyFire'); if(c)c.checked=false; const k=$('#fireKey'); if(k)k.style.display='none'; } return; }
  fireDS.entities.removeAll();
  (r.fires||[]).forEach(f=>{ fireDS.entities.add({ position:Cesium.Cartesian3.fromDegrees(+f.lng,+f.lat),
      billboard:{ image:fireIcon(fireColor(f.conf)), width:18, height:18,
        verticalOrigin:Cesium.VerticalOrigin.BOTTOM,
        disableDepthTestDistance:Number.POSITIVE_INFINITY,
        scaleByDistance:new Cesium.NearFarScalar(1.0e5,1.5,1.2e7,0.5) }, _fire:f }); });
  const key=$('#fireKey'); if(key)key.style.display='block';
  const fc=$('#fireCount'); if(fc)fc.textContent='NASA FIRMS · '+(r.count||0)+' detections · last 24h';
  if(explicit&&r.count===0) toast('No active fires in this view','ok');
  else if(explicit) toast(r.count+' active fire detection(s) in view','ok');
}
function showFire(f){ setInfo('<b>🔥 Active fire</b><div class="muted" style="margin-top:4px;line-height:1.6">'+
  (+f.lat).toFixed(3)+', '+(+f.lng).toFixed(3)+'<br>confidence: '+escapeHtml(f.conf||'—')+
  ' · FRP: '+escapeHtml(String(f.frp||'—'))+' MW<br>'+escapeHtml((f.date||'')+' '+(f.time||''))+' UTC · '+escapeHtml(f.sat||'')+
  '<br><span style="color:#8b97a5">NASA FIRMS detection — a thermal hotspot, not confirmed damage.</span></div>'); }


// ── horizon culling: hide icons on the FAR side of the globe (they use
//    "always on top" so the depth buffer won't hide them). Runs throttled every
//    frame so it keeps up with the auto-rotating globe.
let _cullLast=0, _occluder=null;
function cullOccluded(){
  if(!viewer) return;
  const now=performance.now(); if(now-_cullLast<200) return; _cullLast=now;
  try{
    if(!_occluder) _occluder=new Cesium.EllipsoidalOccluder(viewer.scene.globe.ellipsoid);
    _occluder.cameraPosition=viewer.camera.positionWC;
    const occ=_occluder, t=Cesium.JulianDate.now();
    const cull=e=>{ if(!e||!e.position||!e.position.getValue) return;
      let p; try{ p=e.position.getValue(t); }catch(_){ return; }
      if(p) e.show=occ.isPointVisible(p); };
    camEntities.forEach(cull);
    if(fireDS) fireDS.entities.values.forEach(cull);
    satEntities.forEach(s=>cull(s.e));
    locateEntities.forEach(cull); traceEntities.forEach(cull); overlayEntities.forEach(cull);
  }catch(e){}
}

// ── compass: rotate the rose to match camera heading; draggable + resizable ──
let _compassRose=null;
function updateCompass(){ if(!viewer)return;
  if(!_compassRose) _compassRose=document.getElementById('compassRose');
  if(!_compassRose)return;
  const deg=Cesium.Math.toDegrees(viewer.camera.heading);
  _compassRose.setAttribute('transform','rotate('+(-deg).toFixed(1)+' 50 50)'); }
// left tools panel: collapsible + draggable, and above the sat HUD (z-index in CSS)
function initPanel(){ const ap=$('#atlasPanel'), ah=$('#apHead'); if(!ap||!ah)return;
  const col=$('#apCollapse');
  if(col) col.onclick=e=>{ e.stopPropagation(); const c=ap.classList.toggle('collapsed'); col.textContent=c?'▸':'▾'; };
  ah.addEventListener('mousedown',e=>{ if(e.target.id==='apCollapse')return; e.preventDefault();
    const host=ap.parentElement.getBoundingClientRect(), r=ap.getBoundingClientRect(), ox=e.clientX-r.left, oy=e.clientY-r.top;
    ah.style.cursor='grabbing';
    const mv=ev=>{ ap.style.left=Math.max(0,ev.clientX-host.left-ox)+'px'; ap.style.top=Math.max(0,ev.clientY-host.top-oy)+'px'; ap.style.right='auto'; };
    const up=()=>{ ah.style.cursor='grab'; document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up); };
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up);
  });
}
function initCompass(){ const el=$('#compass'); if(!el)return; _compassRose=null;
  el.addEventListener('mousedown',e=>{
    const r=el.getBoundingClientRect();
    if(e.clientX>r.right-18 && e.clientY>r.bottom-18) return;      // let the resize corner work
    e.preventDefault(); const host=el.parentElement.getBoundingClientRect();
    const ox=e.clientX-r.left, oy=e.clientY-r.top; el.style.cursor='grabbing';
    const mv=ev=>{ el.style.left=Math.max(0,ev.clientX-host.left-ox)+'px'; el.style.top=Math.max(0,ev.clientY-host.top-oy)+'px'; el.style.bottom='auto'; };
    const up=()=>{ el.style.cursor='grab'; document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up); };
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up);
  });
  el.addEventListener('dblclick',()=>{ if(!viewer)return; const p=viewer.camera.positionCartographic;
    try{ viewer.camera.flyTo({ destination:Cesium.Cartesian3.fromRadians(p.longitude,p.latitude,p.height),
      orientation:{heading:0,pitch:viewer.camera.pitch,roll:0}, duration:0.6 }); }catch(e){} });
}

// HDR + MSAA — the heavier realism knobs, gated so users can drop them if it lags.
function setCinematic(on){ if(!viewer)return; const sc=viewer.scene;
  try{ if(sc.highDynamicRangeSupported) sc.highDynamicRange=!!on; }catch(e){}
  try{ sc.msaaSamples = on?2:1; sc.requestRender&&sc.requestRender(); }catch(e){}
  try{ localStorage.setItem('rode.atlasCine', on?'1':'0'); }catch(e){}
}

// ── camera and view helpers ──
function flyTo(lat,lng,h){ if(!viewer)return;
  try{ viewer.camera.flyTo({destination:Cesium.Cartesian3.fromDegrees(+lng,+lat,h||1500000),duration:1.4}); }catch(e){} }
function flyToEntities(list){ if(!viewer||!list.length)return;
  try{ viewer.flyTo(list,{duration:1.6}); }catch(e){ const f=list[0]; if(f&&f._pos) flyTo(f._pos.lat,f._pos.lng); } }
function setMeta(){ const el=$('#cmeta'); if(!el)return;
  const bits=[]; if(overlayEntities.length)bits.push(nodeCount()+' hosts');
  if(traceEntities.length)bits.push('trace active'); if(cams.length&&layers.cam)bits.push(cams.length+' cams');
  if(satEntities.length)bits.push(satEntities.length+' sats'); el.textContent=bits.join(' · '); }
function nodeCount(){ return overlayEntities.filter(e=>e._node).length; }
function setInfo(html){ const el=$('#atlasInfo'); if(el) el.innerHTML=html; }

// ── fly to a place name or "lat,lng" (QoL) ──
function _parseCoords(s){ const m=(s||'').trim().match(/^\s*(-?\d{1,3}(?:\.\d+)?)\s*[, ]\s*(-?\d{1,3}(?:\.\d+)?)\s*$/);
  if(!m) return null; const lat=+m[1], lng=+m[2];
  if(lat<-90||lat>90||lng<-180||lng>180) return null; return {lat,lng}; }
function spinOff(){ spinOn=false; const sc=$('#spin'); if(sc)sc.checked=false; try{ localStorage.setItem('rode.atlasSpin','0'); }catch(_){} }
async function doFlyTo(q){
  q=(q||'').trim(); if(!q||!viewer) return;
  const c=_parseCoords(q);
  if(c){ spinOff(); flyTo(c.lat,c.lng,45000); setInfo('<b>'+c.lat.toFixed(4)+', '+c.lng.toFixed(4)+'</b><br><span class="muted">coordinates</span>'); return; }
  setInfo('<span class="muted">searching “'+escapeHtml(q)+'”…</span>');
  let d; try{ d=await API('/geocode?q='+encodeURIComponent(q)); }catch(e){ setInfo('place lookup failed'); return; }
  if(!d || !d.ok){ setInfo('<span class="muted">no place found for “'+escapeHtml(q)+'”</span>'); toast('Place not found','warn'); return; }
  spinOff();
  if(d.west!=null){ try{ viewer.camera.flyTo({destination:Cesium.Rectangle.fromDegrees(d.west,d.south,d.east,d.north),duration:1.8}); }catch(e){ flyTo(d.lat,d.lng,60000); } }
  else flyTo(d.lat,d.lng,60000);
  setInfo('<b>'+escapeHtml(d.name||q)+'</b><br><span class="muted">'+(+d.lat).toFixed(3)+', '+(+d.lng).toFixed(3)+'</span>');
}

// ── locate an IP/domain ──
function clearLocate(){ locateEntities.forEach(e=>{try{viewer.entities.remove(e);}catch(_){}}); locateEntities=[]; }
async function doLocate(q){
  q=(q||'').trim(); if(!q){ toast('Type an IP or domain','warn'); return; }
  setInfo('<span class="muted">locating '+escapeHtml(q)+'…</span>');
  let d; try{ d=await API('/locate?q='+encodeURIComponent(q)); }catch(e){ setInfo('locate failed'); return; }
  if(!d || d.lat==null){ setInfo('<b>'+escapeHtml((d&&d.ip)||q)+'</b><br><span class="muted">'+escapeHtml((d&&d.country)||'no public location')+'</span>'); toast('No public gelocation for '+((d&&d.ip)||q),'warn'); return; }
  clearLocate();
  const e=viewer.entities.add({ position:Cesium.Cartesian3.fromDegrees(+d.lng,+d.lat),
    point:{pixelSize:13,color:Cesium.Color.fromCssColorString('#4ec9c0'),outlineColor:Cesium.Color.WHITE,outlineWidth:2,disableDepthTestDistance:Number.POSITIVE_INFINITY},
    label:{text:d.ip,font:'11px sans-serif',fillColor:Cesium.Color.fromCssColorString('#d7f0ec'),pixelOffset:new Cesium.Cartesian2(0,-18),showBackground:true,backgroundColor:Cesium.Color.fromCssColorString('rgba(13,17,23,.8)')} });
  e._loc=d; e._pos={lat:d.lat,lng:d.lng}; locateEntities.push(e);
  flyTo(d.lat,d.lng,1200000); showLoc(d);
}
function showLoc(d){
  setInfo(`<b>${escapeHtml(d.ip)}</b><div class="muted" style="margin:3px 0 8px">${escapeHtml([d.city,d.country].filter(Boolean).join(', ')||'located')}</div>`+
    `<button class="sm" id="locAdd">＋ add to graph</button>`);
  const b=$('#locAdd'); if(b) b.onclick=()=>addToGraph('ip', d.ip, {lat:d.lat,lng:d.lng,city:d.city,country:d.country,source:'atlas-locate'});
}

// ── traceroute across the globe ──
function clearTrace(){ traceEntities.forEach(e=>{try{viewer.entities.remove(e);}catch(_){}}); traceEntities=[]; }
async function doTrace(target){
  target=(target||'').trim(); if(!target){ toast('Enter a host to trace','warn'); return; }
  if(!layers.trace){ layers.trace=true; const c=$('#lyTrace'); if(c)c.checked=true; }
  setInfo('<span class="muted">tracing route to '+escapeHtml(target)+'…<br>this can take 20–40s (per-hop probes).</span>');
  let d; try{ d=await API('/traceroute?target='+encodeURIComponent(target)); }catch(e){ setInfo('traceroute failed'); return; }
  if(!d.ok){ setInfo('<span class="muted">'+escapeHtml(d.error||'traceroute failed')+'</span>'); toast(d.error||'traceroute failed','warn'); return; }
  clearTrace();
  const geo=d.hops.filter(h=>h.lat!=null&&h.lng!=null);
  geo.forEach((h,i)=>{ const last=i===geo.length-1;
    const col=last?'#e0686a':(i===0?'#5fbf8a':'#d9a441');
    const e=viewer.entities.add({ position:Cesium.Cartesian3.fromDegrees(+h.lng,+h.lat),
      point:{pixelSize:last?12:9,color:Cesium.Color.fromCssColorString(col),outlineColor:Cesium.Color.BLACK,outlineWidth:1.5,disableDepthTestDistance:Number.POSITIVE_INFINITY},
      label:{text:'#'+h.hop,font:'9px monospace',fillColor:Cesium.Color.fromCssColorString('#c9d3df'),pixelOffset:new Cesium.Cartesian2(0,-14),
        translucencyByDistance:new Cesium.NearFarScalar(5e6,1,3e7,0)} });
    e._hop=h; e._pos={lat:h.lat,lng:h.lng}; traceEntities.push(e); });
  if(geo.length>1){ const pos=[]; geo.forEach(h=>pos.push(+h.lng,+h.lat));
    const line=viewer.entities.add({ polyline:{ positions:Cesium.Cartesian3.fromDegreesArray(pos), width:2.5,
      arcType:Cesium.ArcType.GEODESIC, material:new Cesium.PolylineGlowMaterialProperty({glowPower:0.22,color:Cesium.Color.fromCssColorString('#e08a48')}) } });
    traceEntities.push(line); }
  renderTraceList(d, geo);
  if(geo.length) flyToEntities(traceEntities.filter(e=>e._hop));
  else toast('No hops could be geolocated (all private/LAN).','warn');
}
function renderTraceList(d, geo){
  const rows=d.hops.map(h=>{
    const loc=h.lat!=null?escapeHtml([h.city,h.country].filter(Boolean).join(', ')):'<span class="muted">'+(h.ip?escapeHtml(h.country||'private'):'—')+'</span>';
    return `<div class="tr-hop"><span class="tr-n">#${h.hop}</span><span class="tr-ip mono">${h.ip?escapeHtml(h.ip):'* timeout'}</span><span class="tr-loc">${loc}</span></div>`;
  }).join('');
  setInfo(`<b>traceroute → ${escapeHtml(d.target)}</b><div class="muted" style="margin:2px 0 7px">${d.hops.length} hops · ${geo.length} located</div><div class="tr-list">${rows}</div>`);
}
function showHop(h){
  setInfo(`<b>hop #${h.hop}</b><div class="mono" style="margin:3px 0">${escapeHtml(h.ip||'timeout')}</div>`+
    `<div class="muted" style="margin-bottom:8px">${escapeHtml([h.city,h.country].filter(Boolean).join(', ')||'—')}</div>`+
    (h.ip&&h.lat!=null?`<button class="sm" id="hopAdd">＋ add to graph</button>`:''));
  const b=$('#hopAdd'); if(b) b.onclick=()=>addToGraph('ip', h.ip, {lat:h.lat,lng:h.lng,city:h.city,country:h.country,source:'traceroute'});
}

// ── investigation overlay (geolocated entities + relationship arcs) ──
function clearOverlay(){ overlayEntities.forEach(e=>{try{viewer.entities.remove(e);}catch(_){}}); overlayEntities=[]; }
async function loadOverlay(){
  clearOverlay();
  const cEl=$('#cInv');
  if(!layers.inv || !S.inv){ if(cEl)cEl.textContent=''; setMeta(); return; }
  if(cEl)cEl.textContent='…';
  try{ await fetch('/api/investigations/'+S.inv+'/geolocate',{method:'POST'}); }catch(e){}
  let g; try{ g=await API('/graph/'+S.inv); }catch(e){ if(cEl)cEl.textContent=''; return; }
  const nodes=(g.nodes||[]).map(n=>n.data).filter(n=>n.lat!=null&&n.lng!=null);
  const byId={}; nodes.forEach(n=>byId[n.id]=n);
  nodes.forEach(n=>{ const col=typeColor(n.type);
    const e=viewer.entities.add({ position:Cesium.Cartesian3.fromDegrees(+n.lng,+n.lat),
      point:{pixelSize:11,color:Cesium.Color.fromCssColorString(col),outlineColor:Cesium.Color.BLACK,outlineWidth:1.5,disableDepthTestDistance:Number.POSITIVE_INFINITY},
      label:{text:n.label,font:'10px sans-serif',fillColor:Cesium.Color.fromCssColorString('#c9d3df'),pixelOffset:new Cesium.Cartesian2(0,-16),
        showBackground:true,backgroundColor:Cesium.Color.fromCssColorString('rgba(13,17,23,.75)'),
        translucencyByDistance:new Cesium.NearFarScalar(8e6,1,4e7,0)} });
    e._node=n; e._pos={lat:n.lat,lng:n.lng}; overlayEntities.push(e); });
  (g.edges||[]).forEach(ed=>{ const s=byId[ed.data.source], t=byId[ed.data.target]; if(!s||!t||s===t)return;
    const line=viewer.entities.add({ polyline:{ positions:Cesium.Cartesian3.fromDegreesArray([+s.lng,+s.lat,+t.lng,+t.lat]),
      width:1.5, arcType:Cesium.ArcType.GEODESIC, material:Cesium.Color.fromCssColorString('#4bb8d0').withAlpha(0.45) } });
    line._edge=true; overlayEntities.push(line); });
  if(cEl)cEl.textContent=String(nodes.length);
  setMeta();
  if(nodes.length && !locateEntities.length && !traceEntities.length) flyToEntities(overlayEntities.filter(e=>e._node));
}
function showNode(n){
  setInfo(`<b>${escapeHtml(n.label)}</b><div class="muted" style="margin:3px 0 4px">${escapeHtml(n.type)} · ${escapeHtml(n.value)}</div>`+
    `<button class="sm" id="nodeOpen">open in graph →</button>`);
  const b=$('#nodeOpen'); if(b) b.onclick=()=>{ if(S.ctx) S.ctx.focusEntity=n.entity_id; location.hash='#/investigation'; };
}
async function addToGraph(type, value, meta){
  if(!S.inv){ toast('Create/select an investigation first','warn'); return; }
  try{ await fetch('/api/entities/add',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({investigation_id:S.inv,type,value,label:value,metadata:meta||{},link_type:null,link_value:null})});
    toast('Added '+value+' to graph','ok'); if(layers.inv) loadOverlay();
  }catch(e){ toast('Could not add to graph','warn'); }
}

// ── cameras (optional layer, off by default) ──
// Each source auto-imports when the globe view intersects its bounds
// [west, south, east, north]. Government DOT feeds — public, no account.
const CAM_SOURCES=[
  {id:'tfl', name:'London (TfL)',   bounds:[-0.62, 51.20, 0.36, 51.76]},
  {id:'nyc', name:'New York (DOT)', bounds:[-74.30, 40.48, -73.68, 40.93]},
  {id:'caltrans', name:'California (Caltrans)', bounds:[-124.6, 32.4, -114.0, 42.1]},
  // "One Network" 511 family — US states + Canadian provinces
  {id:'on',     name:'Ontario 511',       bounds:[-95.2, 41.6, -74.0, 51.5]},
  {id:'ab',     name:'Alberta 511',       bounds:[-120.1, 48.9, -109.9, 60.1]},
  {id:'ns',     name:'Nova Scotia 511',   bounds:[-66.5, 43.3, -59.7, 47.1]},
  {id:'sk',     name:'Saskatchewan 511',  bounds:[-110.0, 48.9, -101.3, 60.1]},
  {id:'nv',     name:'Nevada NDOT',       bounds:[-120.1, 34.9, -113.9, 42.1]},
  {id:'wi',     name:'Wisconsin 511',     bounds:[-92.9, 42.4, -86.7, 47.1]},
  {id:'pa',     name:'Pennsylvania 511',  bounds:[-80.6, 39.6, -74.6, 42.4]},
  {id:'ne_usa', name:'New England 511',   bounds:[-73.6, 42.6, -66.8, 47.6]},
  {id:'neska',  name:'Nebraska 511',      bounds:[-104.1, 39.9, -95.2, 43.1]},
  {id:'la',     name:'Louisiana 511',     bounds:[-94.1, 28.8, -88.7, 33.1]},
  {id:'mb',     name:'Manitoba 511',      bounds:[-102.1, 48.9, -88.9, 60.1]},
  {id:'nb',     name:'New Brunswick 511', bounds:[-69.1, 44.5, -63.7, 48.1]},
  {id:'pei',    name:'PEI 511',           bounds:[-64.5, 45.9, -61.9, 47.1]},
  {id:'nl',     name:'Newfoundland 511',  bounds:[-59.5, 46.5, -52.5, 55.5]},
];
function viewRectDeg(){ if(!viewer)return null;
  try{ const r=viewer.camera.computeViewRectangle(); if(!r)return null;
    const D=Cesium.Math.toDegrees; return [D(r.west),D(r.south),D(r.east),D(r.north)]; }catch(e){ return null; } }
function camH(){ try{ return viewer.camera.positionCartographic.height; }catch(e){ return 1e12; } }
function bInt(a,b){ return a[0]<=b[2]&&a[2]>=b[0]&&a[1]<=b[3]&&a[3]>=b[1]; }
function inV(c,v){ if(!v)return true; const x=+c.lng,y=+c.lat; return x>=v[0]&&x<=v[2]&&y>=v[1]&&y<=v[3]; }
let windySaved=false;
let windyTiles=new Set();     // ~1° areas already queried from Windy, to avoid re-hitting the API
async function initWindy(){
  try{ const st=await API('/secrets'); windySaved=!!(st&&st.windy); }catch(e){}
  // migrate any old browser-stored key to the gitignored server store, then clear it
  try{ const old=(localStorage.getItem('rode.windyKey')||'').trim();
    if(old && !windySaved){ await fetch('/api/secrets/windy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:old})}); windySaved=true; }
    if(old) localStorage.removeItem('rode.windyKey');
  }catch(e){}
  const wk=$('#windyKey'); if(wk && windySaved) wk.placeholder='Windy key saved ✓';
}
async function queryWindy(explicit){
  if(!windySaved){ if(explicit)toast('Save your Windy key first','warn'); return false; }
  const v=viewRectDeg(); if(!v){ if(explicit)toast('Zoom to a place on the globe first','warn'); return false; }
  const spanLat=v[3]-v[1], spanLng=v[2]-v[0];
  const radius=Math.min(250, Math.max(25, Math.round(spanLat*111/3)));
  const step=Math.max(0.6,(radius/111)*1.7);                       // ~2×radius so circles tile
  const cols=Math.min(3,Math.max(1,Math.ceil(spanLng/step)));
  const rows=Math.min(3,Math.max(1,Math.ceil(spanLat/step)));
  const pts=[];
  for(let r=0;r<rows;r++) for(let c=0;c<cols;c++){
    const lat=v[1]+spanLat*(r+0.5)/rows, lng=v[0]+spanLng*(c+0.5)/cols;
    const key=Math.round(lat)+','+Math.round(lng);
    if(!explicit && windyTiles.has(key)) continue;                 // already covered this area
    windyTiles.add(key); pts.push([lat,lng]);
  }
  if(!explicit && pts.length>6) pts.length=6;                      // keep auto-pans quota-friendly
  if(!pts.length) return false;
  if(explicit){ setInfo('<span class="muted">querying Windy across '+pts.length+' point(s) ('+radius+'km each)…</span>'); }
  let total=0, okAny=false;
  for(const [lat,lng] of pts){
    let res;
    try{ res=await fetch('/api/cams/windy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({lat,lng,radius})}); }
    catch(e){ continue; }
    if(res.status===404){ if(explicit)toast('Windy endpoint missing — restart the R.O.D.E server','warn'); return false; }
    if(!res.ok) continue;
    let r; try{ r=await res.json(); }catch(e){ continue; }
    if(r&&r.ok){ okAny=true; total+=r.added||0; }
    else if(r&&r.error){ if(explicit){ toast('Windy: '+r.error,'warn'); setInfo('<span class="muted">Windy error: '+escapeHtml(r.error)+'</span>'); } return false; }
  }
  if(total){ toast('Loaded '+total+' Windy webcams','ok'); if(explicit)setInfo('<span class="muted">'+total+' Windy webcams loaded across this view.</span>'); }
  else if(explicit){ toast('No Windy webcams in this view','warn'); setInfo('<span class="muted">Windy returned 0 here — try a bigger city.</span>'); }
  return okAny;
}
async function autoImportForView(){
  if(!layers.cam || camH()>4000000) return false;
  const v=viewRectDeg(); if(!v)return false; let did=false;
  for(const src of CAM_SOURCES){ if(importedSources.has(src.id)||!bInt(src.bounds,v)) continue;
    importedSources.add(src.id);
    try{ const r=await fetch('/api/cams/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:src.id})}).then(x=>x.json());
      if(r&&r.ok&&r.added){ toast('Loaded '+r.added+' cameras · '+src.name,'ok'); did=true; }
      else if(r&&!r.ok){ importedSources.delete(src.id); } }catch(e){ importedSources.delete(src.id); } }
  if(await queryWindy(false)) did=true;
  return did;
}
function clearCamEntities(){ if(camDS)camDS.entities.removeAll(); camEntities=[]; }
// classify a camera by its name/place so we can show a telling icon at a glance
const CAM_KINDS={
  highway:{c:'#e0863a',label:'highway',g:"<path d='M12 4v4M12 11v2M12 16v4'/>"},
  intersection:{c:'#4a90d9',label:'intersection',g:"<path d='M12 4v16M4 12h16'/>"},
  roundabout:{c:'#38b2ac',label:'roundabout',g:"<circle cx='12' cy='12' r='4.5'/>"},
  transit:{c:'#a06cd5',label:'metro / rail',g:"<rect x='7.5' y='5' width='9' height='11' rx='2'/><path d='M9 19l1.5-3M15 19l-1.5-3'/>"},
  bridge:{c:'#c0894a',label:'bridge / tunnel',g:"<path d='M3 14c4 0 4-4 9-4s5 4 9 4M4 14v4M20 14v4'/>"},
  street:{c:'#5fbf8a',label:'street',g:"<circle cx='12' cy='12' r='3'/>"},
  webcam:{c:'#e0a24b',label:'webcam',g:"<rect x='5.5' y='8' width='10' height='8' rx='1.5'/><path d='M15.5 10.5l4-2v7l-4-2z'/>"},
};
function camKind(c){
  if((c.type||'')==='webcam') return 'webcam';
  const s=((c.name||'')+' '+(c.place||'')).toLowerCase();
  if(/round\s?about|traffic circle|rotary/.test(s)) return 'roundabout';
  if(/\b(metro|subway|rail|train|station|transit|platform|light\s?rail|lrt|tram)\b/.test(s)) return 'transit';
  if(/\b(bridge|tunnel|overpass|viaduct|crossing)\b/.test(s)) return 'bridge';
  if(/\b(hwy|highway|freeway|motorway|interstate|expressway|expy|autoroute|turnpike|qew|i-?\d|us-?\d|sr-?\d|route)\b/.test(s)) return 'highway';
  if(/ at |&| and |intersection|junction|\bjct\b|@/.test(s)) return 'intersection';
  return 'street';
}
const _camIconCache={};
function camIcon(kind){
  if(_camIconCache[kind]) return _camIconCache[kind];
  const k=CAM_KINDS[kind]||CAM_KINDS.street;
  const uri="data:image/svg+xml,"+encodeURIComponent(
    "<svg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 24 24'>"+
    "<circle cx='12' cy='12' r='11' fill='"+k.c+"' stroke='#0a0d12' stroke-width='1.6'/>"+
    "<g fill='none' stroke='#0a0d12' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'>"+k.g+"</g></svg>");
  _camIconCache[kind]=uri; return uri;
}
function renderCamLegend(){
  const el=$('#camLegend'); if(!el)return;
  el.style.display=layers.cam?'block':'none';
  if(!el.dataset.built){
    el.innerHTML=Object.keys(CAM_KINDS).map(k=>`<div><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${CAM_KINDS[k].c};margin-right:6px;vertical-align:middle"></span>${CAM_KINDS[k].label}</div>`).join('');
    el.dataset.built='1';
  }
}
function addCamEntities(){
  if(!viewer)return; clearCamEntities();
  if(!layers.cam){ setMeta(); return; }
  const v=viewRectDeg();
  cams.filter(c=>c.lat&&c.lng&&inV(c,v)).forEach(c=>{
    const kind=camKind(c);
    const e=camDS.entities.add({ position:Cesium.Cartesian3.fromDegrees(+c.lng,+c.lat),
      billboard:{ image:camIcon(kind), width:22, height:22, disableDepthTestDistance:Number.POSITIVE_INFINITY,
        scaleByDistance:new Cesium.NearFarScalar(1.0e5,1.7,1.0e7,0.62) } });
    e._cam=c; e._kind=kind; camEntities.push(e); });
  setMeta();
}
async function loadCams(){
  let d; try{ d=await API('/cams'); }catch(e){ return; } cams=d.cameras||[];
  const imp=await autoImportForView(); if(imp){ try{ d=await API('/cams'); cams=d.cameras||[]; }catch(e){} }
  addCamEntities();
}
function onViewChanged(){
  clearTimeout(viewChangeTimer);
  const fl=$('#lyFire'); if(fl&&fl.checked){ clearTimeout(fireTimer); fireTimer=setTimeout(()=>loadFires(false),700); }
  viewChangeTimer=setTimeout(async ()=>{ if(!layers.cam)return;
    const imp=await autoImportForView(); if(imp){ try{ const d=await API('/cams'); cams=d.cameras||[]; }catch(e){} }
    addCamEntities(); }, 450);
}

// ── satellites (optional layer, off by default) ──
async function loadSats(){
  if(!viewer || typeof satellite==='undefined') return;
  try{ const d=await API('/satellites'); const sats=d.sats||[];
    sats.forEach(s=>{ let rec; try{ rec=satellite.twoline2satrec(s.l1,s.l2); }catch(e){ return; }
      // billboard icon (bigger, clickable); no disableDepthTestDistance so the
      // globe occludes satellites on its far side
      const e=viewer.entities.add({ billboard:{ image:SAT_ICON, width:30, height:30,
          verticalOrigin:Cesium.VerticalOrigin.CENTER,
          scaleByDistance:new Cesium.NearFarScalar(1.0e6,1.35,3.2e7,0.72) },
        label:{text:s.name,font:'bold 10px monospace',fillColor:Cesium.Color.CYAN.withAlpha(0.9),
          outlineColor:Cesium.Color.BLACK,outlineWidth:2,style:Cesium.LabelStyle.FILL_AND_OUTLINE,
          pixelOffset:new Cesium.Cartesian2(15,0), show:false} });   // shown only on hover (declutter)
      e._sat={name:s.name,rec}; satEntities.push({rec,e}); });
    updateSats(); if(satTimer)clearInterval(satTimer); satTimer=setInterval(updateSats,2000); setMeta();
  }catch(e){}
}
function updateSats(){ if(!satEntities.length)return; const now=new Date(), gmst=satellite.gstime(now);
  satEntities.forEach(s=>{ try{ const pv=satellite.propagate(s.rec,now); if(!pv||!pv.position)return;
    const geo=satellite.eciToGeodetic(pv.position,gmst);
    s.e.position=Cesium.Cartesian3.fromDegrees(satellite.degreesLong(geo.longitude),satellite.degreesLat(geo.latitude),geo.height*1000);
  }catch(e){} }); }
function clearSats(){ if(satTimer){clearInterval(satTimer);satTimer=null;} satEntities.forEach(s=>{try{viewer.entities.remove(s.e);}catch(e){}}); satEntities=[]; setMeta(); }

// ── simulated satellite viewpoint ──
function enterSatView(sat){ if(!viewer)return; closeModal(); satView=true; satViewSat=sat; satViewTime=new Date(); satLastFrame=0;
  try{ viewer.camera.lookAtTransform(Cesium.Matrix4.IDENTITY); viewer.scene.screenSpaceCameraController.enableInputs=false; }catch(e){}
  try{ const now=new Date(), pv=satellite.propagate(sat.rec,now), gmst=satellite.gstime(now), geo=satellite.eciToGeodetic(pv.position,gmst);
    satViewAlt=Math.max(180000, Math.min(geo.height*1000,1600000)); }catch(e){ satViewAlt=700000; }
  $('#satViewName').textContent=sat.name||'satellite'; $('#satView').style.display='block'; followSat();
}
function followSat(){ if(!viewer||!satViewSat)return; const t=performance.now(); if(!satLastFrame)satLastFrame=t;
  satViewTime=new Date(satViewTime.getTime()+(t-satLastFrame)*satSpeed); satLastFrame=t;
  try{ const pv=satellite.propagate(satViewSat.rec,satViewTime), gmst=satellite.gstime(satViewTime), geo=satellite.eciToGeodetic(pv.position,gmst);
    const lo=satellite.degreesLong(geo.longitude), la=satellite.degreesLat(geo.latitude);
    viewer.camera.setView({ destination:Cesium.Cartesian3.fromDegrees(lo,la,satViewAlt),
      orientation:{heading:0,pitch:-Cesium.Math.PI_OVER_TWO,roll:0} });
    if(t-satHudLast>180){ satHudLast=t;
      const te=$('#svTelem'); if(te)te.innerHTML='LAT '+la.toFixed(4)+'°<br>LON '+lo.toFixed(4)+'°<br>ALT '+(satViewAlt/1000).toFixed(0)+' km';
      const ck=$('#svClock'); if(ck)ck.textContent=satViewTime.toISOString().substr(11,8); }
  }catch(e){} }
function exitSatView(){ satView=false; satViewSat=null; $('#satView').style.display='none';
  try{ viewer.scene.screenSpaceCameraController.enableInputs=true; }catch(e){}
  if($('#spin')) spinOn=$('#spin').checked; if(viewer){ try{ viewer.camera.flyHome(1.4); }catch(e){} } }
function svZoom(inward){ satViewAlt=Math.max(150, Math.min(satViewAlt*(inward?0.6:1.55),9000000)); }

// ── camera modal ──
function openModal(){ modalOpen=true; $('#cmBg').classList.add('show'); $('#cmModal').classList.add('show'); }
function closeModal(){ modalOpen=false; if(timer){clearInterval(timer);timer=null;}
  if(mediaHls){ try{mediaHls.destroy();}catch(e){} mediaHls=null; }
  const v=$('#cmVid'); if(v){ try{v.pause(); v.removeAttribute('src'); v.load();}catch(e){} }
  const img=$('#cmImg'); if(img)img.src='';
  $('#cmBg').classList.remove('show'); $('#cmModal').classList.remove('show'); }
function openSat(sat){
  let alt='?',spd='?';
  try{ const now=new Date(), pv=satellite.propagate(sat.rec,now), gmst=satellite.gstime(now);
    if(pv&&pv.position){ const geo=satellite.eciToGeodetic(pv.position,gmst); alt=geo.height.toFixed(0);
      const vv=pv.velocity; spd=Math.sqrt(vv.x*vv.x+vv.y*vv.y+vv.z*vv.z).toFixed(2); } }catch(e){}
  const iss=/ISS|ZARYA|25544/i.test(sat.name||'');
  $('#cmTitle').textContent=sat.name||'satellite';
  $('#cmSub').textContent='satellite · live orbital data (Celestrak TLE)';
  $('#cmBody').innerHTML=`<div class="muted" style="line-height:1.7">Real satellite — positions computed live from <b>Celestrak</b> orbital elements.
    <div style="margin-top:10px;display:flex;gap:24px"><div><div class="ins-run-t">Altitude</div><b style="font-size:17px;color:var(--text)">${alt} km</b></div>
      <div><div class="ins-run-t">Speed</div><b style="font-size:17px;color:var(--text)">${spd} km/s</b></div></div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="primary" id="satViewBtn" style="padding:7px 12px">▣ View from this satellite (simulated)</button>
      ${iss?'<a href="https://www.nasa.gov/live/" target="_blank" rel="noopener" style="background:var(--surface2);color:var(--text);text-decoration:none;padding:7px 12px;border-radius:7px;border:1px solid var(--line)">▶ Watch the ISS live (NASA)</a>':''}</div></div>`;
  openModal(); const b=$('#satViewBtn'); if(b)b.onclick=()=>enterSatView(sat);
}
function mediaOf(cam){ const v=cam.video||(cam.url&&/\.mp4(\?|$)/i.test(cam.url)?cam.url:'');
  const hls=(cam.url&&/\.m3u8(\?|$)/i.test(cam.url))?cam.url:''; return {v,hls,img:(!v&&!hls&&cam.url)?cam.url:''}; }
function openCam(cam){
  $('#cmTitle').textContent=cam.name;
  $('#cmSub').textContent=[cam.type, cam.place||cam.country, `${(+cam.lat).toFixed(3)}, ${(+cam.lng).toFixed(3)}`].filter(Boolean).join(' · ');
  const body=$('#cmBody'), m=mediaOf(cam);
  const foot=`<div style="margin-top:8px;display:flex;gap:8px;align-items:center"><span class="muted" id="cmStat"></span><div class="spacer"></div><button class="sm danger" id="cmDel">Delete feed</button></div>`;
  if(m.v){ body.innerHTML=`<video id="cmVid" autoplay loop muted playsinline controls style="width:100%;border-radius:8px;background:#000;min-height:220px"></video>`+foot;
    const v=$('#cmVid'); const bust=()=>m.v+(m.v.includes('?')?'&':'?')+'_='+Date.now(); v.src=bust();
    $('#cmStat').textContent='clip refreshes ~90s'; timer=setInterval(()=>{ try{ v.src=bust(); v.load(); v.play().catch(()=>{}); }catch(e){} },90000);
  } else if(m.hls){ body.innerHTML=`<video id="cmVid" autoplay muted playsinline controls style="width:100%;border-radius:8px;background:#000;min-height:220px"></video>`+foot;
    const v=$('#cmVid'); $('#cmStat').textContent='live stream (HLS)';
    if(window.Hls&&window.Hls.isSupported()){ mediaHls=new Hls(); mediaHls.loadSource(m.hls); mediaHls.attachMedia(v); } else { v.src=m.hls; }
  } else if(m.img){ body.innerHTML=`<img id="cmImg" alt="feed" style="width:100%;border-radius:8px;background:#000;min-height:220px;object-fit:contain"/>`+foot;
    const img=$('#cmImg'); img.onerror=()=>{ $('#cmStat').textContent='feed offline or blocks embedding'; };
    img.onload=()=>{ $('#cmStat').textContent='snapshot · refreshing 1.5s'; };
    const tick=()=>{ img.src='/api/cams/'+cam.id+'/snapshot?t='+Date.now(); }; tick(); timer=setInterval(tick,1500);
  } else { body.innerHTML=`<div class="muted">No feed set for this point.</div>`+foot; }
  const del=$('#cmDel'); if(del)del.onclick=()=>delCam(cam); openModal();
}
function delCam(cam){ fetch('/api/cams/'+cam.id,{method:'DELETE'}).then(()=>{ closeModal(); toast('Removed','warn'); loadCams(); }); }

// ── floating camera windows: open many feeds at once, drag/resize/close each ──
function openCamWindow(cam){
  // parented to <body> (position:fixed) so moving a window never touches the globe render
  const host=document.body;
  const dup=camWindows.find(w=>w.camId===cam.id);
  if(dup){ dup.el.style.zIndex=(++_camZ); dup.el.style.outline='2px solid #4ec9c0'; setTimeout(()=>{try{dup.el.style.outline='';}catch(e){}},600); return; }
  const n=camWindows.length%6;
  const W=Math.min(560, Math.max(360, Math.round(window.innerWidth*0.34))), H=Math.round(W*0.7);
  const left=Math.max(20, Math.round((window.innerWidth-W)/2)+(n-2)*30);
  const top=Math.max(16, Math.round((window.innerHeight-H)/2)+(n-2)*26);
  const win=document.createElement('div');
  win.style.cssText='position:fixed;z-index:'+(++_camZ)+';left:'+left+'px;top:'+top+'px;width:'+W+'px;height:'+H+'px;'+
    'background:#0b0e13;border:1px solid rgba(255,255,255,.18);border-radius:10px;overflow:hidden;resize:both;'+
    'min-width:220px;min-height:170px;max-width:96vw;max-height:90vh;box-shadow:0 18px 50px rgba(0,0,0,.6);display:flex;flex-direction:column';
  win.innerHTML='<div class="cw-bar" style="display:flex;align-items:center;gap:6px;padding:6px 8px;background:#141a22;cursor:grab;flex:0 0 auto;user-select:none">'+
    '<span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11.5px;color:#dbe3ea">'+escapeHtml(cam.name||'camera')+'</span>'+
    '<span class="cw-stat" style="font-size:9px;color:#8b97a5"></span>'+
    '<button class="cw-x" title="Close" style="background:transparent;border:0;color:#c9d3df;cursor:pointer;font-size:16px;line-height:1;padding:0 3px">&times;</button></div>'+
    '<div class="cw-body" style="flex:1;min-height:0;background:#000;position:relative"></div>';
  host.appendChild(win);
  const bar=win.querySelector('.cw-bar'), body=win.querySelector('.cw-body'), stat=win.querySelector('.cw-stat');
  const rec={el:win, camId:cam.id, timer:null, hls:null};
  camWindows.push(rec);
  const m=mediaOf(cam);
  if(m.v||m.hls){
    const v=document.createElement('video'); v.autoplay=true; v.muted=true; v.loop=!!m.v; v.playsInline=true; v.controls=true;
    v.style.cssText='width:100%;height:100%;object-fit:contain;background:#000'; body.appendChild(v);
    if(m.hls){ stat.innerHTML='<span style="color:#5fbf8a">● LIVE</span>'; stat.title='Live video stream (HLS)';
      if(window.Hls&&window.Hls.isSupported()){ rec.hls=new Hls(); rec.hls.loadSource(m.hls); rec.hls.attachMedia(v); } else { v.src=m.hls; } }
    else { const bust=()=>m.v+(m.v.includes('?')?'&':'?')+'_='+Date.now(); v.src=bust();
      stat.innerHTML='<span style="color:#6ea8fe">▸ CLIP</span>'; stat.title='Short video clip, reloaded every ~90s';
      rec.timer=setInterval(()=>{ try{ v.src=bust(); v.load(); v.play().catch(()=>{}); }catch(e){} },90000); }
  } else if(m.img){
    const img=document.createElement('img'); img.alt='feed'; img.style.cssText='width:100%;height:100%;object-fit:contain;background:#000'; body.appendChild(img);
    stat.title='Still snapshot re-fetched every 2.5s (some sources only refresh every 30–60s at the origin)';
    img.onerror=()=>{ stat.innerHTML='<span style="color:#e0686a">○ OFFLINE</span>'; };
    img.onload=()=>{ stat.innerHTML='<span style="color:#e0a24b">◉ SNAPSHOT</span> <span class="cw-ref" style="color:#5fbf8a;transition:opacity .6s">↻</span>';
      const rf=stat.querySelector('.cw-ref'); if(rf) setTimeout(()=>{ try{ rf.style.opacity='0'; }catch(e){} }, 500); };
    const tick=()=>{ if(document.hidden)return; img.src='/api/cams/'+cam.id+'/snapshot?t='+Date.now(); }; tick(); rec.timer=setInterval(tick,2500);
  } else { body.innerHTML='<div style="color:#8b97a5;padding:16px;font-size:12px">No feed set for this point.</div>'; }
  win.querySelector('.cw-x').onclick=()=>closeCamWindow(rec);
  win.addEventListener('mousedown',()=>{ win.style.zIndex=(++_camZ); });
  bar.addEventListener('mousedown',e=>{ if(e.target.classList.contains('cw-x'))return; e.preventDefault();
    const r=win.getBoundingClientRect(), ox=e.clientX-r.left, oy=e.clientY-r.top; bar.style.cursor='grabbing';
    const mv=ev=>{ win.style.left=Math.max(0,ev.clientX-ox)+'px'; win.style.top=Math.max(0,ev.clientY-oy)+'px'; };
    const up=()=>{ bar.style.cursor='grab'; document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up); };
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up);
  });
  setInfo('<b>'+escapeHtml(cam.name||'camera')+'</b><div class="muted" style="margin-top:3px">'+escapeHtml([cam.type,cam.place||cam.country].filter(Boolean).join(' · '))+'</div><div class="muted" style="font-size:10.5px;margin-top:5px">Opened in a floating window — drag the title bar, resize from the corner, × to close. Open as many as you like.</div>');
}
function closeCamWindow(rec){
  if(rec.timer)clearInterval(rec.timer);
  if(rec.hls){ try{ rec.hls.destroy(); }catch(e){} }
  const v=rec.el.querySelector('video'); if(v){ try{ v.pause(); v.removeAttribute('src'); v.load(); }catch(e){} }
  try{ rec.el.remove(); }catch(e){}
  camWindows=camWindows.filter(w=>w!==rec);
}
function closeAllCamWindows(){ camWindows.slice().forEach(closeCamWindow); }

function mount(root){
  root.innerHTML=shell();
  $('#cmClose').onclick=closeModal; $('#cmBg').onclick=closeModal;
  $('#placeGo').onclick=()=>doFlyTo($('#placeInput').value);
  $('#placeInput').onkeydown=e=>{ if(e.key==='Enter') doFlyTo(e.target.value); };
  $('#locGo').onclick=()=>doLocate($('#locInput').value);
  $('#locInput').onkeydown=e=>{ if(e.key==='Enter') doLocate(e.target.value); };
  $('#trGo').onclick=()=>doTrace($('#trInput').value);
  $('#trInput').onkeydown=e=>{ if(e.key==='Enter') doTrace(e.target.value); };
  $('#globeOptsHdr').onclick=()=>{ const o=$('#globeOpts'); const open=o.style.display==='none'; o.style.display=open?'block':'none'; $('#globeOptsHdr').textContent='Globe options '+(open?'▾':'▸'); };
  if(typeof Cesium==='undefined'){
    $('#cesiumViz').style.display='none';
    $('#glbFallback').innerHTML='<div class="muted" style="padding:40px 24px">The 3D globe engine (CesiumJS) didn\'t load — it needs internet access to its CDN. The rest of R.O.D.E works offline; reconnect and reload this tab.</div>';
    return;
  }
  try{ initCesium(); }catch(e){ $('#glbFallback').innerHTML='<div class="muted" style="padding:24px">Globe failed to initialise: '+escapeHtml(String(e).slice(0,140))+'</div>'; return; }
  $('#base').onchange=e=>setBase(e.target.value);
  $('#hill').onchange=e=>setHill(e.target.checked);
  $('#labels').onchange=e=>setLabels(e.target.checked);
  $('#sun').onchange=e=>{ if(viewer)viewer.scene.globe.enableLighting=e.target.checked; };
  $('#cine').onchange=e=>setCinematic(e.target.checked);
  $('#lyRain').onchange=e=>setRain(e.target.checked);
  $('#lyFire').onchange=e=>setFires(e.target.checked);
  const fk=$('#firmsKey'); if(fk){ fk.onkeydown=ev=>{ if(ev.key==='Enter') $('#firmsGo').click(); }; }
  $('#firmsGo').onclick=async ()=>{ const val=(fk&&fk.value.trim())||'';
    if(val){ try{ await fetch('/api/secrets/firms',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:val})}); }catch(e){}
      firmsSaved=true; if(fk){ fk.value=''; fk.placeholder='FIRMS key saved ✓'; } toast('FIRMS key saved','ok');
      const lf=$('#lyFire'); if(lf&&!lf.checked)lf.checked=true; setFires(true); }
    else if(!firmsSaved){ toast('Paste your free FIRMS key first','warn'); } };
  initFirms();
  initCompass();
  initPanel();
  try{ const c=localStorage.getItem('rode.atlasCine'); if(c!==null&&$('#cine'))$('#cine').checked=c==='1'; }catch(e){}
  $('#spin').onchange=e=>{ spinOn=e.target.checked; try{ localStorage.setItem('rode.atlasSpin', spinOn?'1':'0'); }catch(_){} };
  $('#spd').onchange=e=>{ spinSpeed=+e.target.value||1; };
  $('#lyInv').onchange=e=>{ layers.inv=e.target.checked; saveLayers(); loadOverlay(); };
  $('#lyTrace').onchange=e=>{ layers.trace=e.target.checked; saveLayers(); if(!layers.trace)clearTrace(); };
  const wk=$('#windyKey'); if(wk){ wk.onkeydown=e=>{ if(e.key==='Enter') $('#windyGo').click(); }; }
  initWindy();
  const wg=$('#windyGo'); if(wg) wg.onclick=async ()=>{
    const val=(wk&&wk.value.trim())||'';
    if(val){ try{ await fetch('/api/secrets/windy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:val})}); }catch(e){}
      windySaved=true; if(wk){ wk.value=''; wk.placeholder='Windy key saved ✓'; } toast('Windy key saved','ok'); }
    if(!windySaved){ toast('Paste your Windy key first','warn'); return; }
    if(!layers.cam){ layers.cam=true; const c=$('#lyCam'); if(c)c.checked=true; }
    const ok=await queryWindy(true);
    if(ok){ try{ const d=await API('/cams'); cams=d.cameras||[]; }catch(e){} addCamEntities(); } };
  $('#lyCam').onchange=e=>{ layers.cam=e.target.checked; saveLayers(); if(layers.cam)loadCams(); else { clearCamEntities(); importedSources.clear(); windyTiles.clear(); } setMeta(); renderCamLegend(); };
  $('#lySat').onchange=e=>{ layers.sat=e.target.checked; saveLayers(); if(layers.sat)loadSats(); else clearSats(); };
  $('#svExit').onclick=exitSatView; $('#svExitTop').onclick=exitSatView; $('#svZoomIn').onclick=()=>svZoom(true); $('#svZoomOut').onclick=()=>svZoom(false);
  $('#svSpeed').onchange=e=>{ satSpeed=+e.target.value||0.25; };
  atlasKey=e=>{ if(e.key==='Escape'&&satView){ e.preventDefault(); exitSatView(); } };
  document.addEventListener('keydown', atlasKey);
  $('#homeBtn').onclick=()=>{ if(viewer){ try{ viewer.camera.flyHome(1.5); }catch(e){} } };
  $('#clearBtn').onclick=()=>{ clearTrace(); clearLocate(); setInfo('Click a pin, or locate / trace a target.'); };
  try{ const sv=JSON.parse(localStorage.getItem('rode.atlasLayers')||'null'); if(sv) Object.assign(layers,sv); }catch(e){}
  try{ const sp=localStorage.getItem('rode.atlasSpin'); if(sp!==null){ spinOn=sp==='1'; const sc=$('#spin'); if(sc)sc.checked=spinOn; } }catch(e){}
  $('#lyInv').checked=layers.inv; $('#lyTrace').checked=layers.trace; $('#lyCam').checked=layers.cam; $('#lySat').checked=layers.sat;
  if(layers.cam) loadCams();
  if(layers.sat) loadSats();
  renderCamLegend();
  loadOverlay();
}
function unmount(){
  if(atlasKey){ document.removeEventListener('keydown', atlasKey); atlasKey=null; }
  clearTimeout(viewChangeTimer);
  if(timer){clearInterval(timer);timer=null;} if(satTimer){clearInterval(satTimer);satTimer=null;}
  if(camHandler){ try{camHandler.destroy();}catch(e){} camHandler=null; }
  if(viewer){ try{viewer.destroy();}catch(e){} viewer=null; }
  cams=[]; camEntities=[]; satEntities=[]; overlayEntities=[]; traceEntities=[]; locateEntities=[];
  importedSources=new Set(); baseLayer=labelLayer=hillLayer=rainLayer=null;
  clearTimeout(fireTimer); fireDS=null; _compassRose=null; _occluder=null;
  closeAllCamWindows();
}
function refresh(){ if(viewer) try{ loadOverlay(); }catch(e){} }
export default { id:'atlas', label:'Atlas', short:'Atlas', mount, unmount, refresh };
