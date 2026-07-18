// pages/atlas.js — Atlas v2: a geospatial lens on your investigation.
// The globe is aimed at YOUR data: locate an IP/domain, traceroute a target
// across the world, and plot the investigation's geolocated entities with
// relationship arcs. Cameras + satellites remain as optional layers (off by
// default). Free/no-account sources (ESRI imagery, ip-api.com, Celestrak).
import { $, API, S, COLOR, escapeHtml, toast } from '../core.js';

let viewer=null, baseLayer=null, labelLayer=null, hillLayer=null, camHandler=null, camDS=null, atlasKey=null;
let timer=null, satTimer=null, mediaHls=null, viewChangeTimer=null;
let cams=[], camEntities=[], satEntities=[], overlayEntities=[], traceEntities=[], locateEntities=[];
let importedSources=new Set();
let spinOn=true, spinSpeed=1, lastInteract=0, modalOpen=false;
let satView=false, satViewSat=null, satViewAlt=700000, satSpeed=0.25, satViewTime=null, satLastFrame=0;
const layers={ inv:true, trace:true, cam:false, sat:false };
function saveLayers(){ try{ localStorage.setItem('rode.atlasLayers', JSON.stringify(layers)); }catch(e){} }
const ESRI='https://services.arcgisonline.com/ArcGIS/rest/services/';
function esri(path){ return new Cesium.ArcGisMapServerImageryProvider({url:ESRI+path+'/MapServer'}); }
function typeColor(t){ return COLOR[t] || '#5aa9e6'; }

function shell(){ return `
<div class="page" style="height:100%">
<div class="page-body" style="padding:0;position:relative;height:100%">
  <div id="cesiumViz" style="width:100%;height:100%;min-height:420px;background:#05070b"></div>
  <div id="glbFallback"></div>

  <div id="atlasPanel">
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
      </div>
    </div>

    <div class="ap-sec" id="atlasInfoSec"><div class="ap-lbl">Selection</div>
      <div id="atlasInfo" class="ap-info muted">Click a pin, or locate / trace a target.</div>
    </div>
    <div class="ap-meta" id="cmeta"></div>
  </div>

  <div id="satView" style="position:absolute;inset:0;display:none;pointer-events:none;z-index:6">
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
  viewer.scene.preRender.addEventListener(()=>{
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
  const cl=camDS.clustering; cl.enabled=true; cl.pixelRange=42; cl.minimumClusterSize=4;
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
    if(id._cam)openCam(id._cam); else if(id._sat)openSat(id._sat);
    else if(id._hop)showHop(id._hop); else if(id._node)showNode(id._node); else if(id._loc)showLoc(id._loc);
  }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
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
  if(on){ labelLayer=viewer.imageryLayers.addImageryProvider(esri('Reference/World_Boundaries_and_Places')); }
}
function setHill(on){
  if(!viewer)return;
  if(hillLayer){ viewer.imageryLayers.remove(hillLayer,true); hillLayer=null; }
  if(on){ hillLayer=viewer.imageryLayers.addImageryProvider(esri('Elevation/World_Hillshade')); hillLayer.alpha=0.45;
    if(baseLayer) viewer.imageryLayers.raise(hillLayer); }
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
const CAM_SOURCES=[
  {id:'tfl', name:'London (TfL)',   bounds:[-0.62, 51.20, 0.36, 51.76]},
  {id:'nyc', name:'New York (DOT)', bounds:[-74.30, 40.48, -73.68, 40.93]},
  {id:'caltrans', name:'California (Caltrans)', bounds:[-124.6, 32.4, -114.0, 42.1]},
];
function viewRectDeg(){ if(!viewer)return null;
  try{ const r=viewer.camera.computeViewRectangle(); if(!r)return null;
    const D=Cesium.Math.toDegrees; return [D(r.west),D(r.south),D(r.east),D(r.north)]; }catch(e){ return null; } }
function camH(){ try{ return viewer.camera.positionCartographic.height; }catch(e){ return 1e12; } }
function bInt(a,b){ return a[0]<=b[2]&&a[2]>=b[0]&&a[1]<=b[3]&&a[3]>=b[1]; }
function inV(c,v){ if(!v)return true; const x=+c.lng,y=+c.lat; return x>=v[0]&&x<=v[2]&&y>=v[1]&&y<=v[3]; }
let windySaved=false;
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
  const lat=(v[1]+v[3])/2, lng=(v[0]+v[2])/2;
  const radius=Math.min(250, Math.max(20, Math.round((v[3]-v[1])*111/1.5)));
  if(explicit){ setInfo('<span class="muted">querying Windy near '+lat.toFixed(2)+', '+lng.toFixed(2)+' ('+radius+'km)…</span>'); }
  let res;
  try{ res=await fetch('/api/cams/windy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({lat,lng,radius})}); }
  catch(e){ if(explicit)toast('Could not reach the R.O.D.E server','warn'); return false; }
  if(res.status===404){ toast('Windy endpoint missing — restart the R.O.D.E server (start.bat)','warn'); return false; }
  if(!res.ok){ toast('Windy request failed ('+res.status+')','warn'); return false; }
  let r; try{ r=await res.json(); }catch(e){ return false; }
  if(r&&r.ok){ if(r.added){ toast('Loaded '+r.added+' Windy webcams','ok'); if(explicit)setInfo('<span class="muted">'+r.added+' Windy webcams loaded near this view.</span>'); return true; }
    if(explicit){ toast('No Windy webcams within '+radius+'km of this view','warn'); setInfo('<span class="muted">Windy returned 0 cams here — try zooming to a bigger city.</span>'); } return false; }
  if(r&&r.error){ toast('Windy: '+r.error,'warn'); if(explicit)setInfo('<span class="muted">Windy error: '+escapeHtml(r.error)+'</span>'); }
  return false;
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
function addCamEntities(){
  if(!viewer)return; clearCamEntities();
  if(!layers.cam){ setMeta(); return; }
  const v=viewRectDeg();
  cams.filter(c=>c.lat&&c.lng&&inV(c,v)).forEach(c=>{
    const e=camDS.entities.add({ position:Cesium.Cartesian3.fromDegrees(+c.lng,+c.lat),
      point:{pixelSize:8,color:Cesium.Color.fromCssColorString(c.url?'#5fbf8a':'#e0a24b'),outlineColor:Cesium.Color.BLACK,outlineWidth:1,disableDepthTestDistance:Number.POSITIVE_INFINITY} });
    e._cam=c; camEntities.push(e); });
  setMeta();
}
async function loadCams(){
  let d; try{ d=await API('/cams'); }catch(e){ return; } cams=d.cameras||[];
  const imp=await autoImportForView(); if(imp){ try{ d=await API('/cams'); cams=d.cameras||[]; }catch(e){} }
  addCamEntities();
}
function onViewChanged(){
  clearTimeout(viewChangeTimer);
  viewChangeTimer=setTimeout(async ()=>{ if(!layers.cam)return;
    const imp=await autoImportForView(); if(imp){ try{ const d=await API('/cams'); cams=d.cameras||[]; }catch(e){} }
    addCamEntities(); }, 450);
}

// ── satellites (optional layer, off by default) ──
async function loadSats(){
  if(!viewer || typeof satellite==='undefined') return;
  try{ const d=await API('/satellites'); const sats=d.sats||[];
    sats.forEach(s=>{ let rec; try{ rec=satellite.twoline2satrec(s.l1,s.l2); }catch(e){ return; }
      const e=viewer.entities.add({ point:{pixelSize:3,color:Cesium.Color.CYAN.withAlpha(0.9),disableDepthTestDistance:Number.POSITIVE_INFINITY},
        label:{text:s.name,font:'9px monospace',fillColor:Cesium.Color.CYAN.withAlpha(0.6),pixelOffset:new Cesium.Cartesian2(6,0),
          translucencyByDistance:new Cesium.NearFarScalar(3.0e6,1.0,1.2e7,0.0)} });
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
    viewer.camera.setView({ destination:Cesium.Cartesian3.fromDegrees(satellite.degreesLong(geo.longitude),satellite.degreesLat(geo.latitude),satViewAlt),
      orientation:{heading:0,pitch:-Cesium.Math.PI_OVER_TWO,roll:0} }); }catch(e){} }
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
  $('#lyCam').onchange=e=>{ layers.cam=e.target.checked; saveLayers(); if(layers.cam)loadCams(); else { clearCamEntities(); importedSources.clear(); } setMeta(); };
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
  loadOverlay();
}
function unmount(){
  if(atlasKey){ document.removeEventListener('keydown', atlasKey); atlasKey=null; }
  clearTimeout(viewChangeTimer);
  if(timer){clearInterval(timer);timer=null;} if(satTimer){clearInterval(satTimer);satTimer=null;}
  if(camHandler){ try{camHandler.destroy();}catch(e){} camHandler=null; }
  if(viewer){ try{viewer.destroy();}catch(e){} viewer=null; }
  cams=[]; camEntities=[]; satEntities=[]; overlayEntities=[]; traceEntities=[]; locateEntities=[];
  importedSources=new Set(); baseLayer=labelLayer=hillLayer=null;
}
function refresh(){ if(viewer) try{ loadOverlay(); }catch(e){} }
export default { id:'atlas', label:'Atlas', short:'Atlas', mount, unmount, refresh };
