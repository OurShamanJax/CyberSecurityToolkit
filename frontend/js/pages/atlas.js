// pages/atlas.js — Google-Earth-style globe (CesiumJS): satellite imagery with
// zoom LOD, sunlight/day-night, country+state labels, orbiting satellites, and
// published public camera feeds. Free/no-account sources (ESRI imagery, Celestrak).
import { $, API, escapeHtml, toast } from '../core.js';
let viewer=null, baseLayer=null, labelLayer=null, camHandler=null, timer=null, satTimer=null, mediaHls=null, atlasKey=null;
let cams=[], satEntities=[], triedImport=false, spinOn=true, satView=false, spinSpeed=1, lastInteract=0, satViewSat=null, satViewAlt=700000, satSpeed=0.25, satViewTime=null, satLastFrame=0, modalOpen=false;
const ESRI='https://services.arcgisonline.com/ArcGIS/rest/services/';
function esri(path){ return new Cesium.ArcGisMapServerImageryProvider({url:ESRI+path+'/MapServer'}); }

function shell(){ return `
<div class="page"><div class="page-h"><h2>Atlas <span class="tag">public cameras</span></h2>
  <p>A Google-Earth-style globe (CesiumJS) with real satellite imagery that sharpens as you zoom, sunlight day/night, borders & labels, and real satellites tracked live from Celestrak orbital data. The Earth rotates on its axis (inertial frame, real orientation data) with a fixed sun — speed up the spin to see it move. Plotted with <b>published public camera feeds</b> — click a point to view. Add your region's public feeds. Free/no-account sources; needs internet for the map tiles.</p></div>
<div class="page-body" style="padding:0;position:relative">
  <div id="cesiumViz" style="width:100%;height:calc(100vh - 200px);min-height:440px;background:#05070b"></div>
  <div id="glbFallback"></div>
  <div id="globeCtrl" style="position:absolute;top:12px;left:12px;display:flex;gap:8px;z-index:5;align-items:center;flex-wrap:wrap;background:rgba(13,17,23,.6);padding:6px 8px;border-radius:9px">
    <button class="sm primary" id="addCam">＋ Add feed</button>
    <button class="sm ghost" id="reload">Reload</button>
    <select id="camSrc" class="sm" title="Camera source"><option value="tfl">London (TfL)</option><option value="nyc">New York (DOT)</option></select>
    <button class="sm ghost" id="importCams">＋ Load live cams</button>
    <select id="base" class="sm"><option value="satellite">Satellite</option><option value="streets">Streets</option></select>
    <label class="muted" style="display:flex;gap:5px;align-items:center"><input type="checkbox" id="labels" checked style="width:auto"/>labels</label>
    <label class="muted" style="display:flex;gap:5px;align-items:center"><input type="checkbox" id="sun" checked style="width:auto"/>sunlight</label>
    <label class="muted" style="display:flex;gap:5px;align-items:center"><input type="checkbox" id="spin" checked style="width:auto"/>spin</label>
    <select id="spd" class="sm" title="Rotation speed"><option value="1">real-time</option><option value="600">10 min/s</option><option value="3600">1 hr/s</option><option value="21600">6 hr/s</option></select>
    <label class="muted" style="display:flex;gap:5px;align-items:center"><input type="checkbox" id="sats" checked style="width:auto"/>satellites</label>
    <span class="muted" id="cmeta"></span>
  </div>
  <div id="satView" style="position:absolute;inset:0;display:none;pointer-events:none;z-index:6">
    <div style="position:absolute;top:14px;left:50%;transform:translateX(-50%);pointer-events:auto;background:rgba(224,164,65,.12);border:1px solid rgba(224,164,65,.42);color:#e3c078;padding:7px 13px;border-radius:9px;font-size:12px;max-width:80%;text-align:center">
      <b id="satViewName"></b> — <b>SIMULATED viewpoint</b> · a representation of what this satellite would see, rendered from map imagery. <b>Not a live camera feed.</b> <button class="sm ghost" id="svExitTop" style="margin-left:8px">Exit ⎋</button></div>
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
        viewer.scene.globe.dynamicAtmosphereLighting=true; viewer.scene.globe.atmosphereLightIntensity=8.0; }catch(e){}
  // Gentle rotation by orbiting the CAMERA around Earth's polar axis (does NOT lock
  // the camera transform, so zoom/pan stay normal). Pauses while you interact.
  viewer.scene.preRender.addEventListener(()=>{
    if(satView){ followSat(); return; }
    if(!spinOn || modalOpen) return;
    if(Date.now()-lastInteract < 1500) return;
    const ang=(2*Math.PI/86400)*spinSpeed/60;   // Earth-rotation rate × speed, per frame
    try{ viewer.camera.rotate(Cesium.Cartesian3.UNIT_Z, ang); }catch(e){}
  });
  ['mousedown','wheel','touchstart','pointerdown'].forEach(ev=>
    viewer.scene.canvas.addEventListener(ev, ()=>{ lastInteract=Date.now(); }, {passive:true}));
  viewer.scene.canvas.addEventListener('wheel', (e)=>{
    if(!satView) return;
    e.preventDefault();
    satViewAlt = Math.max(150, Math.min(satViewAlt * (e.deltaY>0 ? 1.15 : 0.86), 9000000));
  }, {passive:false});
  camHandler=new Cesium.ScreenSpaceEventHandler(viewer.scene.canvas);
  camHandler.setInputAction(m=>{ const p=viewer.scene.pick(m.position); if(!p||!p.id)return; if(p.id._cam)openCam(p.id._cam); else if(p.id._sat)openSat(p.id._sat); }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
}
function setBase(kind){
  if(!viewer)return;
  if(baseLayer){ viewer.imageryLayers.remove(baseLayer,true); baseLayer=null; }
  const prov = kind==='streets' ? esri('World_Street_Map') : esri('World_Imagery');
  baseLayer=viewer.imageryLayers.addImageryProvider(prov);
  viewer.imageryLayers.lowerToBottom(baseLayer);
}
function setLabels(on){
  if(!viewer)return;
  if(labelLayer){ viewer.imageryLayers.remove(labelLayer,true); labelLayer=null; }
  if(on){ labelLayer=viewer.imageryLayers.addImageryProvider(esri('Reference/World_Boundaries_and_Places')); }
}
function addCamEntities(){
  if(!viewer)return;
  cams.forEach(c=>{ const e=viewer.entities.add({ position:Cesium.Cartesian3.fromDegrees(+c.lng,+c.lat),
    point:{pixelSize:9, color:Cesium.Color.fromCssColorString(c.url?'#5fbf8a':'#e0a24b'), outlineColor:Cesium.Color.BLACK, outlineWidth:1, disableDepthTestDistance:Number.POSITIVE_INFINITY} });
    e._cam=c; });
}
async function load(){
  let d=await API('/cams'); cams=d.cameras||[];
  const needsVideo=cams.some(c=>/jamcams\.tfl\.gov\.uk/.test(c.url||'') && !c.video);
  if((!cams.some(c=>c.url) || needsVideo) && !triedImport){ triedImport=true; $('#cmeta').textContent='loading live video cameras…';
    try{ await fetch('/api/cams/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:'tfl'})}); d=await API('/cams'); cams=d.cameras||[]; }catch(e){} }
  $('#cmeta').textContent=cams.length+' feed(s)';
  if(viewer){ viewer.entities.removeAll(); satEntities=[]; addCamEntities(); if($('#sats')&&$('#sats').checked) loadSats(); }
}
async function loadSats(){
  if(!viewer || typeof satellite==='undefined') return;
  try{
    const d=await API('/satellites'); const sats=d.sats||[];
    sats.forEach(s=>{ let rec; try{ rec=satellite.twoline2satrec(s.l1,s.l2); }catch(e){ return; }
      const e=viewer.entities.add({ point:{pixelSize:3,color:Cesium.Color.CYAN.withAlpha(0.9),disableDepthTestDistance:Number.POSITIVE_INFINITY},
        label:{text:s.name,font:'9px monospace',fillColor:Cesium.Color.CYAN.withAlpha(0.65),pixelOffset:new Cesium.Cartesian2(6,0),
          translucencyByDistance:new Cesium.NearFarScalar(3.0e6,1.0,1.2e7,0.0)} });
      e._sat={name:s.name,rec}; satEntities.push({rec,e}); });
    updateSats(); if(satTimer)clearInterval(satTimer); satTimer=setInterval(updateSats,2000);
    $('#cmeta').textContent=cams.length+' feed(s) · '+satEntities.length+' sats';
  }catch(e){}
}
function updateSats(){
  if(!satEntities.length) return;
  const now=new Date(); const gmst=satellite.gstime(now);
  satEntities.forEach(s=>{ try{ const pv=satellite.propagate(s.rec,now); if(!pv||!pv.position)return;
    const geo=satellite.eciToGeodetic(pv.position,gmst);
    s.e.position=Cesium.Cartesian3.fromDegrees(satellite.degreesLong(geo.longitude), satellite.degreesLat(geo.latitude), geo.height*1000);
  }catch(e){} });
}
function clearSats(){ if(satTimer){clearInterval(satTimer);satTimer=null;} satEntities.forEach(s=>{try{viewer.entities.remove(s.e);}catch(e){}}); satEntities=[]; }

// ── simulated satellite viewpoint ──
function enterSatView(sat){
  if(!viewer)return;
  closeModal(); satView=true; satViewSat=sat; satViewTime=new Date(); satLastFrame=0;
  const gc=$('#globeCtrl'); if(gc)gc.style.display='none';
  try{ viewer.camera.lookAtTransform(Cesium.Matrix4.IDENTITY);
    const c=viewer.scene.screenSpaceCameraController; c.enableInputs=false; }catch(e){}
  try{ const now=new Date(), pv=satellite.propagate(sat.rec,now), gmst=satellite.gstime(now), geo=satellite.eciToGeodetic(pv.position,gmst);
    satViewAlt=Math.max(180000, Math.min(geo.height*1000, 1600000)); }catch(e){ satViewAlt=700000; }
  $('#satViewName').textContent=sat.name||'satellite';
  $('#satView').style.display='block';
  followSat();
}
function followSat(){
  if(!viewer||!satViewSat)return;
  const t=performance.now(); if(!satLastFrame)satLastFrame=t;
  satViewTime=new Date(satViewTime.getTime()+(t-satLastFrame)*satSpeed); satLastFrame=t;
  try{ const pv=satellite.propagate(satViewSat.rec,satViewTime), gmst=satellite.gstime(satViewTime), geo=satellite.eciToGeodetic(pv.position,gmst);
    viewer.camera.setView({ destination:Cesium.Cartesian3.fromDegrees(satellite.degreesLong(geo.longitude), satellite.degreesLat(geo.latitude), satViewAlt),
      orientation:{ heading:0, pitch:-Cesium.Math.PI_OVER_TWO, roll:0 } }); }catch(e){}
}
function exitSatView(){
  satView=false; satViewSat=null; $('#satView').style.display='none';
  const gc=$('#globeCtrl'); if(gc)gc.style.display='';
  try{ const c=viewer.scene.screenSpaceCameraController; c.enableInputs=true; }catch(e){}
  if($('#spin')) spinOn=$('#spin').checked;
  if(viewer){ try{ viewer.camera.flyHome(1.4); }catch(e){} }
}
function svZoom(inward){
  satViewAlt=Math.max(150, Math.min(satViewAlt*(inward?0.6:1.55), 9000000));
}
// ── cam modal ──
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
  $('#cmBody').innerHTML=`<div class="muted" style="line-height:1.7">
    These are <b>real satellites</b>, not decorations — positions are computed live from <b>Celestrak</b> two-line orbital elements with real orbital physics.
    <div style="margin-top:10px;display:flex;gap:24px"><div><div class="ins-run-t">Altitude</div><b style="font-size:17px;color:var(--text)">${alt} km</b></div>
      <div><div class="ins-run-t">Speed</div><b style="font-size:17px;color:var(--text)">${spd} km/s</b></div></div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="primary" id="satViewBtn" style="padding:7px 12px">▣ View from this satellite (simulated)</button>
      ${iss?'<a href="https://www.nasa.gov/live/" target="_blank" rel="noopener" style="background:var(--surface2);color:var(--text);text-decoration:none;padding:7px 12px;border-radius:7px;border:1px solid var(--line)">▶ Watch the ISS live (NASA)</a>':''}</div>
    <div style="margin-top:12px;font-size:12px">There's no free "live video from a satellite looking down" — orbital imagery is periodically-updated tiles. The only genuine live orbital video is the ISS stream${iss?' (above)':''}.</div>
  </div>`;
  openModal();
  const b=$('#satViewBtn'); if(b)b.onclick=()=>enterSatView(sat);
}
function mediaOf(cam){
  const v=cam.video || (cam.url && /\.mp4(\?|$)/i.test(cam.url) ? cam.url : '');
  const hls=(cam.url && /\.m3u8(\?|$)/i.test(cam.url)) ? cam.url : '';
  return {v, hls, img:(!v&&!hls&&cam.url)?cam.url:''};
}
function openCam(cam){
  $('#cmTitle').textContent=cam.name;
  $('#cmSub').textContent=`${cam.type} · ${(+cam.lat).toFixed(3)}, ${(+cam.lng).toFixed(3)} ${cam.country||''}`;
  const body=$('#cmBody'), m=mediaOf(cam);
  const foot=`<div style="margin-top:8px;display:flex;gap:8px;align-items:center"><span class="muted" id="cmStat"></span><div class="spacer"></div><button class="sm danger" id="cmDel">Delete feed</button></div>`;
  if(m.v){
    body.innerHTML=`<video id="cmVid" autoplay loop muted playsinline controls style="width:100%;border-radius:8px;background:#000;min-height:220px"></video>`+foot;
    const v=$('#cmVid'); const bust=()=> m.v+(m.v.includes('?')?'&':'?')+'_='+Date.now();
    v.src=bust(); $('#cmStat').textContent='clip refreshes every ~90s (TfL updates it periodically)';
    // TfL publishes a short clip it overwrites every few minutes — re-pull it so the feed stays current
    timer=setInterval(()=>{ try{ const at=v.currentTime; v.src=bust(); v.load(); v.play().catch(()=>{}); }catch(e){} }, 90000);
  } else if(m.hls){
    body.innerHTML=`<video id="cmVid" autoplay muted playsinline controls style="width:100%;border-radius:8px;background:#000;min-height:220px"></video>`+foot;
    const v=$('#cmVid'); $('#cmStat').textContent='live stream (HLS)';
    if(window.Hls && window.Hls.isSupported()){ mediaHls=new Hls(); mediaHls.loadSource(m.hls); mediaHls.attachMedia(v); }
    else { v.src=m.hls; }
  } else if(m.img){
    body.innerHTML=`<img id="cmImg" alt="feed" style="width:100%;border-radius:8px;background:#000;min-height:220px;object-fit:contain"/>`+foot;
    const img=$('#cmImg'); img.onerror=()=>{ $('#cmStat').textContent='feed offline or blocks embedding'; };
    img.onload=()=>{ $('#cmStat').textContent='snapshot · refreshing every 1.5s'; };
    const tick=()=>{ img.src='/api/cams/'+cam.id+'/snapshot?t='+Date.now(); }; tick(); timer=setInterval(tick,1500);
  } else {
    body.innerHTML=`<div class="muted">No feed set. Paste a <b>published public feed</b> URL — snapshot <code>.jpg</code>, video <code>.mp4</code>, or live stream <code>.m3u8</code>.</div>
      <div style="margin-top:10px;display:flex;gap:8px"><input id="cmUrl" placeholder="https://…/stream.m3u8 or camera.jpg" style="flex:1"/><button class="primary" id="cmSetUrl">Set URL</button><button class="danger" id="cmDel">Delete</button></div>`;
    $('#cmSetUrl').onclick=()=>setUrl(cam);
  }
  $('#cmDel').onclick=()=>delCam(cam); openModal();
}
async function setUrl(cam){ const u=$('#cmUrl').value.trim(); if(!u)return;
  await fetch('/api/cams/'+cam.id,{method:'DELETE'});
  await fetch('/api/cams',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:cam.name,lat:cam.lat,lng:cam.lng,country:cam.country,type:cam.type,url:u})});
  closeModal(); toast('Feed set','ok'); load(); }
function addForm(){
  $('#cmTitle').textContent='Add a public feed'; $('#cmSub').textContent='published public cameras only';
  $('#cmBody').innerHTML=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
    <input id="fName" placeholder="Name (e.g. I-95 MP 12)"/><input id="fUrl" placeholder="Feed URL — https://…/camera.jpg"/>
    <input id="fLat" type="number" step="any" placeholder="Latitude"/><input id="fLng" type="number" step="any" placeholder="Longitude"/></div>
    <div style="margin-top:10px;display:flex;justify-content:flex-end;gap:8px"><button class="ghost" id="fCancel">Cancel</button><button class="primary" id="fAdd">Add feed</button></div>
    <div class="muted" style="margin-top:8px">Public feeds come from your state/city DOT open-data (511) or published webcams — paste its snapshot URL and coordinates.</div>`;
  $('#fCancel').onclick=closeModal;
  $('#fAdd').onclick=async()=>{ const b={name:$('#fName').value||'camera',url:$('#fUrl').value.trim(),lat:+$('#fLat').value||0,lng:+$('#fLng').value||0,type:'webcam'};
    if(!b.url){ toast('A feed URL is required','warn'); return; }
    await fetch('/api/cams',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); closeModal(); toast('Feed added','ok'); load(); };
  openModal();
}
function delCam(cam){ fetch('/api/cams/'+cam.id,{method:'DELETE'}).then(()=>{ closeModal(); toast('Removed','warn'); load(); }); }

function mount(root){
  root.innerHTML=shell();
  $('#addCam').onclick=addForm; $('#reload').onclick=load; $('#cmClose').onclick=closeModal; $('#cmBg').onclick=closeModal;
  $('#importCams').onclick=async()=>{ $('#importCams').disabled=true; $('#cmeta').textContent='importing live cams…';
    try{ const r=await fetch('/api/cams/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:($('#camSrc')&&$('#camSrc').value)||'tfl'})}).then(x=>x.json());
      if(r&&r.ok)toast('Loaded '+r.added+' live cameras','ok'); else toast('Import failed'+((r&&r.error)?': '+r.error:''),'warn'); }catch(e){}
    triedImport=true; $('#importCams').disabled=false; load(); };
  if(typeof Cesium==='undefined'){
    $('#cesiumViz').style.display='none';
    $('#glbFallback').innerHTML='<div class="muted" style="padding:40px 24px">The 3D globe engine (CesiumJS) didn\'t load — it needs internet access to its CDN. The rest of R.O.D.E works offline; reconnect and reload this tab.</div>';
    load(); return;
  }
  try{ initCesium(); }catch(e){ $('#glbFallback').innerHTML='<div class="muted" style="padding:24px">Globe failed to initialise: '+escapeHtml(String(e).slice(0,140))+'</div>'; }
  $('#base').onchange=e=>setBase(e.target.value);
  $('#labels').onchange=e=>setLabels(e.target.checked);
  $('#sun').onchange=e=>{ if(viewer)viewer.scene.globe.enableLighting=e.target.checked; };
  $('#spin').onchange=e=>{ spinOn=e.target.checked; if(!spinOn && viewer){ try{ viewer.camera.lookAtTransform(Cesium.Matrix4.IDENTITY); }catch(_){} } };
  $('#spd').onchange=e=>{ spinSpeed=+e.target.value||1; };
  $('#sats').onchange=e=>{ if(e.target.checked)loadSats(); else clearSats(); };
  $('#svExit').onclick=exitSatView; $('#svExitTop').onclick=exitSatView; $('#svZoomIn').onclick=()=>svZoom(true); $('#svZoomOut').onclick=()=>svZoom(false);
  $('#svSpeed').onchange=e=>{ satSpeed=+e.target.value||0.25; };
  atlasKey=e=>{ if(e.key==='Escape' && satView){ e.preventDefault(); exitSatView(); } };
  document.addEventListener('keydown', atlasKey);
  load();
}
function unmount(){
  if(atlasKey){ document.removeEventListener('keydown', atlasKey); atlasKey=null; }
  if(timer){clearInterval(timer);timer=null;} if(satTimer){clearInterval(satTimer);satTimer=null;}
  if(camHandler){ try{camHandler.destroy();}catch(e){} camHandler=null; }
  if(viewer){ try{viewer.destroy();}catch(e){} viewer=null; }
  cams=[]; satEntities=[]; baseLayer=labelLayer=null;
}
export default { id:'atlas', label:'Atlas', short:'Atlas', mount, unmount };
