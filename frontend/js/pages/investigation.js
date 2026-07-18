// pages/investigation.js — entity graph + console + findings + inspector
import { $, API, S, NM, NOISE, PH, COLOR, escapeHtml, makeTyper, toast,
         runTool, cancelRun, resendConfirmed } from '../core.js';
import { updateFootprint, ask, show, hide, sendTo } from '../app.js';

let cy=null, sel=null, hidden=new Set(), term=null, layout='', zs=false, pickHandler=null, winCleanup=[], mapViewer=null, mapHandler=null, lens='graph';

const HTML=`
<div class="invwrap" id="invwrap">
  <section class="canvas">
    <div id="graph"></div>
    <div class="gfilter" id="gfilter"></div>
    <div class="gtools">
      <button class="sm" id="lensGraph">Graph</button>
      <button class="sm ghost" id="lensMap">Map</button>
      <span id="graphtools" style="display:inline-flex;gap:7px;margin-left:4px">
        <button class="sm ghost" id="fitBtn" title="Fit to view"><svg class="ic" viewBox="0 0 24 24"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></svg>Fit</button>
        <button class="icon ghost sm" id="maxGraph" title="Focus graph" aria-label="Focus graph"><svg class="ic" viewBox="0 0 24 24"><path d="M8 3H3v5M21 8V3h-5M3 16v5h5M16 21h5v-5"/></svg></button>
        <button class="sm danger" id="resetBtn" title="Clear this investigation's graph"><svg class="ic" viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg>Reset</button>
      </span>
    </div>
    <div id="invmap" style="position:absolute;inset:0;display:none;z-index:1;background:#05070b"></div>
    <div class="gempty" id="gempty">
      <svg class="ge-ic" viewBox="0 0 24 24"><circle cx="6" cy="6" r="2.4"/><circle cx="18" cy="7" r="2.4"/><circle cx="12" cy="17" r="2.4"/><path d="M7.7 7.4 10.4 15M16.6 8.6 13.3 15.4"/></svg>
      <div class="h">No entities yet</div>
      <div class="sub">Pick a tool below and run it. Click any node for actions · select one and press <b>Delete</b> to remove it.</div>
      <button class="primary" id="lanBtn" style="margin-top:14px;pointer-events:auto"><svg class="ic" viewBox="0 0 24 24" style="width:15px;height:15px"><path d="M5 12a10 10 0 0 1 14 0M8 15a6 6 0 0 1 8 0"/><circle cx="12" cy="18.5" r="1.2"/></svg> Discover my LAN</button>
      <div class="sub" style="margin-top:6px;opacity:.7">maps every device on your local network into the graph</div>
    </div>
    <div class="runbar">
      <select id="toolSel" style="min-width:190px" aria-label="Tool"></select>
      <span class="noiseTag" id="noiseTag"></span>
      <input id="targetInput" placeholder="target" aria-label="Target"/>
      <button class="primary" id="runBtn"><svg class="ic fill" viewBox="0 0 24 24"><path d="M7 5l12 7-12 7z"/></svg>Run</button>
      <button class="ghost" id="cancelBtn" style="display:none"><svg class="ic" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>Stop</button>
    </div>
  </section>
  <div class="splitter" id="splitter"></div>
  <aside id="aside">
    <div class="teach" id="teach"><button class="x" id="teachClose">&times;</button>
      <h4 id="teachTool"></h4><div class="what" id="teachWhat"></div><div class="flags" id="teachFlags"></div><div class="cmdline" id="teachCmd"></div></div>
    <div class="console-h"><span>Console</span><div class="spacer"></div>
      <button class="sm ghost" id="clearConsole" title="Clear console">Clear</button>
      <button class="icon ghost sm" id="maxSide" title="Maximize panel" aria-label="Maximize"><svg class="ic" viewBox="0 0 24 24"><path d="M8 3H3v5M21 8V3h-5M3 16v5h5M16 21h5v-5"/></svg></button></div>
    <div class="term" id="term" role="log" aria-live="polite"></div>
    <div class="vsplitter" id="vsplitter"></div>
    <div class="findings" id="findings"></div>
    <div class="spinner" id="spinner"></div>
  </aside>
</div>`;

function mount(root){
  root.innerHTML=HTML;
  term=makeTyper($('#term'));
  fillTools(); updateNoiseTag();
  $('#runBtn').onclick=()=>{ const t=$('#toolSel').value, tg=$('#targetInput').value.trim(); if(tg)doRun(t,tg); };
  $('#lanBtn').onclick=()=>{ if(!S.inv){ toast('Create an investigation first','warn'); show('#invOverlay'); return; } doRun('lan_discover','auto'); };
  $('#targetInput').addEventListener('keydown',e=>{ if(e.key==='Enter'){const t=$('#toolSel').value,tg=$('#targetInput').value.trim(); if(tg)doRun(t,tg);} });
  $('#toolSel').onchange=updateNoiseTag;
  $('#cancelBtn').onclick=()=>cancelRun();
  $('#fitBtn').onclick=()=>cy&&cy.fit(null,40);
  $('#resetBtn').onclick=resetGraph;
  $('#lensGraph').onclick=()=>switchLens('graph');
  $('#lensMap').onclick=()=>switchLens('map');
  $('#maxGraph').onclick=toggleGraphMax;
  $('#maxSide').onclick=toggleConsoleMax;
  $('#clearConsole').onclick=()=>term.clear();
  $('#teachClose').onclick=()=>$('#teach').style.display='none';
  initSplitter(); initVSplitter();
  document.addEventListener('keydown', keyHandler);
  pickHandler=e=>pick(e.detail); document.addEventListener('rode:pick', pickHandler);
  if(!S.inv){ term('Create or select an investigation to begin.','sys'); $('#gempty').style.display='flex'; return; }
  term('R.O.D.E v4 ready · '+S.tools.length+' tools · '+S.mode+' mode.','sys');
  refresh();
}
function unmount(){
  document.removeEventListener('keydown', keyHandler);
  if(pickHandler) document.removeEventListener('rode:pick', pickHandler);
  winCleanup.forEach(fn=>{try{fn();}catch(e){}}); winCleanup=[];
  if(mapHandler){try{mapHandler.destroy();}catch(e){} mapHandler=null;}
  if(mapViewer){try{mapViewer.destroy();}catch(e){} mapViewer=null;} lens='graph';
  if(cy){ try{cy.destroy();}catch(e){} cy=null; }
}
function keyHandler(e){
  if((e.key==='Delete'||e.key==='Backspace')&&sel&&document.activeElement.tagName!=='INPUT'){ e.preventDefault(); deleteNode(sel); }
}
function pick(d){ if(!$('#toolSel'))return; if(typeof d==='string'){ $('#toolSel').value=d; } else { if(d.tool)$('#toolSel').value=d.tool; if(d.target&&$('#targetInput'))$('#targetInput').value=d.target; } updateNoiseTag(); }

function fillTools(){
  const by={}; NOISE.forEach(n=>by[n]=[]); S.tools.forEach(t=>by[t.noise].push(t));
  $('#toolSel').innerHTML=NOISE.map(n=>by[n].length?
    `<optgroup label="${n.toUpperCase()}">`+by[n].map(t=>`<option value="${t.id}">${t.name}${t.status.runnable?'':' — needs setup'}</option>`).join('')+`</optgroup>`:'').join('');
}
function updateNoiseTag(){
  const t=S.tools.find(x=>x.id===$('#toolSel').value); if(!t)return;
  $('#noiseTag').innerHTML=`<span class="dot" style="background:${NM[t.noise].c}"></span>${t.noise}`;
  $('#targetInput').placeholder=PH[t.input_type]||('target — '+t.input_type);
}

async function refresh(){ await drawGraph(); await loadFindings(); updateFootprint(); if(lens==='map')plotMap(); }

function switchLens(mode){
  lens=mode;
  $('#lensGraph').classList.toggle('ghost', mode!=='graph');
  $('#lensMap').classList.toggle('ghost', mode!=='map');
  $('#graphtools').style.display=mode==='graph'?'inline-flex':'none';
  $('#gfilter').style.display=mode==='map'?'none':'';
  $('#invmap').style.display=mode==='map'?'block':'none';
  if(mode==='graph'){ if(cy)setTimeout(()=>cy.resize(),60); }
  else { initInvMap(); plotMap(); }
}
function initInvMap(){
  if(mapViewer || typeof Cesium==='undefined') return;
  try{ Cesium.Ion.defaultAccessToken=''; }catch(e){}
  try{
    mapViewer=new Cesium.Viewer('invmap',{ baseLayerPicker:false,geocoder:false,homeButton:false,sceneModePicker:false,
      navigationHelpButton:false,animation:false,timeline:false,fullscreenButton:false,infoBox:false,selectionIndicator:false,
      imageryProvider:new Cesium.ArcGisMapServerImageryProvider({url:'https://services.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer'}),
      terrainProvider:new Cesium.EllipsoidTerrainProvider() });
    mapViewer.imageryLayers.addImageryProvider(new Cesium.ArcGisMapServerImageryProvider({url:'https://services.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer'}));
    mapViewer.scene.globe.enableLighting=true; mapViewer.scene.backgroundColor=Cesium.Color.fromCssColorString('#05070b');
    mapHandler=new Cesium.ScreenSpaceEventHandler(mapViewer.scene.canvas);
    mapHandler.setInputAction(m=>{ const p=mapViewer.scene.pick(m.position); if(p&&p.id&&p.id._ent){ const id=p.id._ent.entity_id; switchLens('graph'); setTimeout(()=>focusEntityById(id),160); } }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
  }catch(e){ $('#invmap').innerHTML='<div class="muted" style="padding:40px">Map globe failed to init: '+escapeHtml(String(e).slice(0,120))+'</div>'; }
}
async function plotMap(){
  if(!S.inv)return;
  if(typeof Cesium==='undefined'){ $('#invmap').innerHTML='<div class="muted" style="padding:40px 24px">The Map lens needs the Cesium globe engine (internet for map tiles).</div>'; return; }
  try{ await fetch('/api/investigations/'+S.inv+'/geolocate',{method:'POST'}); }catch(e){}
  const g=await API('/graph/'+S.inv); if(!mapViewer)return;
  mapViewer.entities.removeAll();
  const pts=g.nodes.filter(n=>n.data.lat!=null && n.data.lng!=null);
  pts.forEach(n=>{ const e=mapViewer.entities.add({ position:Cesium.Cartesian3.fromDegrees(n.data.lng,n.data.lat,0),
    point:{pixelSize:11,color:Cesium.Color.fromCssColorString(COLOR[n.data.type]||'#4bb8d0'),outlineColor:Cesium.Color.BLACK,outlineWidth:1,disableDepthTestDistance:Number.POSITIVE_INFINITY},
    label:{text:_trunc(n.data.label),font:'600 11px sans-serif',fillColor:Cesium.Color.WHITE,pixelOffset:new Cesium.Cartesian2(0,-16),showBackground:true,backgroundColor:Cesium.Color.fromCssColorString('rgba(13,17,23,0.82)'),scale:0.9,disableDepthTestDistance:Number.POSITIVE_INFINITY,translucencyByDistance:new Cesium.NearFarScalar(2.0e6,1.0,2.4e7,0.15)} });
    e._ent=n.data; });
  if(pts.length){ try{ mapViewer.zoomTo(mapViewer.entities); }catch(e){} }
  else toast('No geolocated entities yet — scan a public IP/domain (needs internet)','warn');
}
function focusEntityById(id){ if(!cy)return; const n=cy.nodes().filter(x=>x.data('entity_id')===id); if(n&&n.length)focusCyNode(n[0]); }
function _trunc(l){ l=String(l||''); return l.length>24?l.slice(0,23)+'…':l; }
const _isFind=t=>t==='vulnerability'||t==='secret';

function layoutFor(mode, roots){
  if(mode==='identity'){
    return {name:'concentric', concentric:n=>(roots.includes(n.id())?3:(['username','email','domain'].includes(n.data('type'))?2:1)),
      levelWidth:()=>1, minNodeSpacing:44, animate:true, animationDuration:520, padding:55};
  }
  return {name:'cose', animate:true, animationDuration:600, padding:45, nodeRepulsion:9000,
    idealEdgeLength:82, gravity:0.3, nestingFactor:0.9, randomize:false, componentSpacing:90};
}

async function drawGraph(){
  const g=await API('/graph/'+S.inv);
  $('#gempty').style.display=g.nodes.length?'none':'flex';
  const cc={}; g.edges.forEach(e=>{cc[e.data.source]=(cc[e.data.source]||0)+1;});
  g.nodes.forEach(nd=>{ if(nd.data.type==='category'){ nd.data.label=(nd.data.label||'')+'  ·  '+(cc[nd.data.id]||0); } });
  const tgt=new Set(g.edges.map(e=>e.data.target));
  const roots=g.nodes.filter(n=>!tgt.has(n.data.id)).map(n=>n.data.id);
  if(cy){ try{cy.destroy();}catch(e){} }
  cy=cytoscape({container:$('#graph'),elements:[...g.nodes,...g.edges],
    style:[
      {selector:'node',style:{'background-color':n=>COLOR[n.data('type')]||'#6b7684','label':n=>_trunc(n.data('label')),
        'color':'#a4aebb','font-size':'10px','font-family':'monospace','text-valign':'bottom','text-margin-y':6,
        'width':n=>(_isFind(n.data('type'))?12:18)+n.data('confidence')*8,'height':n=>(_isFind(n.data('type'))?12:18)+n.data('confidence')*8,
        'underlay-color':n=>COLOR[n.data('type')]||'#6b7684','underlay-padding':4,
        'underlay-opacity':n=>n.data('confirmed')?0.34:(_isFind(n.data('type'))?0.05:0.12),
        'border-width':n=>n.data('confirmed')?2:0,'border-color':'#5fbf8a'}},
      {selector:'node[type = "category"]',style:{'shape':'round-rectangle','width':n=>Math.max(80,String(n.data('label')||'').length*6.6+22),
        'height':28,'background-opacity':0.92,'text-valign':'center','text-margin-y':0,'font-size':'11px','font-weight':'bold','color':'#0b0e12','underlay-opacity':0,'label':n=>n.data('label')}},
      {selector:'node:selected',style:{'border-width':2,'border-color':'#46b1c9','underlay-opacity':0.45,'font-size':'12px','color':'#e7ebf0','z-index':99}},
      {selector:'node.hl',style:{'font-size':'12px','color':'#eef2f6','z-index':99}},
      {selector:'node.flash',style:{'border-width':3,'border-color':'#ffd76a','underlay-color':'#ffd76a','underlay-opacity':0.55,'underlay-padding':9,'z-index':999}},
      {selector:'edge',style:{'width':1.1,'line-color':'#42505f','target-arrow-color':'#5a6b80','target-arrow-shape':'triangle','arrow-scale':0.9,'curve-style':'bezier','opacity':0.72}},
      {selector:'edge:selected',style:{'line-color':'#46b1c9','target-arrow-color':'#46b1c9','opacity':1}},
    ],
    layout: layoutFor(S.mode, roots),
  });
  cy.on('tap','node',e=>{ sel=e.target.data('entity_id'); nodeMenu(e.target); });
  cy.on('select','node',e=>sel=e.target.data('entity_id'));
  cy.on('unselect','node',()=>sel=null);
  cy.on('tap',e=>{ if(e.target===cy){ closePop(); sel=null; } });
  cy.on('mouseover','node',e=>{ e.target.addClass('hl'); showTip(e.target); });
  cy.on('mouseout','node',e=>{ e.target.removeClass('hl'); hideTip(); });
  cy.nodes().forEach(n=>{ n.data('_bw',n.width()); n.data('_bh',n.height()); n.data('_bf',n.data('type')==='category'?11:10); });
  zs=false; cy.on('zoom',applyZoomScaling); applyZoomScaling();
  // node fade-in
  if(!window.matchMedia('(prefers-reduced-motion: reduce)').matches){
    cy.nodes().forEach((n,i)=>{ n.style('opacity',0); n.delay(i*14).animate({style:{opacity:1}},{duration:220}); });
  }
  buildFilters(g.nodes); applyFilter();
}
function applyZoomScaling(){
  if(!cy)return; const z=cy.zoom(); const f=Math.min(3.8,Math.max(1,1.0/z));
  if(f<=1.02){ if(zs){ cy.batch(()=>{cy.nodes().forEach(n=>n.removeStyle('width height font-size'));cy.edges().forEach(e=>e.removeStyle('width'));}); zs=false; } return; }
  zs=true;
  cy.batch(()=>{ cy.nodes().forEach(n=>{ const bw=n.data('_bw'),bh=n.data('_bh'),bf=n.data('_bf')||10;
    if(bw)n.style('width',bw*f); if(bh)n.style('height',bh*f); n.style('font-size',(bf*f)+'px'); });
    cy.edges().forEach(e=>e.style('width',1.1*Math.min(f,2.8))); });
}
function showTip(node){
  const rect=$('#graph').getBoundingClientRect(),pos=node.renderedPosition();
  let tip=$('#gtip'); if(!tip){tip=document.createElement('div');tip.id='gtip';tip.className='gtip';document.body.appendChild(tip);}
  tip.textContent=node.data('type')+': '+node.data('value'); tip.style.display='block';
  tip.style.left=Math.min(rect.left+pos.x+14,window.innerWidth-tip.offsetWidth-8)+'px';
  tip.style.top=Math.max(8,rect.top+pos.y-8)+'px';
}
function hideTip(){ const t=$('#gtip'); if(t)t.style.display='none'; }
function buildFilters(nodes){
  const c={}; nodes.forEach(n=>c[n.data.type]=(c[n.data.type]||0)+1);
  const box=$('#gfilter');
  box.innerHTML=Object.keys(c).sort().map(t=>`<span class="fchip${hidden.has(t)?' off':''}" data-t="${t}"><span class="dot" style="background:${COLOR[t]||'#6b7684'}"></span>${t} ${c[t]}</span>`).join('');
  box.querySelectorAll('.fchip').forEach(ch=>ch.onclick=()=>{ const t=ch.dataset.t; if(hidden.has(t)){hidden.delete(t);ch.classList.remove('off');}else{hidden.add(t);ch.classList.add('off');} applyFilter(); });
}
function applyFilter(){
  if(!cy)return;
  cy.batch(()=>{ cy.nodes().forEach(n=>n.style('display',hidden.has(n.data('type'))?'none':'element'));
    cy.edges().forEach(ed=>ed.style('display',(ed.source().style('display')==='none'||ed.target().style('display')==='none')?'none':'element')); });
}
function focusCyNode(node){ if(!cy||!node)return; cy.animate({center:{eles:node},zoom:Math.max(cy.zoom(),1.15)},{duration:400}); node.addClass('flash'); setTimeout(()=>node.removeClass('flash'),1400); }
function focusFinding(title){
  if(!cy||!title)return;
  let node=cy.nodes().filter(n=>_isFind(n.data('type'))&&(n.data('label')===title||n.data('value')===title));
  if(!node.length)node=cy.nodes().filter(n=>n.data('label')===title);
  if(!node.length){ toast('That finding is not on the graph','warn'); return; }
  const n=node[0],ty=n.data('type');
  if(hidden.has(ty)){ hidden.delete(ty); const ch=$('#gfilter').querySelector(`.fchip[data-t="${ty}"]`); if(ch)ch.classList.remove('off'); applyFilter(); }
  $('#aside').classList.remove('console-full'); focusCyNode(n);
}
async function nodeMenu(node){
  closePop(); const d=node.data();
  let det={}; try{ det=await API('/entity/'+d.entity_id); }catch(e){ det={type:d.type,value:d.value,metadata:{},confidence:d.confidence}; }
  const meta=det.metadata||{}, col=COLOR[d.type]||'#6b7684';
  const conf=Math.round(((det.confidence!=null?det.confidence:d.confidence)||0)*100);
  const p=document.createElement('div'); p.className='pop inspector'; p.id='pop';
  let h=`<div class="ins-h"><span class="ins-badge" style="background:${col}22;color:${col};border-color:${col}66">${d.type}</span>
    ${det.confirmed?'<span class="ins-ok">✓ confirmed</span>':''}<span class="ins-conf">${conf}%</span>
    <button class="ins-x" aria-label="Close">&times;</button></div>
    <div class="ins-val">${escapeHtml(det.value||d.value)}</div>`;
  const chips=[];
  if(meta.severity)chips.push(`<span class="sev ${meta.severity}">${meta.severity}</span>`);
  if(meta.source)chips.push(`<span class="ins-chip">via ${escapeHtml(meta.source)}</span>`);
  if(det.times_seen>1)chips.push(`<span class="ins-chip">seen ${det.times_seen}×</span>`);
  if(det.children)chips.push(`<span class="ins-chip" title="connected nodes in the graph">${det.children} connected</span>`);
  if(chips.length)h+=`<div class="ins-chips">${chips.join('')}</div>`;
  if(meta.url)h+=`<div class="ins-row"><span class="k">affects</span><span class="v mono">${escapeHtml(meta.url)}</span></div>`;
  if(det.explain){ const ex=det.explain;
    h+=`<div class="ins-explain"><div class="ex-t">What this means</div><div class="ex-p">${escapeHtml(ex.plain||'')}</div>`;
    if(ex.why)h+=`<div class="ex-why">${escapeHtml(ex.why)}</div>`;
    if(ex.fix&&ex.fix.length)h+=`<div class="ex-fix"><b>Fix:</b> ${escapeHtml(ex.fix[0])}</div>`; h+=`</div>`;
  } else if(meta.detail){ h+=`<div class="ins-explain"><div class="ex-p mono">${escapeHtml(meta.detail)}</div></div>`; }
  p.innerHTML=h;
  const acts=document.createElement('div'); acts.className='ins-acts';
  const mk=(html,cls,fn,t)=>{ const b=document.createElement('button'); b.className='ins-act '+(cls||''); b.innerHTML=html; if(t)b.title=t; b.onclick=fn; acts.appendChild(b); };
  mk('<svg class="ic" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>'+(det.confirmed?'Unconfirm':'Confirm'),'',()=>confirmNode(d.entity_id,!det.confirmed));
  mk('<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/></svg>Focus','',()=>{focusCyNode(node);closePop();});
  mk('<svg class="ic" viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>Copy','',()=>{try{navigator.clipboard.writeText(det.value||d.value);}catch(e){} toast('Copied'); closePop();});
  mk('<svg class="ic" viewBox="0 0 24 24"><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2m2 0-1 13a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1L6 7"/></svg>Delete','danger',()=>deleteNode(d.entity_id));
  p.appendChild(acts);
  const {tools}=await API('/suggest?type='+encodeURIComponent(d.type));
  if(tools.length){ const dv=document.createElement('div'); dv.className='ins-run-t'; dv.textContent='Run next on this'; p.appendChild(dv);
    const rr=document.createElement('div'); rr.className='ins-run';
    tools.forEach(t=>{ const b=document.createElement('button'); b.className='ins-tool'; b.innerHTML=`<span class="dot" style="background:${NM[t.noise].c}"></span>${t.name}`; b.onclick=()=>doRun(t.id,String(d.value)); rr.appendChild(b); }); p.appendChild(rr); }
  // ── exploit path: turn a finding into the concrete next step ──
  const _cve=(meta.cve||'').trim(), _val=String(d.value);
  if(d.type==='exploit'){
    const dv=document.createElement('div'); dv.className='ins-run-t'; dv.style.color='var(--exploit)'; dv.textContent='Exploit path'; p.appendChild(dv);
    const rr=document.createElement('div'); rr.className='ins-run';
    if(meta.url){ const a=document.createElement('button'); a.className='ins-tool'; a.textContent='↗ Open on Exploit-DB'; a.onclick=()=>{ try{ window.open(meta.url,'_blank','noopener'); }catch(e){} }; rr.appendChild(a); }
    const b=document.createElement('button'); b.className='ins-tool'; b.textContent='→ Use in Metasploit';
    b.onclick=()=>{ closePop(); const q=_cve?('cve:'+_cve):(meta.id?('edb-id:'+meta.id):_val); sendTo('exploit',{msfSearch:q}); };
    rr.appendChild(b); p.appendChild(rr);
  } else if(['vulnerability','service','technology','software'].includes(d.type) || _cve){
    const dv=document.createElement('div'); dv.className='ins-run-t'; dv.style.color='var(--exploit)'; dv.textContent='Exploit path'; p.appendChild(dv);
    const rr=document.createElement('div'); rr.className='ins-run';
    const b=document.createElement('button'); b.className='ins-tool'; b.style.borderColor='var(--exploit)'; b.style.color='var(--exploit)';
    b.innerHTML='⚡ Find exploits for this'; b.title='Search Exploit-DB for public exploits matching this';
    b.onclick=()=>doRun('exploit_search', _cve||_val);
    rr.appendChild(b); p.appendChild(rr);
  }
  const st=[], ty=d.type, val=String(d.value);
  if(['url','domain','host','ip'].includes(ty)){ st.push(['Audit login (Credentials)',()=>sendTo('credentials',{target:val})]); st.push(['Watch (Live Traffic)',()=>sendTo('traffic',{target:val})]); }
  if(ty==='file'){ st.push(['Analyze (Analyzer)',()=>sendTo('analyzer',{target:val})]); }
  if(st.length){ const dv=document.createElement('div'); dv.className='ins-run-t'; dv.textContent='Send to'; p.appendChild(dv);
    const rr=document.createElement('div'); rr.className='ins-run';
    st.forEach(([lbl,fn])=>{ const b=document.createElement('button'); b.className='ins-tool'; b.textContent='→ '+lbl; b.onclick=()=>{ closePop(); fn(); }; rr.appendChild(b); }); p.appendChild(rr); }
  document.body.appendChild(p); p.querySelector('.ins-x').onclick=closePop;
  const rect=$('#graph').getBoundingClientRect(),pos=node.renderedPosition();
  p.style.left=Math.max(10,Math.min(rect.left+pos.x+14,window.innerWidth-p.offsetWidth-12))+'px';
  p.style.top=Math.max(10,Math.min(rect.top+pos.y+8,window.innerHeight-p.offsetHeight-12))+'px';
}
function closePop(){ const p=$('#pop'); if(p)p.remove(); }
async function confirmNode(id,val=true){ closePop(); await fetch('/api/entities/'+id+'/confirm?confirmed='+(val?'true':'false'),{method:'POST'}); toast(val?'Pinned as ground truth':'Un-pinned',val?'ok':''); refresh(); }
async function deleteNode(id){ closePop(); await fetch('/api/entities/'+id,{method:'DELETE'}); sel=null; toast('Node removed','warn'); refresh(); }
async function resetGraph(){
  if(!S.inv)return;
  if(!await ask({title:'Clear the graph?',msg:'Every node, edge and finding in this investigation will be removed.',ok:'Clear',danger:true}))return;
  await fetch('/api/investigations/'+S.inv+'/reset',{method:'POST'}); toast('Graph cleared','warn'); refresh();
}
function sevIcon(s){ s=(s||'info').toLowerCase();
  const col=(s==='critical'||s==='high')?'var(--danger)':(s==='medium')?'var(--moderate)':'var(--whisper)';
  const shape=(s==='critical'||s==='high')?'<path d="M8 1l7 13H1z"/>':(s==='medium')?'<path d="M8 1l7 7-7 7-7-7z"/>':'<circle cx="8" cy="8" r="6"/>';
  return `<svg class="sic" viewBox="0 0 16 16" style="color:${col}">${shape}</svg>`; }
async function loadFindings(){
  const f=await API('/findings/'+S.inv);
  $('#findings').style.display=f.length?'block':'none'; $('#vsplitter').style.display=f.length?'block':'none';
  $('#findings').innerHTML=f.length?('<div class="fh">Findings <span class="hh">· click to locate</span></div>'+
    f.map((x,i)=>`<div class="fd" data-i="${i}" title="Locate in graph">${sevIcon(x.severity)}<span class="sev ${x.severity}">${x.severity}</span><span class="ft">${escapeHtml(x.title)}</span></div>`).join('')):'';
  $('#findings').querySelectorAll('.fd').forEach(el=>el.onclick=()=>focusFinding(f[+el.dataset.i].title));
}

// ── running a tool ───────────────────────────────────────
function classify(x){ if(/\[\+\]|found|open|CRACKED|profile|200 /i.test(x))return'success'; if(/error|blocked|failed|refused|\[-\]/i.test(x))return'error'; if(/\[RODE\]/.test(x))return'info'; if(/warn|⚠/i.test(x))return'warn'; return''; }
function setSpin(st){ const s=$('#spinner'); if(s)s.className='spinner'+(st?' '+st:''); }
function showTeach(tool){
  const t=tool.teach||{}; $('#teach').style.display='block'; $('#teachCmd').style.display='none';
  $('#teachTool').innerHTML=`${tool.name} <span class="dot" style="background:${NM[tool.noise].c}"></span><span style="font-size:12px;color:var(--mut);font-weight:400">${tool.noise}</span>`;
  $('#teachWhat').textContent=(t.what||'')+(t.why?(' '+t.why):'');
  let f=''; if(t.flags)for(const k in t.flags)f+=`<div class="flag"><code>${k}</code> — ${t.flags[k]}</div>`;
  if(t.next)f+=`<div class="flag">next: ${t.next}</div>`; if(t.warn)f+=`<div class="flag" style="color:var(--loud)">⚠ ${t.warn}</div>`;
  $('#teachFlags').innerHTML=f;
}
async function doRun(toolId,target){
  closePop();
  if(!S.inv){ toast('Create an investigation first','warn'); return; }
  $('#toolSel').value=toolId; updateNoiseTag(); $('#targetInput').value=target;
  const tool=S.tools.find(t=>t.id===toolId); if(tool)showTeach(tool);
  $('#runBtn').disabled=true; setSpin('run');
  runTool({tool_id:toolId,target,investigation_id:S.inv,confirmed:false},{
    onStart:m=>{ $('#cancelBtn').style.display='inline-flex'; term('› '+toolId+' → '+target,'info'); },
    onCommand:m=>{},
    onOutput:x=>{ x=String(x).replace(/\n$/,''); if(!x.trim())return;
      if(x.indexOf('[CMD] ')===0){ const c=$('#teachCmd'); if(c){c.textContent='$ '+x.slice(6);c.style.display='block';} return; }
      term(x,classify(x)); },
    onAdvisory:msg=>{ term('⚠ '+msg,'warn'); toast('Off-scope target — advisory only','warn'); },
    onConfirm:m=>{ $('#confirmMsg').innerHTML=`<b>${m.tool_id}</b> is rated <b style="color:var(--loud)">${m.noise}</b>.`; show('#confirmOverlay'); $('#runBtn').disabled=false; setSpin(''); },
    onParsed:m=>{ term('✓ '+m.summary+'  (+'+m.entities+' nodes, '+m.findings.length+' findings)','success'); if(m.findings.length)toast(m.findings.length+' new finding(s)','ok'); refresh(); },
    onDone:m=>{ finishRun(); if(m.exit_code)term('✗ exited '+m.exit_code+' · '+((m.duration_ms||0)/1000).toFixed(0)+'s','error'); else term('✓ done · '+((m.duration_ms||0)/1000).toFixed(0)+'s','sys'); },
    onError:msg=>{ term('✗ '+msg,'error'); finishRun(); },
  });
}
function finishRun(){ $('#runBtn').disabled=false; $('#cancelBtn').style.display='none'; setSpin('done'); setTimeout(()=>setSpin(''),1400); updateFootprint(); }

// ── layout toggles + splitters ───────────────────────────
function toggleGraphMax(){ const w=$('#invwrap'); $('#aside').classList.remove('console-full'); w.classList.toggle('max-graph'); setTimeout(()=>{cy&&cy.resize();},180); }
function toggleConsoleMax(){ $('#invwrap').classList.remove('max-graph'); $('#aside').classList.toggle('console-full'); setTimeout(()=>{cy&&cy.resize();},180); }
function initSplitter(){
  const sp=$('#splitter'); let drag=false;
  sp.addEventListener('mousedown',e=>{drag=true;sp.classList.add('drag');document.body.style.userSelect='none';e.preventDefault();});
  const mv=e=>{ if(!drag)return; let w=window.innerWidth-e.clientX-66; w=Math.max(300,Math.min(w,window.innerWidth-420)); document.documentElement.style.setProperty('--side-w',w+'px'); };
  const up=()=>{ if(!drag)return; drag=false; sp.classList.remove('drag'); document.body.style.userSelect=''; if(cy)cy.resize(); };
  window.addEventListener('mousemove',mv); window.addEventListener('mouseup',up);
  winCleanup.push(()=>{window.removeEventListener('mousemove',mv);window.removeEventListener('mouseup',up);});
}
function initVSplitter(){
  const sp=$('#vsplitter'); let drag=false;
  sp.addEventListener('mousedown',e=>{drag=true;sp.classList.add('drag');document.body.style.userSelect='none';e.preventDefault();});
  const mv=e=>{ if(!drag)return; const a=$('#aside').getBoundingClientRect(); let h=a.bottom-e.clientY; h=Math.max(72,Math.min(h,a.height-150)); document.documentElement.style.setProperty('--find-h',h+'px'); };
  const up=()=>{ if(!drag)return; drag=false; sp.classList.remove('drag'); document.body.style.userSelect=''; };
  window.addEventListener('mousemove',mv); window.addEventListener('mouseup',up);
  winCleanup.push(()=>{window.removeEventListener('mousemove',mv);window.removeEventListener('mouseup',up);});
}

export default { id:'investigation', label:'Investigation', short:'Graph', mount, unmount };
