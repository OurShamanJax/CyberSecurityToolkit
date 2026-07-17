// app.js — boot, IDE tab bar, router, command palette, cross-tool handoff
import { $, API, S, NM, NOISE, escapeHtml, toast } from './core.js';
import investigation from './pages/investigation.js';
import traffic from './pages/traffic.js';
import analyzer from './pages/analyzer.js';
import credentials from './pages/credentials.js';
import wireless from './pages/wireless.js';
import exposure from './pages/exposure.js';
import vpn from './pages/vpn.js';
import atlas from './pages/atlas.js';
import exploits from './pages/exploits.js';
import report from './pages/report.js';
import settings, { applySettings } from './pages/settings.js';

const IC = {
  investigation:'<circle cx="6" cy="6" r="2.2"/><circle cx="18" cy="7" r="2.2"/><circle cx="12" cy="17" r="2.2"/><path d="M7.6 7.2 10.6 15M16.4 8.6 13.2 15.2"/>',
  traffic:'<path d="M3 12h4l2-7 4 14 2-7h6"/>',
  analyzer:'<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 9h8M8 13h5"/>',
  credentials:'<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  wireless:'<path d="M5 12a10 10 0 0 1 14 0M8 15a6 6 0 0 1 8 0"/><circle cx="12" cy="18.5" r="1.3"/>',
  exposure:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
  vpn:'<path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z"/><path d="M9.5 12l1.8 1.8L15 10"/>',
  atlas:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
  exploits:'<path d="M13 2 3 14h7l-1 8 10-12h-7z"/>',
  report:'<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5M8 13h8M8 17h6"/>',
  settings:'<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
};
const PAGES = [investigation, traffic, analyzer, credentials, wireless, exposure, vpn, atlas, exploits, report, settings];
const byId = Object.fromEntries(PAGES.map(p=>[p.id,p]));
let current = null;
const $$ = s => [...document.querySelectorAll(s)];

const GROUPS=[
  {label:'Workspace', ids:['investigation']},
  {label:'Recon',     ids:['exposure','wireless','atlas']},
  {label:'Offense',   ids:['credentials']},
  {label:'Defense',   ids:['traffic','vpn']},
  {label:'Exploit',   ids:['analyzer','exploits']},
  {label:'System',    ids:['report','settings']},
];
function buildSidebar(){
  $('#sidenav').innerHTML = GROUPS.map(g=>`<div class="side-group"><div class="lbl">${g.label}</div>`+
    g.ids.map(id=>{ const p=byId[id]; return p?`<button class="side-item" data-id="${id}"><svg class="ic" viewBox="0 0 24 24">${IC[id]||''}</svg>${p.label}</button>`:''; }).join('')+`</div>`).join('');
  $$('.side-item').forEach(b=>b.onclick=()=>{ location.hash='#/'+b.dataset.id; });
}
function route(){
  const id=(location.hash.replace('#/','')||'investigation');
  const page=byId[id]||investigation;
  if(current && current.unmount) try{ current.unmount(); }catch(e){}
  $('#page').innerHTML=''; current=page;
  $('#pageTitle').textContent=page.label;
  $$('.side-item').forEach(b=>b.classList.toggle('active', b.dataset.id===page.id));
  page.mount($('#page'));
}
export function remountCurrent(){ if(current){ $('#page').innerHTML=''; current.mount($('#page')); } }

// cross-tool handoff: set shared context + navigate; investigation gets a pick event
export function sendTo(pageId, ctx){
  if(ctx) S.ctx = { ...(S.ctx||{}), ...ctx };
  if(pageId==='investigation'){
    location.hash='#/investigation';
    setTimeout(()=>document.dispatchEvent(new CustomEvent('rode:pick',{detail:{tool:ctx&&ctx.tool,target:ctx&&ctx.target}})),60);
  } else location.hash='#/'+pageId;
}

// ── header: investigations ───────────────────────────────
async function loadInvestigations(sel){
  const list=await API('/investigations');
  $('#invSel').innerHTML='<option value="">— investigation —</option>'+list.map(i=>`<option value="${i.id}">${escapeHtml(i.name)}</option>`).join('');
  const pick=sel||(list[0]&&list[0].id);
  if(pick){ $('#invSel').value=pick; await selectInv(pick); }
  else { S.inv=null;S.scope=[];S.mode='infra'; setScopeChip(); updateFootprint(); remountCurrent(); }
}
async function selectInv(id){
  if(!id)return; const inv=await API('/investigations/'+id);
  S.inv=id; S.scope=inv.scope||[]; S.mode=inv.mode||'infra';
  setScopeChip(); updateFootprint(); remountCurrent();
}
function setScopeChip(){
  const c=$('#scopeChip');
  if(!S.inv){ c.innerHTML='<span class="dot" style="background:var(--dim)"></span>no investigation'; return; }
  c.innerHTML=`<span class="dot" style="background:var(--silent)"></span>${escapeHtml(S.scope.join(', ')||'advisory')}`;
}
export async function updateFootprint(){
  const bars=$('#fpbars').children;
  const set=(on,c)=>{ $('#fpbars').style.setProperty('--_fpc',c); for(let i=0;i<bars.length;i++)bars[i].classList.toggle('on',i<on); };
  if(!S.inv){ set(0,NM.silent.c); $('#fpLvl').textContent='—'; $('#fpLvl').style.color='var(--dim)'; return; }
  const f=await API('/footprint/'+S.inv); const lvl=f.level||'silent';
  const on=f.runs?NOISE.indexOf(lvl)+1:0; set(on,NM[lvl].c);
  $('#fpLvl').textContent=f.runs?lvl:'—'; $('#fpLvl').style.color=f.runs?NM[lvl].c:'var(--dim)';
}

// ── modals ───────────────────────────────────────────────
export function ask(o){
  o=o||{};
  return new Promise(res=>{
    $('#askTitle').textContent=o.title||'Are you sure?'; $('#askMsg').textContent=o.msg||'';
    const ok=$('#askOk'); ok.textContent=o.ok||'Confirm'; ok.className='primary'+(o.danger?' danger-solid':'');
    show('#askOverlay'); ok.focus();
    const done=v=>{ hide('#askOverlay'); ok.onclick=null; $('#askCancel').onclick=null; res(v); };
    ok.onclick=()=>done(true); $('#askCancel').onclick=()=>done(false);
  });
}
export const show=s=>$(s).classList.add('show');
export const hide=s=>$(s).classList.remove('show');

// ── command palette ──────────────────────────────────────
let palItems=[], palSel=0;
function palList(filter){
  const f=(filter||'').toLowerCase().trim(), items=[];
  PAGES.forEach((p,i)=>items.push({grp:'Go to',label:p.label,icon:IC[p.id],k:i<9?'Alt+'+(i+1):'',run:()=>location.hash='#/'+p.id}));
  items.push({grp:'Action',label:'New investigation',icon:IC.investigation,run:()=>show('#invOverlay')});
  items.push({grp:'Action',label:'Open Arsenal',run:()=>show('#arsenalOverlay')});
  if(S.inv) items.push({grp:'Action',label:'Edit scope',run:editScope});
  const tgt=(S.ctx&&S.ctx.target)||'';
  S.tools.filter(t=>t.status.runnable).forEach(t=>items.push({grp:'Run',label:'Run '+t.name+(tgt?(' on '+tgt):''),sub:t.noise,run:()=>sendTo('investigation',{tool:t.id,target:tgt})}));
  return items.filter(it=>!f||it.label.toLowerCase().includes(f));
}
function renderPalette(){
  palItems=palList($('#palInput').value); if(palSel>=palItems.length)palSel=Math.max(0,palItems.length-1);
  $('#palRes').innerHTML = palItems.length? palItems.map((it,i)=>
    `<div class="pi${i===palSel?' sel':''}" data-i="${i}"><svg class="ic" viewBox="0 0 24 24">${it.icon||''}</svg><span>${escapeHtml(it.label)}</span>${it.sub?`<span class="sub">${it.sub}</span>`:''}<span class="k">${it.k||it.grp}</span></div>`).join('')
    : '<div class="pi"><span class="sub">No matches</span></div>';
  $('#palRes').querySelectorAll('.pi[data-i]').forEach(el=>el.onclick=()=>runPal(+el.dataset.i));
}
function runPal(i){ const it=palItems[i]; closePalette(); if(it&&it.run)it.run(); }
function openPalette(){ palSel=0; $('#palInput').value=''; show('#palette'); $('#palBg').classList.add('show'); renderPalette(); setTimeout(()=>$('#palInput').focus(),0); }
function closePalette(){ hide('#palette'); $('#palBg').classList.remove('show'); }
function togglePalette(){ $('#palette').classList.contains('show')?closePalette():openPalette(); }

// ── arsenal ──────────────────────────────────────────────
function buildLegend(){ $('#legend').innerHTML='Detectability: &nbsp;'+NOISE.map(n=>`<span><span class="dot" style="background:${NM[n].c}"></span>${n}</span>`).join(''); }
function renderArsenal(){
  const by={}; NOISE.forEach(n=>by[n]=[]); S.tools.forEach(t=>by[t.noise].push(t));
  $('#arsenalBody').innerHTML=NOISE.map(n=>{ if(!by[n].length)return''; const m=NM[n];
    const cards=by[n].map(t=>`<div class="card" data-id="${t.id}"><div class="cn">${t.name}<span class="stt ${t.status.runnable?'ok':'no'}">${t.status.runnable?t.status.mode:'setup'}</span></div><div class="cc">${t.category} · ${t.input_type}</div><div class="cw">${(t.teach&&t.teach.what)||''}</div></div>`).join('');
    return `<div class="grp"><div class="grphead"><span class="dot" style="background:${m.c}"></span>${n} <span class="meta">${m.t} — ${m.d}</span></div><div class="cards">${cards}</div></div>`; }).join('');
  $('#arsenalBody').querySelectorAll('.card').forEach(c=>c.onclick=()=>{ hide('#arsenalOverlay'); sendTo('investigation',{tool:c.dataset.id}); });
}

// ── boot ─────────────────────────────────────────────────
async function boot(){
  applySettings();
  buildSidebar();
  const d=await API('/tools'); S.tools=d.tools; buildLegend(); renderArsenal();
  $('#invSel').onchange=e=>selectInv(+e.target.value);
  $('#newInv').onclick=()=>show('#invOverlay');
  $('#invCancel').onclick=()=>hide('#invOverlay');
  $('#invCreate').onclick=createInv;
  $('#delInv').onclick=deleteInv;
  $('#arsenalBtn').onclick=()=>show('#arsenalOverlay');
  $('#arsenalClose').onclick=()=>hide('#arsenalOverlay');
  $('#palHint').onclick=openPalette;
  $('#palBg').onclick=closePalette;
  $('#palInput').oninput=renderPalette;
  $('#palInput').onkeydown=e=>{
    if(e.key==='ArrowDown'){ e.preventDefault(); palSel=Math.min(palSel+1,palItems.length-1); renderPalette(); }
    else if(e.key==='ArrowUp'){ e.preventDefault(); palSel=Math.max(palSel-1,0); renderPalette(); }
    else if(e.key==='Enter'){ e.preventDefault(); runPal(palSel); }
  };
  const sc=$('#scopeChip'); sc.onclick=editScope;
  sc.addEventListener('keydown',e=>{ if(e.key==='Enter'||e.key===' '){e.preventDefault();editScope();} });
  $('#confirmCancel').onclick=()=>hide('#confirmOverlay');
  $('#confirmGo').onclick=()=>{ hide('#confirmOverlay'); import('./core.js').then(m=>m.resendConfirmed()); };
  document.addEventListener('keydown', globalKeys);
  window.addEventListener('hashchange', route);
  await loadInvestigations();
  if(!location.hash) location.hash='#/investigation'; else route();
}
function globalKeys(e){
  if((e.ctrlKey||e.metaKey)&&(e.key==='k'||e.key==='K')){ e.preventDefault(); togglePalette(); return; }
  if(e.key==='Escape'){ closePalette(); $$('.overlay.show').forEach(o=>o.classList.remove('show')); return; }
  if(e.altKey && !e.ctrlKey && !e.metaKey && e.key>='1' && e.key<='9'){ const i=+e.key-1; if(PAGES[i]){ e.preventDefault(); location.hash='#/'+PAGES[i].id; } }
}
async function createInv(){
  const name=$('#invName').value.trim()||'Untitled', mode=$('#invMode').value;
  const scope=$('#invScope').value.split(',').map(s=>s.trim()).filter(Boolean);
  const r=await fetch('/api/investigations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,scope,mode})}).then(x=>x.json());
  hide('#invOverlay'); $('#invName').value=''; $('#invScope').value='';
  await loadInvestigations(r.id); toast('Investigation created','ok');
}
async function deleteInv(){
  if(!S.inv)return; const name=$('#invSel').selectedOptions[0].textContent;
  if(!await ask({title:'Delete investigation?',msg:`"${name}" and all its nodes and findings will be permanently removed.`,ok:'Delete',danger:true}))return;
  await fetch('/api/investigations/'+S.inv,{method:'DELETE'}); toast('Investigation deleted','warn'); await loadInvestigations();
}
async function editScope(){
  if(!S.inv){ toast('Create an investigation first','warn'); return; }
  const v=prompt('Scope — comma-separated targets (advisory only):', S.scope.join(', ')); if(v===null)return;
  const scope=v.split(',').map(s=>s.trim()).filter(Boolean);
  await fetch('/api/investigations/'+S.inv,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({scope})});
  S.scope=scope; setScopeChip(); toast('Scope updated','ok');
}
export { selectInv };
boot();
