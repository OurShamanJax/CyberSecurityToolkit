// pages/home.js — the front door. A command-center landing screen: what
// investigation you're in, what it holds, the latest findings, and one-click
// jumps into the work. Reads the same endpoints the tools do.
import { $, API, S, escapeHtml, toast, NM } from '../core.js';
import { show, sendTo, selectInv } from '../app.js';

const SEVW={critical:4,high:3,medium:2,low:1,info:0};

function shell(){ return `
<div class="page"><div class="page-h"><h2>Home</h2>
  <p>Your command center — pick up where you left off, see what R.O.D.E has found, and jump straight into the work.</p></div>
<div class="page-body" id="homeBody"><div class="muted" style="padding:20px">Loading…</div></div></div>`; }

function actionCard(icon,title,sub,onclick,accent){
  const b=document.createElement('button'); b.className='hm-act';
  if(accent)b.style.borderColor=accent;
  b.innerHTML=`<svg class="ic" viewBox="0 0 24 24" style="width:20px;height:20px;color:${accent||'var(--accent)'}">${icon}</svg>
    <span class="hm-at">${title}</span><span class="hm-as">${sub}</span>`;
  b.onclick=onclick; return b;
}

async function render(root){
  const body=$('#homeBody'); if(!body)return;
  let invs=[]; try{ invs=await API('/investigations'); }catch(e){}
  body.innerHTML='';

  // ── current investigation summary ──
  if(S.inv){
    let nodes=[], finds=[], fp={level:'silent'};
    try{ const g=await API('/graph/'+S.inv); nodes=g.nodes||[]; }catch(e){}
    try{ finds=await API('/findings/'+S.inv); }catch(e){}
    try{ fp=await API('/footprint/'+S.inv); }catch(e){}
    const name=(invs.find(i=>i.id===S.inv)||{}).name||'current investigation';
    const bySev={}; finds.forEach(f=>bySev[f.severity]=(bySev[f.severity]||0)+1);
    const worst=finds.slice().sort((a,b)=>(SEVW[b.severity]||0)-(SEVW[a.severity]||0));

    const head=document.createElement('div'); head.className='hm-head';
    head.innerHTML=`<div><div class="hm-eyebrow">current investigation</div>
      <div class="hm-title">${escapeHtml(name)}</div>
      <div class="hm-scope">${(S.scope&&S.scope.length)?escapeHtml(S.scope.join(', ')):'<span class="muted">no scope set</span>'} · <span class="muted">${escapeHtml(S.mode||'infra')} mode</span></div></div>`;
    body.appendChild(head);

    const stats=document.createElement('div'); stats.className='hm-stats';
    const stat=(n,l,c)=>`<div class="hm-stat"><div class="hm-n" ${c?`style="color:${c}"`:''}>${n}</div><div class="hm-l">${l}</div></div>`;
    const fpc=(NM[fp.level]&&NM[fp.level].c)||'var(--dim)';
    stats.innerHTML=stat(nodes.length,'entities')+stat(finds.length,'findings')+
      stat(bySev.critical||bySev.high?((bySev.critical||0)+(bySev.high||0)):'0','high / critical',(bySev.critical||bySev.high)?'var(--danger)':'')+
      stat(escapeHtml(fp.level||'—'),'footprint',fpc);
    body.appendChild(stats);

    // recent findings
    const fc=document.createElement('div'); fc.className='card2';
    if(worst.length){
      fc.innerHTML='<h3>Top findings</h3>';
      const list=document.createElement('div'); list.className='hm-finds';
      worst.slice(0,6).forEach(f=>{ const r=document.createElement('button'); r.className='hm-find';
        r.innerHTML=`<span class="sev ${f.severity}">${f.severity}</span><span class="hm-ft">${escapeHtml(f.title)}</span>`;
        r.onclick=()=>{ location.hash='#/investigation'; }; list.appendChild(r); });
      fc.appendChild(list);
    } else {
      fc.innerHTML='<h3>Top findings</h3><p class="muted" style="margin:0">Nothing flagged yet. Run recon on a target and findings will surface here.</p>';
    }
    body.appendChild(fc);
  } else {
    const empty=document.createElement('div'); empty.className='card2';
    empty.innerHTML=`<h3>No investigation open</h3>
      <p class="muted" style="margin:0 0 12px">An investigation is the workspace everything feeds into — the graph, the map, the timeline and the report all read from it. Create one to begin.</p>`;
    const b=document.createElement('button'); b.className='primary'; b.textContent='+ New investigation'; b.onclick=()=>show('#invOverlay');
    empty.appendChild(b); body.appendChild(empty);
  }

  // ── quick actions ──
  const qa=document.createElement('div'); qa.className='card2';
  qa.innerHTML='<h3>Jump in</h3>';
  const grid=document.createElement('div'); grid.className='hm-grid';
  grid.appendChild(actionCard('<circle cx="6" cy="6" r="2.2"/><circle cx="18" cy="7" r="2.2"/><circle cx="12" cy="17" r="2.2"/><path d="M7.6 7.2 10.6 15M16.4 8.6 13.2 15.2"/>','Investigation graph','see everything connected',()=>{location.hash='#/investigation';}));
  grid.appendChild(actionCard('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>','World map','locate, trace &amp; fly the globe',()=>sendTo('investigation',{lens:'map'})));
  grid.appendChild(actionCard('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>','Check my exposure','open ports, products, CVEs',()=>{location.hash='#/exposure';}));
  grid.appendChild(actionCard('<path d="M3 12h4l2-7 4 14 2-7h6"/>','Live traffic','watch the wire in plain English',()=>{location.hash='#/traffic';}));
  grid.appendChild(actionCard('<path d="M13 2 3 14h7l-1 8 10-12h-7z"/>','Exploit workspace','find exploits, build payloads',()=>{location.hash='#/exploit';},'var(--exploit)'));
  grid.appendChild(actionCard('<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5M8 13h8M8 17h6"/>','Report','the write-up, at two levels',()=>{location.hash='#/report';}));
  qa.appendChild(grid); body.appendChild(qa);

  // ── investigations switcher ──
  if(invs.length){
    const ic=document.createElement('div'); ic.className='card2';
    ic.innerHTML='<h3>Your investigations</h3>';
    const list=document.createElement('div'); list.className='hm-invs';
    invs.forEach(i=>{ const r=document.createElement('button'); r.className='hm-inv'+(i.id===S.inv?' on':'');
      r.innerHTML=`<span class="hm-it">${escapeHtml(i.name)}</span><span class="hm-is muted">${(i.scope&&i.scope.length)?escapeHtml(i.scope.slice(0,2).join(', ')):i.mode||''}</span>${i.id===S.inv?'<span class="hm-cur">current</span>':''}`;
      r.onclick=async ()=>{ if(i.id!==S.inv){ await selectInv(i.id); toast('Switched to '+i.name,'ok'); } render(root); };
      list.appendChild(r); });
    ic.appendChild(list);
    const nb=document.createElement('button'); nb.className='sm ghost'; nb.style.marginTop='10px'; nb.textContent='+ New investigation'; nb.onclick=()=>show('#invOverlay');
    ic.appendChild(nb);
    body.appendChild(ic);
  }
}

function mount(root){ root.innerHTML=shell(); render(root); }
export default { id:'home', label:'Home', short:'Home', mount, unmount(){} };
