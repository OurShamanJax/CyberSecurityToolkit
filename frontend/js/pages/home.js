// pages/home.js — the front door. A command-center landing screen: what
// investigation you're in, what it holds, the latest findings, and one-click
// jumps into the work. Reads the same endpoints the tools do.
import { $, API, S, escapeHtml, toast, NM } from '../core.js';
import { show, sendTo, selectInv } from '../app.js';

const SEVW={critical:4,high:3,medium:2,low:1,info:0};

// ── first-run guided tour ──
const TOUR=[
  ['Welcome to R.O.D.E','A local, free security lab — Recon · Offense · Defense · Exploit. Everything runs on <b>your machine</b>: no accounts, no cloud. You learn offense and defense on systems you own or are authorized to test.'],
  ['Start with an investigation','An <b>investigation</b> is your workspace. Create one with <b>＋ New</b> (top-left) and give it a scope. Every tool you run flows its results into that one place.'],
  ['Run tools, watch the graph grow','Point recon tools — Exposure, LAN Discovery, Nmap — at a target. Findings become a connected <b>graph</b> of hosts, services, technologies, and issues, colour-coded by type.'],
  ['Three views of one story','The same investigation renders as a <b>Graph</b>, a <b>Map</b> (a live globe), and a <b>Timeline</b>. Switch lenses at the top of the Investigation page.'],
  ['It connects the dots','<b>Correlations</b> escalate combined signals, <b>MITRE ATT&CK</b> maps what you did to the framework, and the two-level <b>Report</b> writes it all up — beginner or advanced.'],
  ['Stay legal &amp; safe','Only test what you <b>own or are authorized</b> to test. Loud tools ask for a confirmation first. Now — go break your own stuff and learn how it works.'],
];
function showTour(force){
  if(!force && localStorage.getItem('rode.tour')==='done') return;
  if(document.getElementById('tourOv')) return;
  let i=0;
  const ov=document.createElement('div'); ov.id='tourOv';
  ov.style.cssText='position:fixed;inset:0;z-index:200;background:rgba(4,7,11,.72);display:flex;align-items:center;justify-content:center';
  ov.innerHTML='<div style="background:var(--surface);border:1px solid var(--line2);border-radius:14px;max-width:440px;width:90%;padding:22px 24px;box-shadow:0 24px 70px rgba(0,0,0,.6)">'+
    '<div id="tStep" style="font-size:10px;letter-spacing:.6px;text-transform:uppercase;color:var(--dim)"></div>'+
    '<h2 id="tTitle" style="margin:6px 0 8px;font-size:19px"></h2>'+
    '<div id="tBody" style="font-size:13.5px;line-height:1.6;color:var(--mut)"></div>'+
    '<div style="display:flex;gap:8px;align-items:center;margin-top:18px">'+
      '<button class="sm ghost" id="tSkip">Skip</button><div style="flex:1"></div>'+
      '<button class="sm ghost" id="tBack">Back</button><button class="primary sm" id="tNext">Next</button></div></div>';
  document.body.appendChild(ov);
  const done=()=>{ try{ localStorage.setItem('rode.tour','done'); }catch(e){} ov.remove(); };
  const draw=()=>{ const s=TOUR[i];
    ov.querySelector('#tStep').textContent='Step '+(i+1)+' of '+TOUR.length;
    ov.querySelector('#tTitle').textContent=s[0];
    ov.querySelector('#tBody').innerHTML=s[1];
    ov.querySelector('#tBack').style.visibility=i?'visible':'hidden';
    ov.querySelector('#tNext').textContent=i===TOUR.length-1?'Get started':'Next'; };
  ov.querySelector('#tSkip').onclick=done;
  ov.querySelector('#tBack').onclick=()=>{ if(i>0){i--;draw();} };
  ov.querySelector('#tNext').onclick=()=>{ if(i<TOUR.length-1){i++;draw();} else { done(); if(!S.inv)show('#invOverlay'); } };
  draw();
}

function shell(){ return `
<div class="page"><div class="page-h" style="display:flex;align-items:flex-start;gap:12px">
  <div style="flex:1"><h2>Home</h2>
  <p>Your command center — pick up where you left off, see what R.O.D.E has found, and jump straight into the work.</p></div>
  <button class="sm ghost" id="tourBtn" title="Replay the guided tour">Take the tour</button></div>
<div class="page-body" id="homeBody"><div class="muted" style="padding:20px">Loading…</div></div></div>`; }

function actionCard(icon,title,sub,onclick,accent){
  const b=document.createElement('button'); b.className='hm-act';
  if(accent)b.style.borderColor=accent;
  b.innerHTML=`<svg class="ic" viewBox="0 0 24 24" style="width:20px;height:20px;color:${accent||'var(--accent)'}">${icon}</svg>
    <span class="hm-at">${title}</span><span class="hm-as">${sub}</span>`;
  b.onclick=onclick; return b;
}

async function showDiff(a,b,card){
  const old=card.querySelector('.hm-diff'); if(old)old.remove();
  const box=document.createElement('div'); box.className='hm-diff';
  box.style.cssText='margin-top:9px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;font-family:var(--mono);font-size:11px;line-height:1.5;max-height:240px;overflow:auto';
  box.textContent='diffing…'; card.appendChild(box);
  try{ const d=await API('/runs/diff?a='+a+'&b='+b);
    let h='<div style="color:var(--mut);margin-bottom:6px">Δ '+d.added_count+' added · '+d.removed_count+' removed vs previous run <span style="float:right;cursor:pointer" data-x="1">✕</span></div>';
    d.added.slice(0,60).forEach(l=>{ h+='<div style="color:#5fbf8a">+ '+escapeHtml(l)+'</div>'; });
    d.removed.slice(0,40).forEach(l=>{ h+='<div style="color:#e0686a">- '+escapeHtml(l)+'</div>'; });
    if(!d.added_count&&!d.removed_count)h+='<div class="muted">No changes since the previous run — same result.</div>';
    box.innerHTML=h; const x=box.querySelector('[data-x]'); if(x)x.onclick=()=>box.remove();
  }catch(e){ box.textContent='diff failed'; }
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
    let cov={tactics:[]}; try{ cov=await API('/attack/'+S.inv); }catch(e){}
    let corr={correlations:[]}; try{ corr=await API('/correlate/'+S.inv); }catch(e){}
    let runsH=[]; try{ runsH=await API('/investigations/'+S.inv+'/runs'); }catch(e){}
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

    // correlations — escalated combined-signal findings (the "smart" layer)
    if(corr.correlations&&corr.correlations.length){
      const cc=document.createElement('div'); cc.className='card2';
      cc.innerHTML='<h3>⚡ Correlations</h3><p class="muted" style="margin:0 0 9px">Combined signals that escalate priority — the graph connecting the dots for you.</p>';
      const list=document.createElement('div'); list.style.cssText='display:flex;flex-direction:column;gap:7px';
      corr.correlations.slice(0,7).forEach(c=>{ const r=document.createElement('div');
        r.style.cssText='background:var(--surface2);border:1px solid var(--line);border-radius:8px;padding:9px 11px';
        const geo=c.geo?` <button class="sm ghost" style="padding:1px 7px;font-size:10px">map ↗</button>`:'';
        r.innerHTML=`<div style="display:flex;align-items:center;gap:8px"><span class="sev ${c.level}">${c.level}</span><b style="font-size:12.5px">${escapeHtml(c.title)}</b><span style="flex:1"></span>${geo}</div>`+
          `<div class="muted" style="font-size:11.5px;margin-top:4px">${escapeHtml(c.why)}</div>`;
        if(c.geo){ const b=r.querySelector('button'); if(b)b.onclick=()=>sendTo('investigation',{lens:'map'}); }
        list.appendChild(r); });
      cc.appendChild(list); body.appendChild(cc);
    }

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

    // ATT&CK coverage
    if(cov.tactics&&cov.tactics.length){
      const ac=document.createElement('div'); ac.className='card2';
      ac.innerHTML='<h3>MITRE ATT&CK coverage</h3><p class="muted" style="margin:0 0 9px">'+
        cov.technique_count+' technique'+(cov.technique_count!==1?'s':'')+' across '+cov.tactic_count+' of '+cov.total_tactics+' tactics — click for the full map in the report.</p>';
      const chips=document.createElement('div'); chips.style.cssText='display:flex;flex-wrap:wrap;gap:6px';
      cov.tactics.forEach(t=>{ const c=document.createElement('span'); c.className='ins-chip';
        c.style.cssText='background:var(--surface2);border:1px solid var(--line)';
        c.title=t.techniques.map(x=>x.id+' '+x.name).join(', ');
        c.textContent=t.tactic+' · '+t.techniques.length; chips.appendChild(c); });
      ac.appendChild(chips);
      const b=document.createElement('button'); b.className='sm ghost'; b.style.marginTop='10px'; b.textContent='Open report →'; b.onclick=()=>{location.hash='#/report';};
      ac.appendChild(b);
      body.appendChild(ac);
    }

    // recent activity / run history + export + diff
    {
      const rc=document.createElement('div'); rc.className='card2';
      rc.innerHTML='<div style="display:flex;align-items:center;gap:8px"><h3 style="margin:0;flex:1">Recent activity</h3>'+
        '<a class="sm ghost" href="/api/investigations/'+S.inv+'/export?format=json" style="text-decoration:none">Export JSON</a>'+
        '<a class="sm ghost" href="/api/investigations/'+S.inv+'/export?format=csv" style="text-decoration:none">Export CSV</a></div>';
      if(runsH.length){
        const list=document.createElement('div'); list.style.cssText='display:flex;flex-direction:column;gap:4px;margin-top:9px';
        runsH.slice(0,8).forEach(rn=>{ const row=document.createElement('div');
          row.style.cssText='display:flex;align-items:center;gap:8px;font-size:12px;background:var(--surface2);border:1px solid var(--line);border-radius:7px;padding:6px 9px';
          const st=rn.status==='done'?'var(--ok)':(rn.status==='failed'?'var(--danger)':'var(--dim)');
          const diffBtn=rn.prev_id?`<button class="sm ghost" data-a="${rn.prev_id}" data-b="${rn.id}" style="padding:1px 7px;font-size:10px">Δ diff</button>`:'';
          row.innerHTML=`<span style="color:var(--accent);font-family:var(--mono)">${escapeHtml(rn.tool)}</span>`+
            `<span class="muted" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(rn.target)}</span>`+
            `<span class="muted" style="font-size:10.5px">${escapeHtml(rn.when)}</span>`+
            `<span style="width:7px;height:7px;border-radius:50%;background:${st}" title="${escapeHtml(rn.status)}"></span>${diffBtn}`;
          const db2=row.querySelector('button'); if(db2)db2.onclick=()=>showDiff(db2.dataset.a,db2.dataset.b,rc);
          list.appendChild(row); });
        rc.appendChild(list);
      } else { rc.innerHTML+='<p class="muted" style="margin:9px 0 0">No tool runs yet.</p>'; }
      body.appendChild(rc);
    }
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

function mount(root){ root.innerHTML=shell(); render(root);
  if(localStorage.getItem('rode.tour')!=='done') setTimeout(()=>showTour(),450);
  const t=$('#tourBtn'); if(t)t.onclick=()=>showTour(true);
}
export default { id:'home', label:'Home', short:'Home', mount, unmount(){} };
