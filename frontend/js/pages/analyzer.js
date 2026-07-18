// pages/analyzer.js — unified app/binary/directory analysis with expand-to-detail
import { $, API, S, escapeHtml, makeTyper, toast, runTool, pageHead } from '../core.js';
import { updateFootprint } from '../app.js';
let tab='running', view='list';

function shell(){ return `
<div class="page">${pageHead({
  title:'Analyzer', tag:'unified',
  intro:"Statically analyze what a program can do — read/write memory, inject, key-log, phone home — plus scan folders for vulnerable dependencies and leaked secrets. Pick a <b>running app</b>, a <b>folder</b>, or a <b>file path</b>. Runs locally / in Docker and lands in this investigation's graph.",
  help:"<b>Static</b> analysis means R.O.D.E reads the program without running it — so inspecting a suspicious binary is safe. The <b>Running apps</b> tab lists live processes (needs psutil); <b>Directory</b> runs Trivy over a folder for vulnerable dependencies and leaked secrets; <b>File path</b> inspects a single .exe/.dll/ELF for its capabilities. Everything attaches to the current investigation's graph."
})}
<div class="page-body" id="abody"></div></div>`; }

function listView(root){
  view='list';
  $('#abody').innerHTML=`
    <div style="display:flex;gap:8px;margin-bottom:14px">
      <button class="sm ${tab==='running'?'primary':'ghost'}" data-tab="running">Running apps</button>
      <button class="sm ${tab==='dir'?'primary':'ghost'}" data-tab="dir">Directory</button>
      <button class="sm ${tab==='file'?'primary':'ghost'}" data-tab="file">File path</button>
    </div><div id="tabBody"></div>`;
  $('#abody').querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{ tab=b.dataset.tab; listView(root); });
  if(tab==='running') renderRunning();
  else if(tab==='dir') renderDir();
  else renderFile();
}
async function renderRunning(){
  const body=$('#tabBody'); body.innerHTML='<div class="muted">Loading running processes…</div>';
  const r=await API('/processes');
  if(!r.available){ body.innerHTML='<div class="card2"><p>Process listing needs <span class="kbd">psutil</span> (in v4 requirements). Restart start.bat to enable it. The Directory and File tabs still work.</p></div>'; return; }
  if(!r.processes.length){ body.innerHTML='<div class="muted">No running executables found.</div>'; return; }
  body.innerHTML=`<div class="grid2">${r.processes.slice(0,60).map(p=>`
    <div class="card" data-exe="${escapeHtml(p.exe)}" data-name="${escapeHtml(p.name||'?')}"><div class="cn">${escapeHtml(p.name||'?')}<span class="stt ok">${p.mb} MB</span></div>
    <div class="cc">pid ${p.pid}</div><div class="cw mono" style="font-size:11px;word-break:break-all">${escapeHtml(p.exe)}</div></div>`).join('')}</div>`;
  body.querySelectorAll('.card').forEach(c=>c.onclick=()=>detailView('binary_inspector', c.dataset.exe, c.dataset.name));
}
function renderDir(){
  $('#tabBody').innerHTML=`<div class="card2"><h3>Scan a directory</h3>
    <p>Trivy scans a folder for vulnerable dependencies, leaked secrets, and misconfigurations.</p>
    <div style="display:flex;gap:8px"><input id="dirIn" placeholder="/path/to/project or C:\\code\\app" style="flex:1"/><button class="primary" id="dirGo">Scan folder</button></div></div>`;
  $('#dirGo').onclick=()=>{ const v=$('#dirIn').value.trim(); if(v)detailView('trivy',v,v); };
}
function renderFile(){
  $('#tabBody').innerHTML=`<div class="card2"><h3>Inspect a binary</h3>
    <p>Statically reveal a program's capabilities from its file (.exe / .dll / ELF) — no execution.</p>
    <div style="display:flex;gap:8px"><input id="fileIn" placeholder="/path/to/app.exe" style="flex:1"/><button class="primary" id="fileGo">Inspect</button></div></div>`;
  $('#fileGo').onclick=()=>{ const v=$('#fileIn').value.trim(); if(v)detailView('binary_inspector',v,v); };
}
function detailView(toolId, target, title){
  view='detail';
  $('#abody').innerHTML=`
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
      <button class="ghost sm" id="back"><svg class="ic" viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>Back</button>
      <div><div style="font-weight:600;font-size:15px">${escapeHtml(title||target)}</div>
        <div class="mono" style="font-size:11px;color:var(--dim);word-break:break-all">${toolId==='trivy'?'directory scan':'binary inspection'} · ${escapeHtml(target)}</div></div>
      <div class="spacer"></div><span class="muted" id="dstat">running…</span>
    </div>
    <div class="card2" style="padding:0"><div class="term" id="aterm" style="height:min(60vh,520px)"></div></div>`;
  $('#back').onclick=()=>listView();
  const term=makeTyper($('#aterm'));
  if(!S.inv){ term('Select or create an investigation first — results attach to it.','warn'); $('#dstat').textContent='no investigation'; return; }
  term('› '+toolId+' → '+target,'info');
  runTool({tool_id:toolId,target,investigation_id:S.inv,confirmed:true},{
    onOutput:x=>{ x=String(x).replace(/\n$/,''); if(x.trim()&&x.indexOf('[CMD] ')!==0)term(x); },
    onParsed:m=>{ term('✓ '+m.summary+'  (+'+m.entities+' nodes)','success'); toast('Analyzed — see the graph','ok'); updateFootprint(); },
    onDone:m=>{ term('✓ done','sys'); $('#dstat').textContent='done'; },
    onError:msg=>{ term('✗ '+msg,'error'); $('#dstat').textContent='error'; },
  });
}
function mount(root){ root.innerHTML=shell(); listView(root); }
export default { id:'analyzer', label:'Analyzer', short:'Analyze', mount, unmount(){} };
