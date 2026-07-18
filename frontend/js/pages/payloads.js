// pages/payloads.js — Metasploit workbench. Wraps the REAL upstream tools:
//   • Payload Builder  → composes + runs an msfvenom command (in Docker or a
//                        local install), shows the exact recipe, streams output.
//   • msfconsole       → a live console session (stdin/stdout over a WebSocket).
// Authorized-lab use only. R.O.D.E doesn't invent payloads; msfvenom does the
// work, and every build is validated server-side (allowlist + range checks).
import { $, S, toast, escapeHtml } from '../core.js';

let ws=null, cat=null, statusInfo=null, tab='build', previewTimer=null;

function shell(){ return `
<div class="page msfpage"><div class="page-h"><div class="row1">
    <h2>Metasploit <span class="tag" id="msfstate">…</span></h2>
    <div class="spacer"></div>
    <button class="sm" id="tabBuild">Payload Builder</button>
    <button class="sm ghost" id="tabConsole">msfconsole</button>
  </div>
  <p>Compose and run real <b>msfvenom</b> payloads, or drive a live <b>msfconsole</b> — wrapping the upstream Metasploit Framework (Docker or local). For systems you <b>own or are authorized to test</b>, like your Pop!_OS lab box.</p></div>
<div class="page-body">
  <div class="tf-banner" id="msfbanner">Checking for Metasploit…</div>

  <!-- ── Payload Builder ── -->
  <div id="paneBuild">
    <div class="msf-grid">
      <div class="card2"><h3>1 · Choose a payload</h3>
        <label class="fld">Payload
          <select id="pl"></select></label>
        <div class="pl-info" id="plInfo"></div>
      </div>
      <div class="card2"><h3>2 · Set the listener</h3>
        <div id="lhostWrap"><label class="fld">LHOST <span class="muted">(your machine — where the target calls back)</span>
          <input id="lhost" placeholder="192.168.1.50"/></label></div>
        <label class="fld">LPORT <input id="lport" value="4444"/></label>
        <div class="two">
          <label class="fld">Format <select id="fmt"></select></label>
          <label class="fld">Encoder <select id="enc"></select></label>
        </div>
        <label class="fld">Encoder iterations <input id="iter" value="0" style="width:80px"/></label>
      </div>
    </div>

    <div class="card2"><h3>The exact command</h3>
      <p class="muted" style="margin:0 0 6px">This is the standard msfvenom command — nothing hidden. Run it yourself on a Linux box, or press Generate to run it here.</p>
      <pre class="recipe" id="recipe">—</pre>
      <div id="recWarn"></div>
      <label class="ackrow"><input type="checkbox" id="ack"/> <span>I <b>own</b> or am <b>authorized</b> to test the machine this payload targets/calls back to.</span></label>
      <div class="row1" style="gap:8px;margin-top:8px">
        <button class="primary" id="gen" disabled><svg class="ic fill" viewBox="0 0 24 24"><path d="M7 5l12 7-12 7z"/></svg> Generate payload</button>
        <button class="ghost sm" id="copyCmd">Copy command</button>
      </div>
      <div class="defnote">⚠ On Windows, Defender will quarantine a generated payload the moment it's written — that's AV doing its job. Prefer generating on your Linux attack box, or add an exclusion folder for lab work only. Never disable AV on a machine you actually use.</div>
    </div>

    <div class="card2"><h3>Output</h3><pre class="msf-out" id="buildOut">Ready.</pre>
      <div id="artifact"></div></div>
  </div>

  <!-- ── msfconsole ── -->
  <div id="paneConsole" style="display:none">
    <div class="card2"><h3>msfconsole</h3>
      <p class="muted" style="margin:0 0 8px">Run an <b>msfconsole</b> command and see its output. Each command runs in a <b>fresh console</b> (it boots the framework, ~30–60s), so there's no session state between commands — for a live interactive session, run <span class="kbd">msfconsole</span> in a terminal on your lab box. Try <span class="kbd">version</span>, <span class="kbd">search platform:linux vsftpd</span>.</p>
      <div class="row1" style="gap:6px;margin-bottom:8px"><span class="prompt">msf ›</span><input id="conIn" placeholder="e.g. search platform:linux ssh" style="flex:1"/><button class="primary sm" id="conRun">Run</button></div>
      <pre class="msf-term" id="term">Type a command and press Run.</pre>
    </div>
  </div>
</div></div>`; }

function fillSelect(el, items, cur){ el.innerHTML=items.map(v=>`<option${v===cur?' selected':''}>${v}</option>`).join(''); }

function payloadInfo(p){
  if(!p) return '';
  const loud=['','silent','whisper','moderate','loud','aggressive'][p.loudness]||'moderate';
  return `<div class="sev ${p.severity}">${p.severity}</div>
    <span class="chip">${p.connect}</span> <span class="chip">${p.stage}</span>
    <span class="chip"><span class="dot" style="background:var(--${loud==='loud'||loud==='aggressive'?'loud':loud==='moderate'?'moderate':'silent'})"></span>loudness ${p.loudness}/5</span>
    ${p.meterpreter?'<span class="chip">meterpreter</span>':''}
    <p class="muted" style="margin:8px 0 0">${escapeHtml(p.desc)}</p>`;
}

function selectedPayload(){ return cat.payloads.find(p=>p.id===$('#pl').value); }

function refreshInfo(){
  const p=selectedPayload();
  $('#plInfo').innerHTML=payloadInfo(p);
  // reverse needs LHOST; bind does not
  $('#lhostWrap').style.display = p && p.connect==='bind' ? 'none' : '';
  preview();
}

function opts(){ const p=selectedPayload();
  return { payload:p?p.id:'', lhost:$('#lhost').value.trim(), lport:$('#lport').value.trim()||'4444',
    format:$('#fmt').value, encoder:$('#enc').value, iterations:$('#iter').value.trim()||'0', lab_ack:$('#ack').checked }; }

function preview(){
  clearTimeout(previewTimer);
  previewTimer=setTimeout(async ()=>{
    try{
      const r=await fetch('/api/msf/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(opts())});
      const d=await r.json();
      $('#recipe').textContent = d.command || '(fix the errors below to see the command)';
      $('#recWarn').innerHTML = [
        ...(d.errors||[]).map(e=>`<div class="wl err">✖ ${escapeHtml(e)}</div>`),
        ...(d.warnings||[]).map(w=>`<div class="wl warn">⚠ ${escapeHtml(w)}</div>`),
      ].join('');
      gate(d.ok);
    }catch(e){ $('#recipe').textContent='(preview unavailable)'; }
  }, 180);
}
function gate(previewOk){
  const ok = previewOk && $('#ack').checked && statusInfo && statusInfo.available;
  $('#gen').disabled=!ok;
}

function connect(onMsg){
  if(ws && ws.readyState<=1) return ws;
  ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/msf');
  ws.onmessage=e=>{ try{ onMsg(JSON.parse(e.data)); }catch(_){} };
  ws.onclose=()=>{ conBusy=false; const b=$('#conRun'); if(b)b.disabled=false; };
  return ws;
}

function appendOut(t){ const el=$('#buildOut'); if(el.textContent==='Ready.')el.textContent=''; el.textContent+=t; el.scrollTop=el.scrollHeight; }
function appendTerm(t){ const el=$('#term'); if(el.textContent==='Console not started.')el.textContent=''; el.textContent+=t; el.scrollTop=el.scrollHeight; }

function doGenerate(){
  const o=opts();
  if(!o.lab_ack){ toast('Confirm authorization first','warn'); return; }
  $('#buildOut').textContent=''; $('#artifact').innerHTML='';
  $('#gen').disabled=true;
  const w=connect(m=>{
    if(m.type==='output') appendOut(m.data);
    else if(m.type==='error'){ appendOut('\n[error] '+m.message+'\n'); toast(m.message,'warn'); gate(true); }
    else if(m.type==='done'){
      gate(true);
      if(m.artifact){ $('#artifact').innerHTML=`<div class="wl ok">✔ Wrote <code>${escapeHtml(m.artifact)}</code> — this is a functional payload; handle it only in your lab.</div>`; }
      else appendOut('\n[done] exit '+m.exit_code+'\n');
    }
  });
  const send=()=>w.send(JSON.stringify({action:'build',...o}));
  if(w.readyState===1) send(); else w.onopen=send;
}

function setTab(t){ tab=t;
  $('#paneBuild').style.display = t==='build'?'':'none';
  $('#paneConsole').style.display = t==='console'?'':'none';
  $('#tabBuild').classList.toggle('ghost',t!=='build');
  $('#tabConsole').classList.toggle('ghost',t!=='console');
}
let conBusy=false;
function runConsoleCmd(cmd){
  cmd=(cmd||'').trim(); if(!cmd) return;
  if(conBusy){ toast('A command is still running…','warn'); return; }
  conBusy=true; const btn=$('#conRun'); if(btn)btn.disabled=true;
  const t0=Date.now();
  const el=$('#term'); if(el && el.textContent==='Type a command and press Run.') el.textContent='';
  appendTerm('› '+cmd+'\n');
  const w=connect(m=>{
    if(m.type==='output') appendTerm(m.data);
    else if(m.type==='console_running') appendTerm('[booting msfconsole — this can take 30–60s]\n');
    else if(m.type==='console_done'){ conBusy=false; if(btn)btn.disabled=false; appendTerm('\n[done · '+Math.round((Date.now()-t0)/1000)+'s]\n'); const i=$('#conIn'); if(i)i.focus(); }
    else if(m.type==='error'){ conBusy=false; if(btn)btn.disabled=false; appendTerm('\n[error] '+(m.message||'')+'\n'); }
  });
  const go=()=>w.send(JSON.stringify({action:'console_exec',cmd}));
  if(w.readyState===1) go(); else w.onopen=go;
}

async function mount(root){
  root.innerHTML=shell();
  setTab('build');
  $('#tabBuild').onclick=()=>setTab('build');
  $('#tabConsole').onclick=()=>setTab('console');

  // load catalog + status in parallel
  try{
    const [c,s]=await Promise.all([fetch('/api/msf/payloads').then(r=>r.json()), fetch('/api/msf/status').then(r=>r.json())]);
    cat=c; statusInfo=s;
    fillSelect($('#pl'), c.payloads.map(p=>p.id), c.payloads[0].id);
    fillSelect($('#fmt'), c.formats, c.payloads[0].fmt);
    fillSelect($('#enc'), c.encoders, 'none');
    renderStatus(s);
    refreshInfo();
  }catch(e){ $('#msfbanner').textContent='Could not reach the R.O.D.E backend.'; return; }

  $('#pl').onchange=()=>{ const p=selectedPayload(); if(p) $('#fmt').value=p.fmt; refreshInfo(); };
  ['#lhost','#lport','#iter'].forEach(id=>$(id).oninput=preview);
  ['#fmt','#enc'].forEach(id=>$(id).onchange=preview);
  $('#ack').onchange=()=>gate(true);
  $('#gen').onclick=doGenerate;
  $('#copyCmd').onclick=()=>{ const t=$('#recipe').textContent; try{navigator.clipboard.writeText(t);}catch(_){} toast('Command copied'); };
  $('#conRun').onclick=()=>{ runConsoleCmd($('#conIn').value); $('#conIn').value=''; };
  $('#conIn').onkeydown=e=>{ if(e.key==='Enter'){ runConsoleCmd(e.target.value); e.target.value=''; } };
  if(S.ctx&&S.ctx.msfSearch){ setTab('console'); const ci=$('#conIn'); if(ci)ci.value='search '+S.ctx.msfSearch; S.ctx.msfSearch=null; toast('Loaded into msfconsole — press Run'); }
}

function renderStatus(s){
  const tag=$('#msfstate'), b=$('#msfbanner');
  if(s.available){
    tag.textContent = s.mode==='local' ? 'local install' : (s.image_present?'docker · ready':'docker');
    tag.className='tag';
    b.innerHTML = s.mode==='local'
      ? '● <b>Metasploit found</b> (local install). Payload Builder and msfconsole are live.'
      : (s.image_present
          ? '● <b>Docker image ready.</b> Payload Builder and msfconsole run in a container.'
          : '● <b>Docker is running</b> but the Metasploit image isn\'t pulled yet — first run will download it (~2 GB). <span class="kbd">'+escapeHtml(s.pull_hint)+'</span>');
  } else {
    tag.textContent='not installed'; tag.className='tag soon';
    b.innerHTML='▶ <b>Metasploit not available.</b> '+escapeHtml(s.install_hint||'')+' The builder still shows you the exact command to run elsewhere.';
  }
}

function unmount(){ try{ if(ws){ ws.close(); ws=null; } }catch(e){} }
export default { id:'payloads', label:'Payloads', short:'Payloads', mount, unmount };
