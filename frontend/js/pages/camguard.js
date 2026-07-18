// pages/camguard.js — Camera Guard: audit YOUR OWN cameras/IoT and lock them down.
// Defensive counterpart to the camera globe. Scans only your LAN + your own public
// IP; never accesses anyone else's device. A clearly-labelled SAMPLE lets you see it
// work with no camera — sample data is never mixed into a real scan.
import { $, API, S, escapeHtml, toast, pageHead } from '../core.js';
import { sendToBar } from '../app.js';

const SEV = {
  critical:{c:'#e0454a', t:'CRITICAL'}, high:{c:'#e0803a', t:'HIGH'},
  medium:{c:'#e0b93a', t:'MEDIUM'}, low:{c:'#4bb8d0', t:'LOW'}, info:{c:'#7a8797', t:'INFO'},
};
const sevBadge = s => { const v=SEV[s]||SEV.info; return `<span class="cg-sev" style="background:${v.c}22;color:${v.c};border:1px solid ${v.c}55">${v.t}</span>`; };

function shell(){ return `
<div class="page">${pageHead({
  title:'Camera Guard', tag:'defensive',
  intro:'Find exposed cameras &amp; IoT devices on <b>your own</b> network and check whether any are reachable from the internet — then lock them down. The defensive counterpart to the camera globe.',
  help:"This audits devices you own. It scans only your local network (private IP ranges) and your own public IP — it can't reach anyone else's devices, and it never logs in or brute-forces passwords. It detects open services (RTSP video, Telnet, DVR ports) and admin pages with no password, then hands you a plain-English fix checklist. No cameras handy? Hit <b>See a sample audit</b> for a realistic example (clearly marked SAMPLE). And finding that someone else's device is exposed is never permission to access it — use the disclosure template to report it instead."
})}
<div class="page-body">
  <div class="card2"><div class="cg-actions">
    <button class="primary" id="cgScan"><svg class="ic" viewBox="0 0 24 24"><path d="M5 12a10 10 0 0 1 14 0M8 15a6 6 0 0 1 8 0"/><circle cx="12" cy="18.5" r="1.3"/></svg>Scan my network</button>
    <button class="ghost" id="cgExpo"><svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>Check my internet exposure</button>
    <button class="ghost" id="cgSample">See a sample audit</button>
    <span class="spacer"></span><span class="muted" id="cgMeta"></span>
  </div>
  <div class="muted" style="font-size:12px;margin-top:9px">Scans your LAN (private addresses only) and your own public IP — nothing else is ever contacted. No passwords are tried.</div>
  </div>
  <div id="cgRes"></div>
</div></div>`; }

function mount(root){
  root.innerHTML=shell();
  $('#cgScan').onclick=scanNet;
  $('#cgExpo').onclick=checkExpo;
  $('#cgSample').onclick=showSample;
}

async function scanNet(){
  busy('#cgScan', true);
  $('#cgRes').innerHTML=spin('Sweeping your local network and probing each device for camera/IoT services… this takes a few seconds.');
  try{
    const r=await fetch('/api/camaudit/lan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})}).then(x=>x.json());
    busy('#cgScan', false);
    if(!r.ok){ $('#cgRes').innerHTML=errCard(r.error); return; }
    renderScan(r);
  }catch(e){ busy('#cgScan', false); $('#cgRes').innerHTML=errCard('Request failed — is the server running?'); }
}

async function showSample(){
  $('#cgRes').innerHTML=spin('Loading a sample audit…');
  try{ const r=await API('/camaudit/sample'); renderScan(r); }
  catch(e){ $('#cgRes').innerHTML=errCard('Could not load the sample.'); }
}

async function checkExpo(){
  busy('#cgExpo', true);
  $('#cgRes').innerHTML=spin('Looking up what the internet can see of your home connection (your own public IP only)…');
  try{
    const r=await API('/camaudit/exposure'); busy('#cgExpo', false);
    if(!r.ok){ $('#cgRes').innerHTML=errCard(r.error); return; }
    renderExposure(r);
  }catch(e){ busy('#cgExpo', false); $('#cgRes').innerHTML=errCard('Request failed — are you online?'); }
}

function renderScan(r){
  const cams=r.devices.filter(d=>d.is_camera);
  const flagged=r.devices.filter(d=>d.findings.length);
  let h='';
  if(r.is_sample) h+=`<div class="cg-sample">⚠ SAMPLE AUDIT — illustrative data, not your real network. Use “Scan my network” for a real audit.</div>`;
  h+=`<div class="card2"><div class="cg-sum">
    <div><div class="cg-num">${r.device_count}</div><div class="cg-lbl">devices on ${escapeHtml(r.subnet||'your LAN')}</div></div>
    <div><div class="cg-num">${r.camera_count}</div><div class="cg-lbl">camera / DVR</div></div>
    <div><div class="cg-num" style="color:${flagged.length?'#e0803a':'#5fbf8a'}">${r.findings.length}</div><div class="cg-lbl">issues found</div></div>
  </div></div>`;

  if(!r.findings.length){
    h+=`<div class="card2"><h3 style="color:var(--ok)">✓ No exposures found</h3>
      <p class="muted">Scan complete — ${r.device_count} device(s) checked, none showed an open camera/IoT weakness on the ports we probe. That's a good sign. Ports checked: <span class="mono" style="font-size:11px">${r.checked_ports.join(', ')}</span>.</p>
      <p class="muted" style="margin-top:6px">Still worth confirming your cameras aren't using default passwords and aren't port-forwarded to the internet — run <b>Check my internet exposure</b> for that.</p></div>`;
  } else {
    h+=`<div class="card2"><h3>Devices with findings</h3><div id="cgDevs"></div></div>`;
  }
  $('#cgRes').innerHTML=h;
  $('#cgMeta').textContent=(r.is_sample?'sample · ':'')+`${r.device_count} devices · ${r.findings.length} issues`;

  const wrap=$('#cgDevs');
  if(wrap){
    flagged.sort((a,b)=>sevRank(a.worst)-sevRank(b.worst)).forEach(d=>wrap.appendChild(deviceCard(d, r.is_sample)));
  }
}

function deviceCard(d, isSample){
  const el=document.createElement('div'); el.className='cg-dev';
  el.innerHTML=`<div class="cg-dev-h">
      ${sevBadge(d.worst)}
      <div style="flex:1;min-width:0"><b>${escapeHtml(d.label)}</b>
        <span class="mono" style="font-size:11px;color:var(--dim)"> ${escapeHtml(d.ip)}${d.hostname?' · '+escapeHtml(d.hostname):''}</span></div>
      ${d.is_camera?'<span class="cg-tag">📷 camera</span>':(d.is_iot?'<span class="cg-tag">IoT</span>':'')}
    </div>
    <div class="cg-ports">open: ${d.open_ports.map(p=>`<span class="cg-chip">${p}</span>`).join('')||'<span class="muted">none of the checked ports</span>'}</div>
    <div class="cg-finds">${d.findings.map(f=>`
      <div class="cg-find">
        <div class="cg-find-h">${sevBadge(f.severity)}<span>${escapeHtml(f.title)}</span></div>
        <div class="cg-why">${escapeHtml(f.why)}</div>
        <details class="cg-fix"><summary>How to fix (${f.fixes.length})</summary>
          <ul>${f.fixes.map(x=>`<li>${escapeHtml(x)}</li>`).join('')}</ul></details>
      </div>`).join('')}</div>
    <div class="cg-dev-act"></div>`;
  const act=el.querySelector('.cg-dev-act');
  if(!isSample){
    act.appendChild(sendToBar({
      add: async()=>{ if(!S.inv){ toast('Create an investigation first','warn'); return; }
        await fetch('/api/entities/add',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({investigation_id:S.inv,type:'host',value:d.ip,label:d.label+' ('+d.ip+')',
            metadata:{source:'camguard',device:d.label,ports:d.open_ports.join(','),camera:d.is_camera}})}).then(()=>toast('Device added to graph','ok')); },
      sends:[{label:'Scan with Nmap →', page:'investigation', ctx:{tool:'nmap', target:d.ip}}]
    }));
  }
  return el;
}

function renderExposure(r){
  let h='';
  if(r.clean){
    h+=`<div class="card2"><h3 style="color:var(--ok)">✓ Nothing camera/IoT-like is exposed</h3>
      <p class="muted">Your public IP <span class="mono">${escapeHtml(r.ip)}</span> shows no risky camera/DVR/IoT ports reachable from the internet. ${escapeHtml(r.note||'')}</p>
      <p class="muted" style="margin-top:6px">Ports the internet currently sees on you: ${(r.exposed_ports||[]).map(p=>`<span class="cg-chip">${p}</span>`).join('')||'<span class="muted">none</span>'}</p></div>`;
    $('#cgRes').innerHTML=h; $('#cgMeta').textContent='exposure: clean'; return;
  }
  h+=`<div class="card2"><h3 style="color:#e0803a">⚠ ${r.risky_ports.length} camera/IoT port(s) exposed to the internet</h3>
    <p class="muted">Your public IP <span class="mono">${escapeHtml(r.ip)}</span> is reachable on ports that shouldn't be internet-facing. This is exactly how private cameras end up watched by strangers — close these.</p>
    <div id="cgExpoF"></div>
    <div style="margin-top:12px"><button class="sm ghost" id="cgDisc">Responsible-disclosure template</button>
      <span class="muted" style="font-size:11px"> — for reporting <i>someone else's</i> exposed device you happen to find (report it, don't access it)</span></div>
    <div id="cgDiscBox"></div></div>`;
  $('#cgRes').innerHTML=h; $('#cgMeta').textContent=`exposure: ${r.risky_ports.length} risky port(s)`;
  const f=$('#cgExpoF');
  r.findings.forEach(x=>{ const el=document.createElement('div'); el.className='cg-find';
    el.innerHTML=`<div class="cg-find-h">${sevBadge(x.severity)}<span>${escapeHtml(x.title)}</span></div>
      <div class="cg-why">${escapeHtml(x.why)}</div>
      <details class="cg-fix"><summary>How to fix (${x.fixes.length})</summary><ul>${x.fixes.map(y=>`<li>${escapeHtml(y)}</li>`).join('')}</ul></details>`;
    f.appendChild(el); });
  $('#cgDisc').onclick=async()=>{
    try{ const d=await API('/camaudit/disclosure');
      $('#cgDiscBox').innerHTML=`<textarea readonly class="cg-disc">${escapeHtml(d.template)}</textarea>
        <button class="sm" id="cgCopy">Copy</button>`;
      $('#cgCopy').onclick=()=>{ navigator.clipboard&&navigator.clipboard.writeText(d.template); toast('Template copied'); };
    }catch(e){ toast('Could not load template','warn'); }
  };
}

// helpers
const sevRank = s => ({critical:0,high:1,medium:2,low:3,info:4}[s]??9);
const spin = m => `<div class="muted" style="padding:10px 4px"><span class="pulse">●</span> ${escapeHtml(m)}</div>`;
const errCard = m => `<div class="card2"><p style="color:#eaa0a1">✗ ${escapeHtml(m||'failed')}</p></div>`;
function busy(sel,on){ const b=$(sel); if(b) b.disabled=on; }

export default { id:'camguard', label:'Camera Guard', short:'Cameras', mount, unmount(){} };
