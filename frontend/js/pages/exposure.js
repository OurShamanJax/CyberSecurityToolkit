// pages/exposure.js — internet-exposure lookup (Shodan InternetDB, free/no-account)
import { $, API, S, escapeHtml, toast } from '../core.js';
import { updateFootprint } from '../app.js';
let last=null;
function shell(){ return `
<div class="page"><div class="page-h"><h2>Exposure <span class="tag">what the internet sees</span></h2>
  <p>Look up what's already indexed as exposed on an IP — open ports, detected products, and known CVEs — using <b>Shodan InternetDB</b> (free, no account). Point it at <b>your own</b> public IP to audit your front door. It's a per-IP lookup, so it shows exposure, not a target list.</p></div>
<div class="page-body"><div class="grid2">
  <div class="card2"><h3>Look up an IP or domain</h3>
    <input id="tgt" placeholder="e.g. your-public-ip or example.com" style="width:100%;margin:8px 0"/>
    <div style="display:flex;gap:8px"><button class="ghost" id="mine" style="flex:1">Use my public IP</button><button class="primary" id="go" style="flex:1">Look up</button></div>
    <div class="muted">Best used on systems you own or are authorized to assess. This reads public index data — it does not scan or touch the target.</div>
  </div>
  <div class="card2"><h3>What this teaches</h3><p class="muted">Anything internet-facing gets indexed by exposure engines like Shodan. If a device answers on a port with a banner that reveals old firmware, it's findable — and if it also has default creds, it's trivially abusable. The lesson: close ports you don't need, patch what's exposed, and put admin behind a VPN.</p></div>
</div>
<div id="res"></div>
</div></div>`; }
function mount(root){
  root.innerHTML=shell();
  $('#go').onclick=run;
  $('#tgt').addEventListener('keydown',e=>{ if(e.key==='Enter')run(); });
  $('#mine').onclick=async()=>{ const r=await API('/myip'); if(r.ip){ $('#tgt').value=r.ip; toast('Your public IP: '+r.ip,'ok'); run(); } else toast('Could not detect your public IP','warn'); };
  if(S.ctx&&S.ctx.target){ $('#tgt').value=String(S.ctx.target).replace(/^\w+:\/\//,'').split('/')[0]; S.ctx.target=null; }
}
async function run(){
  const t=$('#tgt').value.trim(); if(!t){ toast('Enter an IP or domain','warn'); return; }
  $('#go').disabled=true; $('#res').innerHTML='<div class="muted" style="padding:8px 4px"><span class="pulse">●</span> Looking up exposure…</div>';
  try{
    const r=await API('/exposure?target='+encodeURIComponent(t)); last=r; $('#go').disabled=false;
    if(!r.ok){ $('#res').innerHTML=`<div class="card2"><p style="color:#eaa0a1">✗ ${escapeHtml(r.error)}</p></div>`; return; }
    const chip=(x,c)=>`<span class="ins-chip" style="${c||''}">${escapeHtml(x)}</span>`;
    let h=`<div class="card2"><div style="display:flex;align-items:center;gap:10px"><h3 style="margin:0;flex:1">${escapeHtml(r.host)} <span class="mono" style="font-size:12px;color:var(--dim)">${escapeHtml(r.ip)}</span></h3>
      <button class="sm primary" id="addG">Add to graph</button></div>`;
    if(r.note) h+=`<p class="muted" style="margin-top:8px;color:var(--ok)">${escapeHtml(r.note)}</p>`;
    h+=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px;margin-top:12px">
      <div><div class="ins-run-t">Open ports (${r.ports.length})</div><div class="ins-chips">${r.ports.map(p=>chip(p)).join('')||'<span class="muted">none</span>'}</div></div>
      <div><div class="ins-run-t">Products (${r.cpes.length})</div><div class="ins-chips">${r.cpes.slice(0,20).map(c=>chip(c.replace('cpe:2.3:','').split(':').slice(0,4).join(' '))).join('')||'<span class="muted">none</span>'}</div></div>
      <div><div class="ins-run-t">Hostnames</div><div class="ins-chips">${(r.hostnames||[]).map(x=>chip(x)).join('')||'<span class="muted">none</span>'}</div></div>
      <div><div class="ins-run-t">Tags</div><div class="ins-chips">${(r.tags||[]).map(x=>chip(x)).join('')||'<span class="muted">none</span>'}</div></div>
    </div>`;
    if(r.vulns.length){
      h+=`<div class="ins-run-t" style="margin-top:14px">Known CVEs (${r.vulns.length})</div>
        <div class="tf-feed" style="height:auto;max-height:260px">${r.vulns.map(v=>`<div class="tf-row" style="grid-template-columns:150px 1fr"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}" target="_blank" rel="noopener" style="color:var(--accent)">${escapeHtml(v)}</a><span class="muted">National Vulnerability Database ↗</span></div>`).join('')}</div>`;
    } else h+=`<p class="muted" style="margin-top:12px">No known CVEs indexed for these services.</p>`;
    h+=`</div>`;
    $('#res').innerHTML=h;
    $('#addG').onclick=addToGraph;
  }catch(e){ $('#go').disabled=false; $('#res').innerHTML='<div class="muted">Lookup failed — is the server running / online?</div>'; }
}
async function addToGraph(){
  if(!S.inv){ toast('Create an investigation first','warn'); return; }
  const r=last; if(!r||!r.ok) return;
  const post=b=>fetch('/api/entities/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
  await post({investigation_id:S.inv,type:'host',value:r.ip,label:r.host+' ('+r.ip+')',metadata:{source:'exposure',tags:(r.tags||[]).join(',')}});
  for(const p of r.ports) await post({investigation_id:S.inv,type:'service',value:r.ip+':'+p,label:'port '+p,metadata:{port:p,source:'exposure'},link_type:'host',link_value:r.ip,relation:'HAS_PORT'});
  for(const v of r.vulns.slice(0,40)) await post({investigation_id:S.inv,type:'vulnerability',value:v,label:v,metadata:{severity:'high',source:'exposure'},link_type:'host',link_value:r.ip,relation:'HAS_VULNERABILITY'});
  toast('Exposure added to graph','ok'); updateFootprint();
}
export default { id:'exposure', label:'Exposure', short:'Exposure', mount, unmount(){} };
