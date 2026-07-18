// pages/vpn.js — real WireGuard config generator
import { $, escapeHtml, toast, pageHead } from '../core.js';
function shell(){ return `
<div class="page">${pageHead({
  title:'VPN', tag:'WireGuard generator',
  intro:"Generate a real, ready-to-import <b>WireGuard</b> configuration. Free, self-hosted, no accounts — R.O.D.E doesn't invent crypto, it hands you correct configs for WireGuard's audited implementation.",
  help:"A VPN routes your traffic through a <b>server you control</b>. To actually run one you need: <b>1)</b> a machine with a public address — a cheap VPS, or a home box with a forwarded port; <b>2)</b> WireGuard installed on it; <b>3)</b> the config below. If you're just learning, generate a config and read the annotations — the keys are real and generated locally in your browser session; nothing leaves your machine."
})}
<div class="page-body">
  <div class="card2"><h3>1 · Tunnel settings</h3>
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
    <div style="flex:2;min-width:180px"><label class="muted">Server endpoint (your public host/IP)</label><input id="ep" value="vpn.example.com" style="width:100%;margin-top:4px"/></div>
    <div style="width:90px"><label class="muted">Port</label><input id="port" type="number" value="51820" style="width:100%;margin-top:4px"/></div>
    <div style="width:110px"><label class="muted">Subnet /24</label><input id="sub" value="10.8.0" style="width:100%;margin-top:4px"/></div>
    <div style="width:120px"><label class="muted">DNS</label><input id="dns" value="1.1.1.1" style="width:100%;margin-top:4px"/></div>
    <div style="width:80px"><label class="muted">Peers</label><input id="peers" type="number" value="1" min="1" max="30" style="width:100%;margin-top:4px"/></div>
    <button class="primary" id="gen">Generate</button>
  </div></div>
  <div id="out"></div>
  <div class="card2"><h3 style="color:var(--ok)">3 · Deploy it</h3><p class="muted"><b>Server:</b> install WireGuard on your public machine, save the <b>wg0.conf</b> to <span class="kbd">/etc/wireguard/wg0.conf</span>, then <span class="kbd">wg-quick up wg0</span>. <b>Devices:</b> install the WireGuard app and import each <b>peer</b> config (it reads the .conf file). Set <span class="kbd">Endpoint</span> to your server's real public IP/hostname before deploying.</p></div>
</div></div>`; }
function confBlock(title, text, fname){
  return `<div class="card2"><div style="display:flex;align-items:center;gap:10px"><h3 style="margin:0;flex:1">${title}</h3>
    <button class="sm ghost" data-dl="${escapeHtml(fname)}">Download ${escapeHtml(fname)}</button></div>
    <textarea readonly style="width:100%;height:190px;margin-top:8px;font-family:var(--mono);font-size:12px;background:var(--bg);color:#c4ccd6;border:1px solid var(--line);border-radius:8px;padding:10px">${escapeHtml(text)}</textarea></div>`;
}
function mount(root){ root.innerHTML=shell(); $('#gen').onclick=gen; }
async function gen(){
  const body={ endpoint:$('#ep').value.trim(), port:+$('#port').value||51820, subnet:$('#sub').value.trim(), dns:$('#dns').value.trim(), peers:+$('#peers').value||1 };
  $('#gen').disabled=true;
  try{
    const r=await fetch('/api/vpn/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(x=>x.json());
    $('#gen').disabled=false;
    if(!r.ok){ $('#out').innerHTML=`<div class="card2"><p style="color:#eaa0a1">✗ ${escapeHtml(r.error)}</p></div>`; return; }
    const files={};
    let h=confBlock('Server — wg0.conf', r.server.conf, 'wg0.conf'); files['wg0.conf']=r.server.conf;
    r.peers.forEach(p=>{ h+=confBlock(`Peer — ${p.name} (${p.ip})`, p.conf, p.name+'.conf'); files[p.name+'.conf']=p.conf; });
    $('#out').innerHTML='<div class="card2" style="padding:8px 14px"><b>2 · Your configs</b> — download and keep the private keys safe.</div>'+h;
    $('#out').querySelectorAll('[data-dl]').forEach(b=>b.onclick=()=>{ const n=b.dataset.dl; const blob=new Blob([files[n]],{type:'text/plain'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=n; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),2000); });
    toast('WireGuard config generated','ok');
  }catch(e){ $('#gen').disabled=false; $('#out').innerHTML='<div class="card2"><p class="muted">Request failed.</p></div>'; }
}
export default { id:'vpn', label:'VPN', short:'VPN', mount, unmount(){} };
