// pages/wireless.js — AP discovery with per-router action menus
import { $, escapeHtml, toast, S } from '../core.js';
import { sendTo } from '../app.js';
let connected=null;
function shell(){ return `
<div class="page"><div class="page-h"><h2>Wireless <span class="tag">AP scan</span></h2>
  <p>Discover the access points your adapter can see — SSID, BSSID, signal, channel, encryption. <b>Click a network</b> for options: analyze your router, check its admin panel, or (with the right hardware) go deeper. Read-only scan uses <span class="kbd">netsh</span>/<span class="kbd">nmcli</span> — no special adapter.</p></div>
<div class="page-body">
  <div class="card2"><div style="display:flex;gap:10px;align-items:center">
    <button class="primary" id="scan"><svg class="ic" viewBox="0 0 24 24"><path d="M5 12a10 10 0 0 1 14 0M8 15a6 6 0 0 1 8 0"/><circle cx="12" cy="18.5" r="1.3"/></svg>Scan for access points</button>
    <button class="ghost" id="router">Analyze my router</button>
    <div class="spacer"></div><span class="muted" id="scanmeta"></span>
  </div></div>
  <div id="aps"></div>
  <div class="card2"><h3 style="color:var(--warnc)">Going deeper needs hardware</h3><p class="muted">Packet capture, deauth, and WPA-handshake work need a WiFi adapter with <b>monitor mode + injection</b>, usually on Linux (or a Linux VM with USB passthrough). This read-only scan works on any adapter. Only test networks you own or are authorized to test.</p></div>
</div></div>`; }
function mount(root){ root.innerHTML=shell(); $('#scan').onclick=scan; $('#router').onclick=analyzeRouter; document.addEventListener('click', closePop); }
function unmount(){ document.removeEventListener('click', closePop); closePop(); }
function closePop(e){ const p=$('#wpop'); if(p && (!e || !p.contains(e.target))) p.remove(); }

async function scan(){
  $('#scan').disabled=true; $('#aps').innerHTML='<div class="muted" style="padding:0 4px 12px">Scanning…</div>';
  try{
    const [r,c]=await Promise.all([fetch('/api/wifi/scan').then(x=>x.json()), fetch('/api/wifi/connected').then(x=>x.json()).catch(()=>({}))]);
    connected=c||{}; $('#scan').disabled=false; $('#scanmeta').textContent=(r.os?('on '+r.os):'')+(connected.ssid?(' · connected: '+connected.ssid):'');
    if(!r.available){ $('#aps').innerHTML=`<div class="card2"><p class="muted">${escapeHtml(r.reason||'WiFi scan unavailable here.')}</p></div>`; return; }
    if(!r.aps.length){ $('#aps').innerHTML='<div class="card2"><p class="muted">No access points visible. Make sure WiFi is on.</p></div>'; return; }
    $('#aps').innerHTML=`<div class="card2"><h3>${r.aps.length} access point(s) <span class="hh" style="font-weight:400;color:var(--dim);font-size:12px">· click one for actions</span></h3>
      <div class="tf-feed" style="height:auto;max-height:440px">
      <div class="tf-row" style="grid-template-columns:1fr 150px 62px 44px 120px;color:var(--dim)"><span>SSID</span><span>BSSID</span><span>Signal</span><span>Ch</span><span>Security</span></div>
      ${r.aps.map((a,i)=>{ const mine=connected.bssid && a.bssid && a.bssid.toLowerCase()===connected.bssid.toLowerCase();
        return `<div class="tf-row" data-i="${i}" style="grid-template-columns:1fr 150px 62px 44px 120px;cursor:pointer">
        <span>${escapeHtml(a.ssid||'(hidden)')}${mine?' <span class="tag" style="margin-left:4px;padding:0 6px">yours</span>':''}</span>
        <span class="mono">${escapeHtml(a.bssid||'—')}</span><span>${escapeHtml(a.signal||'—')}</span><span>${escapeHtml(a.channel||'—')}</span><span>${escapeHtml(a.auth||'—')}</span></div>`; }).join('')}</div></div>`;
    const aps=r.aps;
    $('#aps').querySelectorAll('.tf-row[data-i]').forEach(el=>el.onclick=e=>{ e.stopPropagation(); menu(aps[+el.dataset.i], el); });
    toast(r.aps.length+' AP(s) found','ok');
  }catch(e){ $('#scan').disabled=false; $('#aps').innerHTML='<div class="card2"><p class="muted">Scan request failed.</p></div>'; }
}
function menu(ap, el){
  closePop();
  const mine=connected.bssid && ap.bssid && ap.bssid.toLowerCase()===connected.bssid.toLowerCase();
  const gw=connected.gateway;
  const p=document.createElement('div'); p.className='pop'; p.id='wpop';
  const head=document.createElement('div'); head.className='t'; head.textContent=(ap.ssid||'(hidden)')+' · '+(ap.bssid||''); p.appendChild(head);
  const mk=(label,fn,cls)=>{ const b=document.createElement('button'); if(cls)b.className=cls; b.textContent=label; b.onclick=()=>{ closePop(); fn(); }; p.appendChild(b); };
  if(mine && gw){
    mk('🔍  Analyze router (Nmap '+gw+')', ()=>sendTo('investigation',{tool:'nmap',target:gw}));
    mk('🔑  Check admin panel (HTTPx)', ()=>sendTo('investigation',{tool:'httpx',target:'http://'+gw}));
    mk('📋  Copy gateway IP', ()=>{ navigator.clipboard&&navigator.clipboard.writeText(gw); toast('Copied '+gw); });
  } else {
    const note=document.createElement('div'); note.className='divider'; note.textContent="Connect to this network to analyze its router"; p.appendChild(note);
  }
  mk('➕  Add to graph', ()=>{ if(!S.inv){ toast('Create an investigation first','warn'); return; }
    fetch('/api/entities/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({investigation_id:S.inv,type:'access_point',value:ap.bssid||ap.ssid||'ap',label:ap.ssid||'(hidden)',metadata:{signal:ap.signal,channel:ap.channel,auth:ap.auth,source:'wifi'}})}).then(()=>toast('AP added to graph','ok')); });
  mk('📋  Copy BSSID', ()=>{ navigator.clipboard&&navigator.clipboard.writeText(ap.bssid||''); toast('BSSID copied'); });
  const dv=document.createElement('div'); dv.className='divider'; dv.textContent='Deeper (needs monitor-mode adapter)'; p.appendChild(dv);
  mk('📡  Capture WPA handshake', ()=>toast('Needs a monitor-mode WiFi adapter on Linux — see the note below','warn'));
  mk('⚡  Deauth test (own network)', ()=>toast('Needs a monitor-mode/injection adapter — gated for authorized own-network testing','warn'));
  document.body.appendChild(p);
  const r=el.getBoundingClientRect();
  p.style.left=Math.min(r.left+40, window.innerWidth-p.offsetWidth-12)+'px';
  p.style.top=Math.min(r.bottom+4, window.innerHeight-p.offsetHeight-12)+'px';
}
async function analyzeRouter(){
  try{ const c=await fetch('/api/wifi/connected').then(x=>x.json()); connected=c;
    if(!c.gateway){ toast('Could not detect your gateway','warn'); return; }
    toast('Router '+c.gateway+' → Nmap','ok'); sendTo('investigation',{tool:'nmap',target:c.gateway});
  }catch(e){ toast('Gateway lookup failed','warn'); }
}
export default { id:'wireless', label:'Wireless', short:'WiFi', mount, unmount };
