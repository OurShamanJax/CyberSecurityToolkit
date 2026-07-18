// pages/traffic.js — Live Traffic Monitor. Real tshark capture when available,
// clearly-labelled simulated feed otherwise. Play/pause/speed control the DISPLAY
// (buffer + drain), which works for both real and simulated sources.
import { $, toast, S, escapeHtml } from '../core.js';
let ws=null, mode='sim', playing=false, speed=1, seq=0, rows=[], buffer=[], sel=null, ifaces=[];
let drainTimer=null, simTimer=null, capStarted=false;
let lanMap={}, selfIp='', gatewayIp='';
const HOSTS=['192.168.1.14','192.168.1.1','10.0.0.5','93.184.216.34','142.250.72.14','127.0.0.1'];
const PROTO=['TCP','UDP','TLS','HTTP','DNS','ARP'];
const ALERTS=[{k:'Port scan',why:'many SYNs to sequential ports from one host'},{k:'ARP spoofing',why:'gateway IP now maps to a new MAC'},{k:'DNS tunneling',why:'long, high-entropy subdomain lookups'}];
const rnd=a=>a[Math.floor(Math.random()*a.length)];
const PROTONAMES={MDNS:'device discovery (mDNS/Bonjour)',ARP:'finding a device (ARP)',DNS:'name lookup (DNS)',LLMNR:'name lookup (LLMNR)',NBNS:'name lookup (NetBIOS)',TLS:'encrypted web (HTTPS/TLS)',HTTP:'web page (HTTP)',QUIC:'encrypted web (QUIC)',SSDP:'device discovery (UPnP)',DHCP:'getting an IP (DHCP)',DHCPV6:'getting an IP (DHCPv6)',ICMP:'ping / network test',ICMPV6:'IPv6 signalling',IGMP:'multicast group join',NTP:'clock sync (NTP)',TCP:'connection (TCP)',UDP:'datagram (UDP)',SSH:'secure shell (SSH)',STUN:'NAT traversal (STUN)',TFTP:'file transfer (TFTP)'};
const GLOSS={MDNS:'Devices announcing and looking up each other by name on your LAN — normal constant background chatter.',ARP:'A device asking "who has this IP?" to locate another device on the LAN.',DNS:'Turning a website name into an IP address.',SSDP:'A device advertising itself (casting, printers) via UPnP.',TLS:'Encrypted web traffic — you can see who is talking, not what they say.',DHCP:'A device asking the router for an IP address to join the network.',NTP:'A device syncing its clock.'};
function protoInfo(p){ const k=(p||'').split(' ')[0].toUpperCase(); return PROTONAMES[p]||PROTONAMES[k]||(p||'traffic'); }
function annIP(ip){
  if(!ip) return {ip:'?',tag:'',cls:''};
  if(ip.indexOf(':')>=0){ const l=ip.toLowerCase();
    if(l.startsWith('ff0')) return {ip,tag:'IPv6 multicast',cls:'m'};
    if(l.startsWith('fe80')) return {ip,tag:'local IPv6',cls:'l'};
    if(l==='::1') return {ip,tag:'this PC',cls:'self'};
    return {ip,tag:'IPv6',cls:''}; }
  const o=ip.split('.').map(Number);
  if(ip===selfIp||ip==='127.0.0.1') return {ip,tag:'this PC',cls:'self'};
  if(gatewayIp&&ip===gatewayIp) return {ip,tag:'your router',cls:'gw'};
  const h=lanMap[ip];
  if(h){ const nm=h.hostname||(h.vendor&&!/randomized/.test(h.vendor)?h.vendor:''); return {ip,tag:nm?('your '+nm):'your device',cls:'dev'}; }
  if(o[0]>=224&&o[0]<=239) return {ip,tag: ip==='224.0.0.251'?'mDNS multicast':(ip==='239.255.255.250'?'UPnP/SSDP':'multicast'),cls:'m'};
  if(ip==='255.255.255.255'||o[3]===255) return {ip,tag:'broadcast',cls:'b'};
  if(o[0]===10||(o[0]===192&&o[1]===168)||(o[0]===172&&o[1]>=16&&o[1]<=31)) return {ip,tag:'local device',cls:'l'};
  return {ip,tag:'internet',cls:'net'};
}
async function loadLan(){
  try{ const d=await (await fetch('/api/lan/hosts')).json();
    (d.hosts||[]).forEach(h=>{ if(h.ip) lanMap[h.ip]={hostname:h.hostname,vendor:h.vendor,role:h.role}; });
    if(d.gateway)gatewayIp=d.gateway; if(d.self)selfIp=d.self; }catch(e){}
  try{ const l=await (await fetch('/api/lanip')).json(); if(l&&l.ip)selfIp=l.ip; }catch(e){}
  renderFeed();
}

function shell(){ return `
<div class="page"><div class="page-h"><h2>Live Traffic <span class="tag" id="modetag">…</span></h2>
  <p>Realtime traffic with defensive alerting. Uses <b>tshark</b> for real capture when installed with privileges; otherwise a clearly-labelled simulated feed. Play/pause and speed control the display in both modes.</p></div>
<div class="page-body">
  <div class="tf-banner" id="banner">Connecting to capture engine…</div>
  <div class="tf-ctrl">
    <select id="iface" style="min-width:180px;display:none"></select>
    <button class="primary" id="play"><svg class="ic fill" viewBox="0 0 24 24"><path d="M7 5l12 7-12 7z"/></svg><span id="playlbl">Play</span></button>
    <button class="ghost" id="step">Step</button>
    <button class="ghost" id="reset">Reset</button>
    <span class="muted">Display speed <input type="range" id="spd" min="0.1" max="1" step="0.1" value="1" style="width:130px;vertical-align:middle"/> <span id="spdlbl">realtime</span></span>
    <span class="muted" id="bufmeta" style="margin-left:6px"></span>
    <div class="spacer"></div><input id="filt" placeholder="filter: host / protocol" style="width:190px"/>
  </div>
  <div class="tf-wrap">
    <div class="tf-feed" id="feed"></div>
    <div>
      <div class="tf-side" style="margin-bottom:12px"><h4>Packet detail</h4><div class="tf-detail" id="detail">Click a packet to inspect its layers.</div></div>
      <div class="tf-side" style="height:auto;min-height:90px"><h4>Alerts</h4><div id="alerts"><div class="muted">No suspicious activity yet.</div></div></div>
    </div>
  </div>
</div></div>`; }

function makeSim(){ seq++; const src=rnd(HOSTS),dst=rnd(HOSTS.filter(h=>h!==src)),proto=rnd(PROTO),len=40+((Math.random()*1400)|0);
  const al=Math.random()<0.08?rnd(ALERTS):null;
  return {id:seq,t:new Date().toLocaleTimeString().split(' ')[0],src,dst,proto,len,summary:al?al.k:`${proto} seq=${seq}`,alert:al,info:`${proto} ${src}→${dst}`}; }
function realRow(p,alerts){ seq++; const al=(alerts&&alerts[0])||null;
  buffer.push({id:p.num||seq,t:p.t||'',src:p.src||'',dst:p.dst||'',proto:p.proto||'',len:+p.len||0,summary:p.info||p.proto,alert:al,info:p.info||''});
  if(buffer.length>2000)buffer.shift(); }
function pushRow(r){ rows.push(r); if(rows.length>500)rows.shift(); renderFeed(); if(r.alert)renderAlert(r);
  const bm=$('#bufmeta'); if(bm)bm.textContent=buffer.length?('· '+buffer.length+' queued'):''; }
function renderFeed(){ const feed=$('#feed'); if(!feed)return;
  const f=(($('#filt')&&$('#filt').value)||'').toLowerCase();
  const vis=rows.filter(r=>!f||[r.src,r.dst,r.proto,r.summary].join(' ').toLowerCase().includes(f));
  feed.innerHTML=vis.slice(-220).map(r=>{ const s=annIP(r.src),d=annIP(r.dst);
    const end=a=>`${a.ip}${a.tag?` <em class="iptag ${a.cls}">${a.tag}</em>`:''}`;
    return `<div class="tf-row${r.alert?' alert':''}${sel===r.id?' sel':''}" data-id="${r.id}"><span class="t">${r.t}</span><span class="mid"><span class="p" title="${protoInfo(r.proto)}">${r.proto||'?'}</span> ${end(s)} <span class="arr">→</span> ${end(d)}</span><span>${r.len}B</span><span>#${r.id}</span></div>`; }).join('');
  feed.scrollTop=feed.scrollHeight;
  feed.querySelectorAll('.tf-row').forEach(el=>el.onclick=()=>select(el.dataset.id)); }
function renderAlert(r){ const a=$('#alerts'); if(!a)return; if(a.querySelector('.muted'))a.innerHTML='';
  const d=document.createElement('div'); d.className='tf-alert';
  d.innerHTML=`<b>${r.alert.k}</b> — ${r.alert.why}<br><span class="muted">#${r.id} · ${r.src||''}</span> <button class="sm ghost" style="padding:1px 7px;font-size:10px">＋ graph</button>`;
  d.querySelector('button').onclick=()=>addAlert(r);
  a.prepend(d); while(a.children.length>7)a.lastChild.remove(); }
function addAlert(r){ if(!S.inv){ toast('Create an investigation first','warn'); return; }
  fetch('/api/entities/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({investigation_id:S.inv,type:'alert',value:r.alert.k+' #'+r.id,label:r.alert.k,metadata:{severity:'medium',why:r.alert.why,src:r.src,source:'traffic'},link_type:'ip',link_value:r.src||''})}).then(()=>toast('Alert added to graph','ok')); }
function select(id){ sel=id; const r=rows.find(x=>String(x.id)===String(id)); if(!r)return; renderFeed();
  const s=annIP(r.src),d=annIP(r.dst),p=protoInfo(r.proto),k=(r.proto||'').split(' ')[0].toUpperCase();
  const from=s.tag||r.src||'?', to=d.tag||r.dst||'?', gl=GLOSS[k]?(' '+GLOSS[k]):'';
  $('#detail').innerHTML=`<div style="font-size:13px;line-height:1.55;margin-bottom:9px"><b>${from}</b> → <b>${to}</b><br><span style="color:var(--accent)">${p}</span>.${gl}</div>`+
    `<div class="muted" style="font-size:11.5px;line-height:1.6">frame #${r.id} · ${r.t} · ${r.len} bytes<br>${r.src||'?'} → ${r.dst||'?'}<br>${escapeHtml(r.info||r.proto||'')}</div>`+
    (r.alert?`<div style="color:#eaa0a1;margin-top:8px">⚠ ${escapeHtml(r.alert.k)}: ${escapeHtml(r.alert.why)}</div>`:''); }

// ── display control (works for real + simulated) ──
function startDrain(){ clearInterval(drainTimer); drainTimer=null; if(!playing)return;
  drainTimer=setInterval(()=>{ if(!playing||!buffer.length)return;
    const per = speed>=1 ? Math.min(buffer.length,30) : Math.max(1, Math.ceil(speed*6));
    for(let i=0;i<per && buffer.length;i++) pushRow(buffer.shift());
  }, 120); }
function startSim(){ clearInterval(simTimer); simTimer=null; if(mode!=='sim'||!playing)return;
  simTimer=setInterval(()=>{ if(playing){ buffer.push(makeSim()); if(buffer.length>1500)buffer.shift(); } }, 220); }
function setPlaying(on){ playing=on; $('#playlbl').textContent=on?'Pause':'Play';
  if(mode==='real' && on && !capStarted && ws && ws.readyState===1){ ws.send(JSON.stringify({action:'start',iface:$('#iface').value})); capStarted=true; }
  startSim(); startDrain(); }

function mount(root){
  root.innerHTML=shell(); rows=[]; buffer=[]; sel=null; seq=0; mode='sim'; playing=false; capStarted=false;
  if(S.ctx&&S.ctx.target){ $('#filt').value=String(S.ctx.target).replace(/^\w+:\/\//,'').split('/')[0]; S.ctx.target=null; }
  $('#filt').oninput=renderFeed;
  loadLan();
  $('#play').onclick=()=>setPlaying(!playing);
  $('#step').onclick=()=>{ if(buffer.length)pushRow(buffer.shift()); else if(mode==='sim')pushRow(makeSim()); };
  $('#reset').onclick=()=>{ playing=false; $('#playlbl').textContent='Play'; clearInterval(simTimer); clearInterval(drainTimer);
    if(mode==='real'&&ws&&ws.readyState===1){ try{ws.send(JSON.stringify({action:'stop'}));}catch(e){} } capStarted=false;
    buffer=[]; rows=[]; sel=null; renderFeed(); $('#alerts').innerHTML='<div class="muted">No suspicious activity yet.</div>'; $('#detail').textContent='Click a packet to inspect its layers.'; $('#bufmeta').textContent=''; };
  $('#spd').oninput=e=>{ speed=+e.target.value; $('#spdlbl').textContent=speed>=1?'realtime':(speed*100|0)+'%'; startDrain(); };
  connectCap();
}
const WGCMD='winget install WiresharkFoundation.Wireshark';
function connectCap(){
  try{
    ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/capture');
    ws.onmessage=e=>{ const m=JSON.parse(e.data);
      if(m.type==='caps'){ if(m.available){ mode='real'; ifaces=m.interfaces||[];
          $('#modetag').textContent='live capture'; $('#modetag').className='tag';
          $('#banner').innerHTML='● <b>Live capture</b> via tshark. Pick an interface and press Play. Needs capture privileges (admin/root · Npcap on Windows). Play/Pause and speed control the display; capture keeps running underneath.';
          $('#iface').style.display=''; $('#iface').innerHTML=ifaces.map(n=>`<option value="${n.id||n}">${(n.label||n)}</option>`).join('')||'<option value="1">default</option>';
        } else {
          mode='sim'; $('#modetag').textContent='simulated preview'; $('#modetag').className='tag soon';
          $('#banner').innerHTML='▶ <b>tshark not detected</b> — simulated preview shown. Real capture needs Wireshark (bundles tshark + Npcap). '+
            '<div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap"><span class="kbd">'+WGCMD+'</span>'+
            '<button class="sm ghost" id="copycmd">Copy</button><button class="sm ghost" id="recheck">Re-check</button>'+
            '<span class="muted">run it, then relaunch R.O.D.E as administrator</span></div>';
          const cc=$('#copycmd'); if(cc)cc.onclick=()=>{ try{navigator.clipboard.writeText(WGCMD);}catch(e){} toast('Command copied — run it in a terminal'); };
          const rc=$('#recheck'); if(rc)rc.onclick=()=>{ try{ws&&ws.close();}catch(e){} $('#banner').textContent='Re-checking…'; setTimeout(connectCap,150); };
        } }
      else if(m.type==='pkt'){ realRow(m.pkt,m.alerts); }
      else if(m.type==='error'){ $('#banner').innerHTML='⚠ '+m.message; toast(m.message,'warn'); }
    };
    ws.onerror=()=>{ $('#modetag').textContent='simulated preview'; $('#modetag').className='tag soon'; $('#banner').innerHTML='▶ Simulated preview (capture engine unreachable).'; };
  }catch(e){ $('#banner').innerHTML='▶ Simulated preview.'; }
}
function unmount(){ clearInterval(simTimer); clearInterval(drainTimer); simTimer=drainTimer=null; playing=false;
  if(ws){ try{ws.close();}catch(e){} ws=null; } }
export default { id:'traffic', label:'Live Traffic', short:'Traffic', mount, unmount };
