// pages/settings.js — real preferences
import { $, API, toast, pageHead } from '../core.js';
const ACCENTS=[['#4bb8d0','Teal'],['#6ea8fe','Blue'],['#a892e0','Violet'],['#5fbf8a','Green'],['#e0a24b','Amber'],['#e0686a','Red']];
export function applySettings(){
  if(localStorage.getItem('rode.compact')==='1') document.body.classList.add('compact');
  const acc=localStorage.getItem('rode.accent'); if(acc) document.documentElement.style.setProperty('--accent',acc);
}
function shell(){ return `
<div class="page">${pageHead({
  title:'Settings',
  intro:'How R.O.D.E behaves and feels. Changes apply immediately and persist on this machine.'
})}
<div class="page-body"><div class="grid2">
  <div class="card2"><h3>Appearance</h3>
    <label class="toggle-row"><input type="checkbox" id="anim"/> Enable animations (typewriter console, node fade-in)</label>
    <label class="toggle-row"><input type="checkbox" id="compact"/> Compact density (tighter spacing)</label>
    <div style="font-size:12px;color:var(--dim);margin-top:12px">Accent color</div>
    <div class="sw" id="sw">${ACCENTS.map(a=>`<b data-c="${a[0]}" style="background:${a[0]}" title="${a[1]}"></b>`).join('')}</div>
  </div>
  <div class="card2"><h3>Tools & capabilities</h3>
    <p class="muted">What's available on this machine right now.</p>
    <div id="caps"><div class="muted">Checking…</div></div>
    <button class="sm ghost" id="recheck" style="margin-top:10px">Re-check</button>
  </div>
  <div class="card2"><h3>Storage</h3>
    <p class="muted">Tool runs save their raw output text to <code>data/output</code>. Clearing it frees space and doesn't touch your investigations (those live in the database).</p>
    <div id="outInfo" class="muted" style="font-size:12px;margin:6px 0 10px">checking…</div>
    <button class="sm danger" id="clearOut">Clear tool output</button>
  </div>
  <div class="card2"><h3>Scope policy</h3><p class="muted">v4 scope is <b>advisory</b> — nothing is blocked; off-scope targets get a one-time heads-up. Only test what you own or are authorized to test.</p></div>
  <div class="card2"><h3>About</h3><p class="muted">R.O.D.E v4 — a free/open-source security multitool. Everything runs locally or in Docker. No accounts, no API keys, no cloud.</p></div>
</div></div></div>`; }
async function loadCaps(){
  const el=$('#caps'); el.innerHTML='<div class="muted">Checking…</div>';
  try{ const c=await API('/capabilities');
    el.innerHTML=`<div class="cap">Docker <span class="pill2 ${c.docker?'yes':'no'}">${c.docker?'available':'not running'}</span></div>
      <div class="cap">tshark (live capture) <span class="pill2 ${c.tshark?'yes':'no'}">${c.tshark?'available':'not installed'}</span></div>`;
  }catch(e){ el.innerHTML='<div class="muted">Could not check.</div>'; }
}
function mount(root){
  root.innerHTML=shell();
  const anim=$('#anim'); anim.checked=localStorage.getItem('rode.anim')!=='0';
  anim.onchange=()=>{ localStorage.setItem('rode.anim',anim.checked?'1':'0'); toast('Animations '+(anim.checked?'on':'off')); };
  const comp=$('#compact'); comp.checked=localStorage.getItem('rode.compact')==='1';
  comp.onchange=()=>{ localStorage.setItem('rode.compact',comp.checked?'1':'0'); document.body.classList.toggle('compact',comp.checked); };
  const cur=localStorage.getItem('rode.accent')||'#4bb8d0';
  $('#sw').querySelectorAll('b').forEach(b=>{ b.classList.toggle('on',b.dataset.c===cur);
    b.onclick=()=>{ localStorage.setItem('rode.accent',b.dataset.c); document.documentElement.style.setProperty('--accent',b.dataset.c); $('#sw').querySelectorAll('b').forEach(x=>x.classList.toggle('on',x===b)); }; });
  $('#recheck').onclick=loadCaps; loadCaps();
  loadOutInfo();
  $('#clearOut').onclick=async ()=>{
    if(!confirm('Delete all saved tool-run output files in data/output? Your investigations are kept.')) return;
    try{ const r=await (await fetch('/api/data/output/clear',{method:'POST'})).json();
      toast('Cleared '+(r.removed||0)+' file(s)','ok'); loadOutInfo(); }
    catch(e){ toast('Could not clear output','warn'); }
  };
}
async function loadOutInfo(){
  const el=$('#outInfo'); if(!el)return;
  try{ const d=await API('/data/output/info'); const mb=(d.bytes/1048576);
    el.textContent=d.count?(d.count+' file(s) · '+(mb<0.1?(d.bytes/1024).toFixed(0)+' KB':mb.toFixed(1)+' MB')):'empty — nothing saved yet';
  }catch(e){ el.textContent='—'; }
}
export default { id:'settings', label:'Settings', short:'Settings', mount, unmount(){} };
