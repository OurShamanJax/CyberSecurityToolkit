// pages/credentials.js — login auditor (for your OWN systems)
import { $, escapeHtml, toast, S, pageHead } from '../core.js';
function shell(){ return `
<div class="page">${pageHead({
  title:'Credentials', tag:'login auditor',
  intro:"Test login security on systems you <b>own</b> — like your local OWASP Juice Shop. Tries a password list against a login endpoint and reports what falls. Runs locally, no accounts. Throttled and capped.",
  help:"Only test accounts and systems you own or are explicitly authorized to test. The lesson here is defensive: rate-limiting, account lockout, MFA, and slow salted password hashing are what stop this kind of attack. If a common password falls in the first few tries, that's exactly what a real attacker would find too."
})}
<div class="page-body"><div class="grid2">
  <div class="card2"><h3>Target</h3>
    <div style="display:flex;gap:8px;margin-bottom:8px"><button class="sm ghost" id="preset">↺ Juice Shop preset</button></div>
    <label class="muted">Base URL</label><input id="base" value="http://localhost:3000" style="width:100%;margin:4px 0 8px"/>
    <label class="muted">Login path</label><input id="path" value="/rest/user/login" style="width:100%;margin:4px 0 8px"/>
    <label class="muted">Username / email</label><input id="user" value="admin@juice-sh.op" style="width:100%;margin:4px 0 8px"/>
    <div style="display:flex;gap:8px">
      <div style="flex:1"><label class="muted">user field</label><input id="uf" value="email" style="width:100%;margin-top:4px"/></div>
      <div style="flex:1"><label class="muted">pass field</label><input id="pf" value="password" style="width:100%;margin-top:4px"/></div>
      <div style="flex:1"><label class="muted">body</label><select id="mode" style="width:100%;margin-top:4px"><option value="json">JSON</option><option value="form">form</option></select></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:10px;align-items:flex-end">
      <div style="flex:1"><label class="muted">wordlist</label><select id="wl" style="width:100%;margin-top:4px"><option>passwords-top.txt</option></select></div>
      <div style="width:90px"><label class="muted">max tries</label><input id="max" type="number" value="300" style="width:100%;margin-top:4px"/></div>
      <button class="primary" id="go"><svg class="ic fill" viewBox="0 0 24 24"><path d="M7 5l12 7-12 7z"/></svg>Audit</button>
    </div>
  </div>
  <div class="card2"><h3>Result</h3><div id="res"><div class="muted">Run an audit to see attempts and any cracked credential.</div></div></div>
</div>
<div class="card2"><h3>Password breach check <span class="tag">k-anonymity</span></h3>
  <p class="muted">Check if a password appears in known breaches. The password <b>never leaves your machine</b> — only the first 5 characters of its SHA-1 hash are sent (Have I Been Pwned), and the match is done locally. Safe to test your real passwords.</p>
  <div style="display:flex;gap:8px;margin-top:6px"><input id="pw" type="password" placeholder="password to check" style="flex:1"/><button class="sm" id="pwgo">Check</button></div>
  <div id="pwres" class="muted" style="margin-top:8px;font-size:12.5px"></div>
</div>
</div></div>`; }
function mount(root){
  root.innerHTML=shell();
  if(S.ctx&&S.ctx.target){ try{ $('#base').value=new URL(S.ctx.target).origin; }catch(e){ $('#base').value=S.ctx.target; } S.ctx.target=null; toast('Target loaded from graph','ok'); }
  $('#preset').onclick=()=>{ $('#base').value='http://localhost:3000'; $('#path').value='/rest/user/login'; $('#user').value='admin@juice-sh.op'; $('#uf').value='email'; $('#pf').value='password'; $('#mode').value='json'; };
  const pwgo=$('#pwgo'); if(pwgo){ const chk=async()=>{ const pw=$('#pw').value; if(!pw){ toast('Enter a password','warn'); return; }
    $('#pwres').textContent='checking (k-anonymity)…';
    try{ const r=await (await fetch('/api/pwned',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:pw})})).json();
      if(!r.ok){ $('#pwres').textContent='check failed: '+escapeHtml(r.error||''); return; }
      if(r.pwned) $('#pwres').innerHTML='<span style="color:var(--danger)">⚠ found in breaches '+r.count.toLocaleString()+' time(s)</span> — do not use this password anywhere.';
      else $('#pwres').innerHTML='<span style="color:var(--ok)">✓ not found</span> in the breach corpus (still use a long, unique password).';
    }catch(e){ $('#pwres').textContent='check failed'; }
    $('#pw').value=''; };
    pwgo.onclick=chk; $('#pw').onkeydown=e=>{ if(e.key==='Enter')chk(); }; }
  $('#go').onclick=run;
}
async function run(){
  const body={ base_url:$('#base').value.trim(), login_path:$('#path').value.trim(), username:$('#user').value.trim(),
    user_field:$('#uf').value.trim(), pass_field:$('#pf').value.trim(), mode:$('#mode').value,
    wordlist:$('#wl').value, max_tries:+$('#max').value||300 };
  if(!body.base_url||!body.username){ toast('Target URL and username required','warn'); return; }
  $('#go').disabled=true; $('#go').textContent='Auditing…'; $('#res').innerHTML='<div class="muted"><span class="pulse">●</span> Auditing… trying each password against the login endpoint. This is instant when the password is early in the list.</div>';
  try{
    const r=await fetch('/api/credaudit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(x=>x.json());
    $('#go').disabled=false; $('#go').innerHTML='<svg class="ic fill" viewBox="0 0 24 24"><path d="M7 5l12 7-12 7z"/></svg>Audit';
    if(!r.ok){ $('#res').innerHTML=`<div class="tf-banner" style="color:#eaa0a1;border-color:rgba(224,104,106,.4);background:rgba(224,104,106,.1)">✗ ${escapeHtml(r.error||'failed')}</div>`; return; }
    let h='';
    if(r.found && S.inv){ try{ fetch('/api/entities/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({investigation_id:S.inv,type:'credential',value:body.username+':'+r.found.password,label:body.username+' : '+r.found.password,metadata:{severity:'high',source:'credaudit'},link_type:'url',link_value:body.base_url,relation:'HAS_CREDENTIAL'})}).then(()=>toast('Credential added to graph','ok')); }catch(e){} }
    if(r.found){ h+=`<div style="background:rgba(95,191,138,.12);border:1px solid rgba(95,191,138,.4);border-radius:9px;padding:12px 14px;margin-bottom:10px">
      <div style="color:var(--ok);font-weight:700;margin-bottom:4px">✓ Credential cracked</div>
      <div class="mono">${escapeHtml(r.found.username)} : <b>${escapeHtml(r.found.password)}</b></div></div>`; toast('Password cracked!','ok'); }
    else h+=`<div class="muted" style="margin-bottom:10px">No password in the list matched (${r.tried} tried, ${r.elapsed}s). That's a good sign for the defender.</div>`;
    h+=`<div class="muted" style="margin-bottom:6px">Attempts (${r.tried} · ${r.elapsed}s)</div>`;
    h+=`<div class="tf-feed" style="height:220px">${(r.log||[]).map(l=>`<div class="tf-row" style="grid-template-columns:1fr 60px"><span class="mono">${escapeHtml(l.pw)}</span><span style="color:${l.ok?'var(--ok)':l.code==='ERR'?'var(--danger)':'var(--dim)'}">${l.code}${l.ok?' ✓':''}</span></div>`).join('')}</div>`;
    $('#res').innerHTML=h;
  }catch(e){ $('#go').disabled=false; $('#go').textContent='Audit'; $('#res').innerHTML='<div class="muted">Request failed — is the server running?</div>'; }
}
export default { id:'credentials', label:'Credentials', short:'Creds', mount, unmount(){} };
