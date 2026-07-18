// core.js — shared state, helpers, API + WebSocket tool runner, toasts, typewriter
export const $  = (s,r=document)=>r.querySelector(s);
export const $$ = (s,r=document)=>[...r.querySelectorAll(s)];
export const API = p => fetch('/api'+p).then(r=>r.json());
export const escapeHtml = s => String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

// Shared page header — one template for every tool page.
// { title, tag?, tagId?(dynamic tag span id), intro?, actions?(html for right side), help?(collapsible "How this works") }
export function pageHead({title, tag='', tagId='', intro='', actions='', help=''}){
  return `<div class="page-h">
    <div class="ph-top">
      <h2>${title}${(tag||tagId)?` <span class="tag"${tagId?` id="${tagId}"`:''}>${tag}</span>`:''}</h2>
      ${actions?`<div class="ph-actions">${actions}</div>`:''}
    </div>
    ${intro?`<p>${intro}</p>`:''}
    ${help?`<details class="ph-help"><summary>How this works · when to use it</summary><div class="ph-help-body">${help}</div></details>`:''}
  </div>`;
}

export const NOISE = ["silent","whisper","moderate","loud","aggressive"];
export const NM = {
  silent:{c:"var(--silent)",t:"Ghost",d:"no packets touch the target — undetectable"},
  whisper:{c:"var(--whisper)",t:"Whisper",d:"a few requests, blends into normal browsing"},
  moderate:{c:"var(--moderate)",t:"Talking",d:"noticeable scanning; an admin may spot it"},
  loud:{c:"var(--loud)",t:"Shouting",d:"heavy traffic; trips IDS / WAF alarms"},
  aggressive:{c:"var(--aggressive)",t:"Siren",d:"very high volume; expect to be blocked"},
};
export const PH = {
  username:'username  —  e.g. johndoe', url:'URL  —  e.g. http://localhost:3000',
  domain:'domain  —  e.g. example.com', ip:'IP address  —  e.g. 192.168.1.10',
  host:'host / IP  —  e.g. 192.168.1.10', software:'software + version  —  e.g. Apache 2.4.41',
  hash:'hash  —  e.g. 5f4dcc3b5aa765d61d8327deb882cf99', file:'log file in workspace/  —  e.g. access.log',
  path:'file or folder path  —  e.g. /path/to/app.exe',
};
const css = k => getComputedStyle(document.body).getPropertyValue('--'+k).trim();
export const COLOR = {ip:css('ip'),host:css('ip'),service:css('service'),url:css('url'),domain:css('domain'),
  vulnerability:css('vuln'),email:css('email'),username:css('username'),technology:css('technology'),
  target:css('target'),software:css('email'),capability:css('capability'),secret:css('secret'),
  file:css('file'),category:css('group'),alert:css('alert'),credential:css('credential'),access_point:css('accesspoint'),exploit:css('exploit')};

// shared app state
export const S = { inv:null, scope:[], mode:'infra', tools:[], ctx:{target:null}, _ws:null, runId:null, _cb:null, _lastReq:null };

export const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
export function animOn(){ try{ return localStorage.getItem('rode.anim')!=='0' && !reduceMotion(); }catch(e){ return !reduceMotion(); } }

// ── toasts ───────────────────────────────────────────────
export function toast(msg, kind=''){
  const t=document.createElement('div'); t.className='toast'+(kind?' '+kind:''); t.textContent=msg;
  $('#toasts').appendChild(t);
  setTimeout(()=>{t.style.transition='opacity .3s';t.style.opacity='0';setTimeout(()=>t.remove(),300);}, 3600);
}

// ── typewriter console writer ────────────────────────────
// makeTyper(el) returns write(text, cls). Types text out with a light cadence;
// if the queue backs up (fast tools) it flushes instantly so it never lags.
export function makeTyper(el){
  const q=[]; let running=false; let animate=animOn();
  function line(text,cls){ const d=document.createElement('div'); if(cls)d.className=cls; el.appendChild(d); return d; }
  function drain(){
    if(!q.length){ running=false; return; }
    running=true;
    const job=q.shift();
    if(!animate || q.length>6 || job.text.length>240){ // flush when backed up / long
      const d=line(job.text,job.cls); d.textContent=job.text; el.scrollTop=el.scrollHeight; return drain();
    }
    const d=line(job.text,job.cls); d.classList.add('caret'); let i=0;
    const step=Math.max(1, Math.ceil(job.text.length/40));
    const iv=setInterval(()=>{
      i+=step; d.textContent=job.text.slice(0,i); el.scrollTop=el.scrollHeight;
      if(i>=job.text.length){ clearInterval(iv); d.textContent=job.text; d.classList.remove('caret'); drain(); }
    }, 12);
  }
  const write=(text,cls='')=>{ q.push({text:String(text),cls}); if(!running)drain(); };
  write.instant=()=>{ animate=false; }; write.clear=()=>{ q.length=0; el.innerHTML=''; };
  write.setAnimate=v=>{ animate=v&&!reduceMotion(); };
  return write;
}

// ── WebSocket tool runner (shared across pages) ──────────
function connect(){
  return new Promise((res,rej)=>{
    if(S._ws && S._ws.readyState===1) return res(S._ws);
    let done=false;
    const url=(location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/run';
    const ws=new WebSocket(url);
    const to=setTimeout(()=>{if(!done){done=true;try{ws.close();}catch(e){}rej(new Error('timeout'));}},7000);
    ws.onopen=()=>{done=true;clearTimeout(to);S._ws=ws;res(ws);};
    ws.onerror=()=>{if(!done){done=true;clearTimeout(to);rej(new Error('handshake'));}};
    ws.onclose=()=>{S._ws=null;if(!done){done=true;clearTimeout(to);rej(new Error('closed'));}};
    ws.onmessage=e=>dispatch(JSON.parse(e.data));
  });
}
function dispatch(m){
  const cb=S._cb||{};
  const call=(k,...a)=>{ if(cb[k]) cb[k](...a); };
  if(m.type==='started'){ S.runId=m.run_id; call('onStart',m); }
  else if(m.type==='command'){ call('onCommand',m); }
  else if(m.type==='output'){ call('onOutput',m.data); }
  else if(m.type==='advisory'){ call('onAdvisory',m.message); }
  else if(m.type==='confirm_required'){ call('onConfirm',m); }
  else if(m.type==='parsed'){ call('onParsed',m); }
  else if(m.type==='blocked'){ call('onOutput','blocked: '+m.reason); call('onDone',m); }
  else if(m.type==='done'){ call('onDone',m); }
  else if(m.type==='error'){ call('onError',m.message); call('onDone',m); }
}
export async function runTool(req, cb){
  S._cb=cb||{}; S._lastReq=req;
  try{ const ws=await connect(); ws.send(JSON.stringify(req)); }
  catch(e){ (cb&&cb.onError)&&cb.onError('Could not reach the R.O.D.E server — is start.bat still running?'); }
}
export function resendConfirmed(){
  if(S._ws && S._lastReq){ S._lastReq.confirmed=true; S._ws.send(JSON.stringify(S._lastReq)); }
}
export function cancelRun(){
  if(S._ws && S.runId){ S._ws.send(JSON.stringify({action:'cancel', run_id:S.runId})); }
}
