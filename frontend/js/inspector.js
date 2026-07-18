// inspector.js — one detail-panel look, shared by every surface.
// The graph node popup defined the canonical vocabulary (.ins-* classes); this
// promotes it into a reusable renderer so Live Traffic, the Map lens, Home, and
// any tool render their "what am I looking at" panel identically. Placement
// (floating popup vs docked side panel) stays the host's job — this owns LOOK.
//
// Model:
//   { kind, accent, title, right, flags:[..], closable, onClose,
//     chips:[{text,cls}], rows:[[k,v,cls?]],
//     explain:{t?,plain,why?,fix?},
//     groups:[{label,accent?,items:[{label,title?,accent?,onClick}]}] }
import { escapeHtml } from './core.js';

export function inspectorInner(m){
  const col = m.accent || '#6b7684';
  let h = `<div class="ins-h"><span class="ins-badge" style="background:${col}22;color:${col};border-color:${col}66">${escapeHtml(m.kind||'')}</span>`;
  (m.flags||[]).forEach(f=>{ h+=`<span class="ins-ok">${escapeHtml(f)}</span>`; });
  if(m.right) h+=`<span class="ins-conf">${escapeHtml(m.right)}</span>`;
  if(m.closable) h+=`<button class="ins-x" aria-label="Close">&times;</button>`;
  h+=`</div>`;
  if(m.title!=null && m.title!=='') h+=`<div class="ins-val">${escapeHtml(m.title)}</div>`;
  if(m.chips && m.chips.length) h+=`<div class="ins-chips">${m.chips.map(c=>`<span class="ins-chip ${c.cls||''}">${escapeHtml(c.text)}</span>`).join('')}</div>`;
  (m.rows||[]).forEach(r=>{ h+=`<div class="ins-row"><span class="k">${escapeHtml(r[0])}</span><span class="v ${r[2]||''}">${escapeHtml(r[1])}</span></div>`; });
  if(m.explain){ const e=m.explain;
    h+=`<div class="ins-explain">`;
    if(e.t!==false) h+=`<div class="ex-t">${escapeHtml(e.t||'What this means')}</div>`;
    if(e.plain) h+=`<div class="ex-p">${escapeHtml(e.plain)}</div>`;
    if(e.why) h+=`<div class="ex-why">${escapeHtml(e.why)}</div>`;
    if(e.fix) h+=`<div class="ex-fix"><b>Fix:</b> ${escapeHtml(e.fix)}</div>`;
    h+=`</div>`;
  }
  return h;
}

// Render into a docked container, wiring action groups + close.
export function renderInspector(el, m){
  if(!el) return el;
  el.innerHTML = inspectorInner(m);
  (m.groups||[]).forEach(g=>{
    const dv=document.createElement('div'); dv.className='ins-run-t';
    if(g.accent) dv.style.color=g.accent; dv.textContent=g.label; el.appendChild(dv);
    const rr=document.createElement('div'); rr.className='ins-run';
    (g.items||[]).forEach(it=>{
      const b=document.createElement('button'); b.className='ins-tool';
      if(it.accent){ b.style.borderColor=it.accent; b.style.color=it.accent; }
      b.innerHTML=it.label; if(it.title)b.title=it.title;
      if(it.onClick)b.onclick=it.onClick; rr.appendChild(b);
    });
    el.appendChild(rr);
  });
  const x=el.querySelector('.ins-x'); if(x&&m.onClose)x.onclick=m.onClose;
  return el;
}

// Placeholder for an empty docked inspector.
export function inspectorEmpty(el, msg){
  if(el) el.innerHTML=`<div class="ins-empty muted">${escapeHtml(msg||'Select something to inspect.')}</div>`;
}
