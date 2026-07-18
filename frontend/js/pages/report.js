// pages/report.js — the growing investigation report, full-page
import { $, API, S, toast, pageHead } from '../core.js';
let html='', filename='report.html';
async function mount(root){
  root.innerHTML=`<div class="page">${pageHead({
    title:'Report',
    intro:'A growing, plain-English report of this investigation — regenerates from the current graph every time you open it.',
    actions:'<button class="ghost" id="rprint">Print / PDF</button><button class="primary" id="rdl">Download</button>'
  })}
    <div class="page-body" style="padding:0"><iframe id="rframe" title="Report" style="width:100%;height:100%;border:0;background:#fff"></iframe></div></div>`;
  if(!S.inv){ $('#rframe').srcdoc='<body style="font-family:sans-serif;color:#555;padding:40px">Select or create an investigation first.</body>'; return; }
  try{ const r=await API('/report/'+S.inv); html=r.html; filename=r.filename; $('#rframe').srcdoc=html; }
  catch(e){ toast('Could not build report','err'); }
  $('#rprint').onclick=()=>{ try{ $('#rframe').contentWindow.focus(); $('#rframe').contentWindow.print(); }catch(e){} };
  $('#rdl').onclick=()=>{ const b=new Blob([html],{type:'text/html'}); const a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download=filename; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),3000); };
}
export default { id:'report', label:'Report', short:'Report', mount, unmount(){} };
