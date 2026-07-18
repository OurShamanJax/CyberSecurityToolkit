"""
Growing investigation report - rendered as a self-contained HTML document.

Pulls the current state of an investigation (findings, capabilities, assets,
tool runs) and produces a printable HTML page, with a plain-English explanation
for every finding drawn from the knowledge base. Re-generating always reflects
the latest state, so the report "grows" as you work.
"""
from __future__ import annotations

import html
import json
from datetime import datetime

from sqlalchemy.orm import Session

from ..models import Investigation, Run, Entity, Finding, Relationship
from .knowledge import lookup

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEV_COLOR = {"critical": "#b00020", "high": "#d9480f", "medium": "#b8860b",
             "low": "#1971c2", "info": "#5c7080", "unknown": "#5c7080"}
ASSET_LABELS = {"ip": "Hosts / IPs", "domain": "Domains & subdomains", "url": "URLs",
                "service": "Services / ports", "email": "Emails", "username": "Usernames",
                "technology": "Technologies", "file": "Files analysed",
                "capability": "Capabilities", "secret": "Secrets", "target": "Targets",
                "credential": "Credentials", "access_point": "Access points", "alert": "Traffic alerts", "exploit": "Known exploits"}


def _e(x) -> str:
    return html.escape(str(x or ""))


def _finding_key(f: Finding) -> str:
    try:
        m = json.loads(f.detail or "{}")
    except Exception:
        m = {}
    return " ".join(x for x in (m.get("template"), m.get("rule"), m.get("pkg"), f.title) if x)


def build_html(db: Session, inv_id: int) -> tuple[str, str]:
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        return "<h1>Investigation not found</h1>", "report.html"

    ents = db.query(Entity).filter(Entity.investigation_id == inv_id).all()
    runs = db.query(Run).filter(Run.investigation_id == inv_id) \
             .order_by(Run.created_at.desc()).all()

    # exploit -> the software/tech it was matched against (the attack path)
    ent_by_id = {e.id: e for e in ents}
    ids = set(ent_by_id)
    affected_of = {}
    if ids:
        rels = db.query(Relationship).filter(
            Relationship.source_id.in_(ids), Relationship.target_id.in_(ids)).all()
        for r in rels:
            if r.relation_type == "HAS_EXPLOIT":
                affected_of[r.target_id] = ent_by_id.get(r.source_id)

    # De-dupe findings by title, keep the most severe.
    fmap: dict[str, Finding] = {}
    for f in db.query(Finding).filter(Finding.investigation_id == inv_id).all():
        cur = fmap.get(f.title)
        if not cur or SEV_ORDER.get(f.severity, 5) < SEV_ORDER.get(cur.severity, 5):
            fmap[f.title] = f
    findings = sorted(fmap.values(), key=lambda x: SEV_ORDER.get(x.severity, 5))

    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    caps = [e for e in ents if e.type == "capability"]
    assets: dict[str, list] = {}
    for e in ents:
        assets.setdefault(e.type, []).append(e)

    now = datetime.utcnow().strftime("%B %d, %Y")
    P = []
    P.append(f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{_e(inv.name)} - Report</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a1a;max-width:820px;margin:0 auto;padding:34px 40px;line-height:1.55;font-size:15px}}
  h1{{font-size:26px;margin:0 0 2px;color:#12263a}} h2{{font-size:19px;color:#2E75B6;border-bottom:2px solid #dbe5ef;padding-bottom:5px;margin-top:30px}}
  h3{{font-size:16px;margin:20px 0 4px}}
  .meta{{color:#5c7080;font-size:13px;margin-bottom:18px}}
  table{{border-collapse:collapse;width:100%;margin:10px 0;font-size:14px}}
  th,td{{border:1px solid #d5dde5;padding:7px 10px;text-align:left;vertical-align:top}}
  th{{background:#12263a;color:#fff;font-weight:600}}
  .pill{{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600;color:#fff;text-transform:uppercase}}
  .sumgrid{{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}}
  .sc{{background:#f3f6f9;border-radius:8px;padding:10px 16px;min-width:92px;text-align:center}}
  .sc b{{font-size:22px;display:block}} .sc span{{font-size:12px;color:#5c7080}}
  .plain{{background:#eef6f3;border-left:5px solid #2E7D6F;padding:11px 15px;border-radius:0 6px 6px 0;margin:8px 0}}
  .plain .t{{font-weight:700;color:#2E7D6F;margin-bottom:4px}}
  .why{{font-size:14px}} .fix li{{margin:3px 0}}
  .muted{{color:#5c7080;font-size:13px}} code{{background:#f0f2f4;padding:1px 5px;border-radius:4px;font-size:13px}}
  .lvltoggle{{position:fixed;top:12px;right:14px;display:flex;border:1px solid #cdd7e1;border-radius:7px;overflow:hidden;font-size:12px;z-index:9}}
  .lvltoggle button{{border:0;background:#fff;color:#5c7080;padding:5px 13px;cursor:pointer;font:inherit}}
  .lvltoggle button.on{{background:#2E75B6;color:#fff}}
  .lvl-a{{display:none}} body.adv .lvl-a{{display:block}} body.adv .lvl-b{{display:none}}
  .tech{{background:#f4f6f8;border-left:5px solid #5c7080;padding:10px 14px;border-radius:0 6px 6px 0;margin:8px 0;font-size:13.5px}}
  .tech .t{{font-weight:700;color:#3a4a5a;margin-bottom:5px}} .tech code{{background:#e7ebef}}
  .kv{{margin:2px 0}} .kv b{{color:#3a4a5a;min-width:104px;display:inline-block}}
  .note{{background:#fff8e6;border-left:5px solid #b8860b;padding:10px 14px;border-radius:0 6px 6px 0;margin:12px 0;font-size:13.5px}}
  @media print{{body{{padding:0}}.lvltoggle{{display:none}}}}
</style></head><body>""")
    P.append('<div class="lvltoggle"><button id="lb" class="on">Beginner</button><button id="la">Advanced</button></div>')
    P.append(f"<h1>{_e(inv.name)}</h1>")
    P.append(f'<div class="meta">R.O.D.E v4 investigation report &middot; {now} &middot; scope: {_e(", ".join(inv.scope()) or "local only")}</div>')

    # Summary
    P.append("<h2>Summary</h2>")
    P.append('<div class="sumgrid">')
    for s in ("critical", "high", "medium", "low", "info"):
        P.append(f'<div class="sc"><b style="color:{SEV_COLOR[s]}">{counts.get(s,0)}</b><span>{s}</span></div>')
    P.append(f'<div class="sc"><b>{len(ents)}</b><span>entities</span></div>')
    P.append(f'<div class="sc"><b>{len(runs)}</b><span>tool runs</span></div>')
    P.append('</div>')

    # Narrative overview (two-level)
    crit = counts.get("critical", 0); high = counts.get("high", 0)
    n_host = len([e for e in ents if e.type in ("ip", "host")])
    scope_txt = ", ".join(inv.scope()) or "your local machine"
    top = findings[0].title if findings else None
    nb = [f"This report covers {scope_txt}. R.O.D.E examined {len(ents)} item(s) and recorded {len(findings)} finding(s)."]
    if crit or high:
        nb.append(f"{crit + high} need attention first ({crit} critical, {high} high)"
                  + (f", starting with “{top}”." if top else "."))
    elif findings:
        nb.append("Nothing critical stood out, but review the items below.")
    else:
        nb.append("Nothing notable was flagged yet — run more tools to deepen the picture.")
    na = [f"Scope {scope_txt}. Graph holds {len(ents)} entities ({n_host} hosts) across {len(runs)} tool run(s); "
          f"{len(findings)} de-duplicated findings — {crit} critical / {high} high / "
          f"{counts.get('medium',0)} medium / {counts.get('low',0)} low / {counts.get('info',0)} info."]
    if exploits_present := [e for e in ents if e.type == "exploit"]:
        na.append(f"{len(exploits_present)} public exploit(s) were matched to discovered software (see attack paths).")
    P.append(f'<div class="plain"><div class="t">Overview</div>'
             f'<div class="lvl-b">{_e(" ".join(nb))}</div>'
             f'<div class="lvl-a">{_e(" ".join(na))}</div></div>')
    P.append('<div class="note"><div class="lvl-b"><b>How to read this:</b> every finding has a '
             '<b>severity</b> — how bad it is if abused (info → critical). Fix critical and high first. '
             'Switch to <b>Advanced</b> (top-right) for the exact rules, CVEs and evidence.</div>'
             '<div class="lvl-a"><b>Severity vs loudness.</b> Severity = potential impact of the issue. '
             'Loudness = how detectable the scan that surfaced it is on the wire — active/exploit checks are '
             'far easier for a defender or IDS to notice than passive lookups. Prioritise by severity; plan '
             'engagement timing by loudness.</div></div>')
    if not findings and not caps:
        P.append('<p class="muted">No findings or capabilities recorded yet. Run some tools, then regenerate this report.</p>')

    # Correlations — escalated combined-signal findings (headline)
    try:
        from .. import correlate
        corr = correlate.correlations(db, inv_id).get("correlations", [])
    except Exception:
        corr = []
    if corr:
        P.append("<h2>Correlations</h2>")
        P.append('<p class="muted">Combined signals that escalate priority — the graph connecting the dots.</p>')
        for c in corr:
            col = SEV_COLOR.get(c["level"], "#5c7080")
            P.append(f'<div class="note" style="border-left-color:{col}"><b>{_e(c["title"])} '
                     f'<span class="pill" style="background:{col}">{_e(c["level"])}</span></b><br>{_e(c["why"])}</div>')

    # Findings
    if findings:
        P.append("<h2>Findings</h2>")
        for i, f in enumerate(findings, 1):
            kb = lookup(_finding_key(f), f.severity)
            col = SEV_COLOR.get(f.severity, "#5c7080")
            P.append(f'<h3>{i}. {_e(f.title)} '
                     f'<span class="pill" style="background:{col}">{_e(f.severity)}</span></h3>')
            P.append('<div class="plain"><div class="t">In plain English</div>'
                     f'<div>{_e(kb.get("plain",""))}</div>')
            if kb.get("why"):
                P.append(f'<div class="why" style="margin-top:6px"><b>Why it matters:</b> {_e(kb["why"])}</div>')
            P.append('</div>')
            # advanced: technical evidence pulled from the finding's raw detail
            try:
                m = json.loads(f.detail or "{}")
            except Exception:
                m = {}
            rows = []
            for label, key in (("Rule / template", "template"), ("Rule", "rule"),
                               ("Package", "pkg"), ("CVE", "cve"), ("Matched at", "matched_at"),
                               ("Evidence", "evidence"), ("URL", "url"), ("Port", "port"), ("Tool", "tool")):
                v = m.get(key)
                if v:
                    rows.append(f'<div class="kv"><b>{_e(label)}</b> <code>{_e(str(v)[:160])}</code></div>')
            P.append('<div class="tech lvl-a"><div class="t">Technical detail</div>')
            P.append("".join(rows) if rows else '<div class="muted">No structured evidence captured.</div>')
            prio = "fix immediately" if f.severity in ("critical", "high") else "schedule after higher-severity items"
            P.append(f'<div style="margin-top:7px"><b>Severity {_e(f.severity)}</b> — impact if abused; {prio}.</div>')
            P.append('</div>')
            if kb.get("fix"):
                P.append('<b>How to fix it</b><ul class="fix">')
                for step in kb["fix"]:
                    P.append(f'<li>{_e(step)}</li>')
                P.append('</ul>')

    # Known exploits & attack paths (from Exploit-DB search)
    exploits = [e for e in ents if e.type == "exploit"]
    if exploits:
        P.append("<h2>Known exploits &amp; attack paths</h2>")
        P.append('<p class="muted">Public exploits R.O.D.E matched to discovered software via Exploit-DB. '
                 'These are references to public research, not attacks in themselves - validate them and only '
                 'use them against systems you own or are authorized to test.</p>')
        P.append('<table><tr><th>Affected (discovered)</th><th>Exploit</th><th>Platform</th>'
                 '<th>CVE</th><th>Reference</th></tr>')
        for e in exploits:
            m = e.metadata_dict()
            aff = affected_of.get(e.id)
            aff_txt = _e(aff.label or aff.value) if aff else '<span class="muted">-</span>'
            url = m.get("url", "")
            eid = m.get("id", "")
            ref = f'<a href="{_e(url)}">EDB-{_e(eid)}</a>' if url else _e(eid)
            P.append(f'<tr><td>{aff_txt}</td><td>{_e(e.label or e.value)}</td>'
                     f'<td class="muted">{_e(m.get("platform",""))}</td>'
                     f'<td class="muted">{_e(m.get("cve",""))}</td><td>{ref}</td></tr>')
        P.append('</table>')

    # MITRE ATT&CK coverage — ties what was done to the framework
    try:
        from .. import attack
        cov = attack.coverage(db, inv_id)
    except Exception:
        cov = {"tactics": []}
    if cov["tactics"]:
        P.append("<h2>MITRE ATT&amp;CK coverage</h2>")
        P.append(f'<p class="muted">What this investigation did, mapped to the ATT&amp;CK framework — '
                 f'{cov["technique_count"]} technique(s) across {cov["tactic_count"]} of '
                 f'{cov["total_tactics"]} tactics.</p>')
        P.append('<table><tr><th>Tactic</th><th>Techniques observed</th></tr>')
        for t in cov["tactics"]:
            techs = ", ".join(f'{_e(x["id"])} {_e(x["name"])}' for x in t["techniques"])
            P.append(f'<tr><td><b>{_e(t["tactic"])}</b></td><td class="muted">{techs}</td></tr>')
        P.append('</table>')

    # Capabilities (from Binary Inspector)
    if caps:
        P.append("<h2>Program capabilities</h2>")
        P.append('<p class="muted">Static capabilities detected in analysed binaries (hints, not proof of behaviour).</p><table>'
                 '<tr><th>Capability</th><th>APIs / evidence</th></tr>')
        for c in caps:
            meta = c.metadata_dict()
            P.append(f'<tr><td>{_e(c.label or c.value)}</td><td><code>{_e(meta.get("apis",""))}</code></td></tr>')
        P.append('</table>')

    # Assets
    other = {k: v for k, v in assets.items() if k not in ("capability", "vulnerability", "secret", "category", "credential", "alert", "exploit")}
    if other:
        P.append("<h2>Assets discovered</h2><table><tr><th>Type</th><th>Count</th><th>Examples</th></tr>")
        for t, items in sorted(other.items(), key=lambda kv: -len(kv[1])):
            ex = ", ".join(_e(x.value)[:40] for x in items[:4])
            P.append(f'<tr><td>{_e(ASSET_LABELS.get(t,t))}</td><td>{len(items)}</td><td class="muted">{ex}</td></tr>')
        P.append("</table>")

    # Tools run
    if runs:
        P.append("<h2>Tools run</h2><table><tr><th>Tool</th><th>Target</th><th>When</th></tr>")
        for r in runs[:40]:
            P.append(f'<tr><td>{_e(r.tool_id)}</td><td class="muted">{_e(r.target)}</td>'
                     f'<td class="muted">{r.created_at.strftime("%Y-%m-%d %H:%M")}</td></tr>')
        P.append("</table>")

    P.append('<p class="muted" style="margin-top:26px">Generated by R.O.D.E v4. Plain-English explanations come from '
             'R.O.D.E&#39;s findings knowledge base. Validate findings before formal use.</p>')
    P.append("<script>(function(){var b=document.body,lb=document.getElementById('lb'),"
             "la=document.getElementById('la');function s(a){b.classList.toggle('adv',a);"
             "lb.classList.toggle('on',!a);la.classList.toggle('on',a);}"
             "if(lb&&la){lb.onclick=function(){s(false);};la.onclick=function(){s(true);};}})();</script>")
    P.append("</body></html>")

    safe = "".join(c if c.isalnum() else "_" for c in inv.name)[:40] or "investigation"
    return "".join(P), f"RODE_report_{safe}.html"
