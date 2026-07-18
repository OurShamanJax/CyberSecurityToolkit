"""MITRE ATT&CK mapping — the framework spine.

Maps the tools R.O.D.E actually runs (and the entities/findings they produce) to
ATT&CK Enterprise techniques, then rolls an investigation up into a **coverage
view**: which tactics and techniques you've touched. Curated + embedded (no data
download, no key). ATT&CK is a free/open framework by MITRE.
"""
from __future__ import annotations

from .models import Run, Entity, Finding

# technique id -> (name, tactic)
TECHNIQUES = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1590": ("Gather Victim Network Information", "Reconnaissance"),
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1589": ("Gather Victim Identity Information", "Reconnaissance"),
    "T1596": ("Search Open Technical Databases", "Reconnaissance"),
    "T1594": ("Search Victim-Owned Websites", "Reconnaissance"),
    "T1587": ("Develop Capabilities", "Resource Development"),
    "T1588": ("Obtain Capabilities", "Resource Development"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1040": ("Network Sniffing", "Discovery"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
}

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# tool_id -> techniques it exercises (substring match, so nmap_quick matches nmap)
TOOL_TECH = {
    "nmap": ["T1046", "T1595"],
    "nikto": ["T1595", "T1594"],
    "nuclei": ["T1595", "T1190"],
    "whatweb": ["T1592", "T1594"],
    "wpscan": ["T1595", "T1592"],
    "sqlmap": ["T1190"],
    "harvester": ["T1589", "T1590"],
    "sherlock": ["T1589"],
    "exposure": ["T1596", "T1590"],
    "shodan": ["T1596"],
    "lan_discover": ["T1018", "T1595"],
    "exploit_search": ["T1588"],
    "cve": ["T1588"],
    "credential": ["T1110", "T1078"],
    "login": ["T1110"],
    "traffic": ["T1040", "T1071"],
    "capture": ["T1040"],
    "msfvenom": ["T1587"],
    "msfconsole": ["T1059", "T1190", "T1210"],
    "analyzer": ["T1592"],
    "wireless": ["T1595"],
}

# entity type -> techniques implied by its existence
ENTITY_TECH = {
    "exploit": ["T1588", "T1190"],
    "vulnerability": ["T1190"],
    "service": ["T1046"],
    "credential": ["T1078", "T1110"],
    "alert": ["T1040"],
}


def _tech_for_tool(tool_id: str):
    t = (tool_id or "").lower()
    hits = set()
    for key, techs in TOOL_TECH.items():
        if key in t:
            hits.update(techs)
    return hits


def techniques_for(tool_id: str = "", entity_type: str = "") -> list:
    """Techniques for a single tool run or entity — used for per-node tags."""
    hits = _tech_for_tool(tool_id)
    if entity_type:
        hits.update(ENTITY_TECH.get(entity_type, []))
    return [{"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1]}
            for t in sorted(hits) if t in TECHNIQUES]


def coverage(db, inv_id: int) -> dict:
    """Roll an investigation up into ATT&CK tactic/technique coverage."""
    counts: dict = {}   # technique id -> evidence count

    def bump(techs):
        for t in techs:
            if t in TECHNIQUES:
                counts[t] = counts.get(t, 0) + 1

    for r in db.query(Run).filter(Run.investigation_id == inv_id).all():
        bump(_tech_for_tool(r.tool_id))
    for e in db.query(Entity).filter(Entity.investigation_id == inv_id).all():
        bump(ENTITY_TECH.get(e.type, []))

    by_tactic: dict = {}
    for tid, n in counts.items():
        name, tactic = TECHNIQUES[tid]
        by_tactic.setdefault(tactic, []).append({"id": tid, "name": name, "count": n})

    tactics = []
    for tac in TACTIC_ORDER:
        techs = sorted(by_tactic.get(tac, []), key=lambda x: -x["count"])
        if techs:
            tactics.append({"tactic": tac, "techniques": techs})

    return {"tactics": tactics, "technique_count": len(counts),
            "tactic_count": len(tactics), "total_tactics": len(TACTIC_ORDER)}
