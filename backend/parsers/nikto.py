"""Nikto parser — turns a wall of '+ /path: description' lines into a graph that
tells a story instead of a flat fan of look-alike nodes.

Modeling rules:
  * A real path (/ftp/, /.htpasswd, /admin) becomes its own ENDPOINT node, with
    the reason it's interesting attached as an issue:
        target -> HAS_ENDPOINT -> /ftp/ -> HAS_ISSUE -> "directory is interesting"
  * Config-level findings that have no distinct location (missing headers, CORS,
    cookie flags, outdated software, speculative backup/cert guesses) collapse
    under a labelled CATEGORY node so 7 header warnings read as one branch:
        target -> HAS_ISSUE_GROUP -> "Headers & policies" -> HAS_ISSUE -> ...
Speculative guesses (hundreds of backup filenames) are de-duplicated to one entry.
"""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

FIND_RE = re.compile(r'^\+\s+(.+?):\s+(.{6,})$', re.M)
SKIP = ("target ip", "target hostname", "target port", "start time", "end time",
        "server", "root page", "no cgi", "scan terminated", "host(s) tested")
NOISE_DESC = re.compile(r'requests?:\s*\d+\s*error|item\(s\) reported', re.I)
MAX_ITEMS = 40
MAX_ENDPOINTS = 14


def _short(desc: str) -> str:
    d = re.sub(r'\s*See:\s*https?://\S+', '', desc).strip().rstrip('.')
    d = re.sub(r'^Suggested security header missing:\s*', 'missing header: ', d, flags=re.I)
    d = re.sub(r'Potentially interesting backup/?cert file found\.?\s*\.?', 'interesting backup/cert file', d, flags=re.I)
    d = re.sub(r'^Uncommon header\(s\)\s*', 'uncommon header: ', d, flags=re.I)
    d = re.sub(r'\s+', ' ', d).strip()
    return d[:58]


def _category(desc: str):
    """(label, key) for the grouping node a location-less finding belongs to."""
    d = desc.lower()
    if 'header' in d:
        return ("Headers & policies", "headers")
    if 'cookie' in d:
        return ("Cookie flags", "cookies")
    if 'access-control' in d or 'cors' in d:
        return ("CORS / access-control", "cors")
    if 'ssl' in d or 'tls' in d or 'cipher' in d or 'certificate' in d:
        return ("TLS / certificates", "tls")
    if 'outdated' in d or 'out of date' in d or 'version' in d:
        return ("Outdated software", "versions")
    return ("Other checks", "other")


def _is_endpoint(path: str, desc: str) -> bool:
    """A concrete, discovered path worth its own node (not a speculative guess)."""
    if 'backup/cert' in desc.lower() or 'backup or cert' in desc.lower():
        return False
    p = path.strip()
    return p.startswith('/') and len(p) > 1


class NiktoParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        root = target.rstrip('/')
        entities = [ParsedEntity("url", target, 1.0, target)]
        rels: list[ParsedRelationship] = []
        seen_item, seen_ep, cats = set(), set(), set()
        n = 0

        for m in FIND_RE.finditer(raw or ""):
            path, desc = m.group(1).strip(), m.group(2).strip()
            if path.lower() in SKIP or path.startswith('+') or NOISE_DESC.search(desc):
                continue

            # ── real endpoint: give the path its own node ───────────────
            if _is_endpoint(path, desc) and len(seen_ep) < MAX_ENDPOINTS:
                ep_key = path.lower()
                if ep_key in seen_ep:
                    continue
                seen_ep.add(ep_key)
                n += 1
                if n > MAX_ITEMS:
                    break
                ep = root + path
                entities.append(ParsedEntity("url", ep, 0.75, path,
                                             {"source": "nikto", "detail": desc[:200]}))
                rels.append(ParsedRelationship(target, "url", "HAS_ENDPOINT", ep, "url", 0.8))
                fval = f"nikto:ep:{ep_key[:40]}"
                entities.append(ParsedEntity("vulnerability", fval, 0.6, f"{_short(desc)} \u2014 {path}",
                                             {"severity": "info", "detail": desc[:200],
                                              "source": "nikto", "url": ep}))
                rels.append(ParsedRelationship(ep, "url", "HAS_ISSUE", fval, "vulnerability", 0.6))
                continue

            # ── location-less finding: collapse under a category ────────
            label = _short(desc)
            key = label.lower()
            if not key or key in seen_item:
                continue
            seen_item.add(key)
            n += 1
            if n > MAX_ITEMS:
                break
            clabel, ckey = _category(desc)
            cval = f"nikto-cat:{ckey}"
            if cval not in cats:
                cats.add(cval)
                entities.append(ParsedEntity("category", cval, 0.9, clabel, {"source": "nikto"}))
                rels.append(ParsedRelationship(target, "url", "HAS_ISSUE_GROUP", cval, "category", 0.9))
            fval = f"nikto:{key[:44]}"
            entities.append(ParsedEntity("vulnerability", fval, 0.6, label,
                                         {"severity": "info", "detail": desc[:200], "source": "nikto"}))
            rels.append(ParsedRelationship(cval, "category", "HAS_ISSUE", fval, "vulnerability", 0.6))

        eps = len(seen_ep)
        return ParseResult(entities, rels,
                           f"Nikto: {n} item(s) on {target} — {eps} endpoint(s), {len(cats)} group(s)")
