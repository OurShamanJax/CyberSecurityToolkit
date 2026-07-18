"""LAN-discovery parser: '[HOST] ip :: hostname :: mac :: role :: vendor' lines
become `host` nodes wired to the gateway — a star-topology of your local
network. The node label prefers a real name (hostname, else vendor, else IP)."""
import re
from .base import BaseParser, ParsedEntity, ParsedRelationship, ParseResult

LINE = re.compile(r'^\[HOST\]\s+(\S+)\s+::\s+(.+?)\s+::\s+(\S+)\s+::\s+(\S+)\s+::\s+(.+?)\s*$', re.M)


class LanParser(BaseParser):
    def parse(self, raw: str, target: str) -> ParseResult:
        ents, rels, hosts = [], [], []
        for m in LINE.finditer(raw or ""):
            ip, name, mac, role, vendor = (m.group(1), m.group(2).strip(), m.group(3).strip(),
                                           m.group(4).strip(), m.group(5).strip())
            name = "" if name == "-" else name
            mac = "" if mac == "-" else mac
            vendor = "" if vendor == "-" else vendor
            real_vendor = vendor and not vendor.startswith("private")
            label = name or ("gateway" if role == "gateway"
                             else (vendor if real_vendor else ip))
            ents.append(ParsedEntity("host", ip, 0.9, label[:60],
                                     {"mac": mac, "hostname": name, "role": role,
                                      "vendor": vendor, "source": "lan-discovery"}))
            hosts.append((ip, role))

        if hosts:
            gw = next((ip for ip, role in hosts if role == "gateway"), None)
            base = hosts[0][0].rsplit(".", 1)[0]
            gw = gw or (base + ".1")
            if gw not in [ip for ip, _ in hosts]:
                ents.append(ParsedEntity("host", gw, 0.7, "gateway",
                                         {"role": "gateway", "source": "lan-discovery"}))
            for ip, _role in hosts:
                if ip != gw:
                    rels.append(ParsedRelationship(ip, "host", "ON_LAN", gw, "host", 0.6))

        return ParseResult(ents, rels, f"LAN discovery: {len(hosts)} live host(s)")
