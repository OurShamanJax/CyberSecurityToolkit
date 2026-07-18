"""Maps a tool's `parser` field to a parser instance."""
from .base import BaseParser
from .generic import GenericParser
from .nmap import NmapParser
from .nuclei import NucleiParser
from .nikto import NiktoParser
from .sherlock import SherlockParser
from .theharvester import TheHarvesterParser
from .gobuster import GobusterParser
from .subfinder import SubfinderParser
from .httpx import HttpxParser
from .binary import BinaryParser
from .trivy import TrivyParser
from .sqlmap import SqlmapParser
from .exploit import ExploitParser
from .lan import LanParser
from .lynis import LynisParser

_PARSERS: dict[str, BaseParser] = {
    "nmap": NmapParser(),
    "nuclei": NucleiParser(),
    "nikto": NiktoParser(),
    "sherlock": SherlockParser(),
    "theharvester": TheHarvesterParser(),
    "gobuster": GobusterParser(),
    "subfinder": SubfinderParser(),
    "httpx": HttpxParser(),
    "binary": BinaryParser(),
    "trivy": TrivyParser(),
    "sqlmap": SqlmapParser(),
    "exploit": ExploitParser(),
    "lan": LanParser(),
    "lynis": LynisParser(),
    "generic": GenericParser(),
}


def get_parser(name: str) -> BaseParser:
    """Return the named parser, falling back to the generic extractor."""
    return _PARSERS.get((name or "").lower(), _PARSERS["generic"])
