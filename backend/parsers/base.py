"""
Parser contract — every tool parser turns raw text into the same shape.

The whole point of parsers is normalization: nmap, nuclei and sherlock all
produce wildly different text, but they all come out of here as the same
Entity/Relationship objects that feed the graph.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ParsedEntity:
    type: str            # ip | domain | url | email | service | vulnerability | ...
    value: str
    confidence: float = 0.5
    label: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ParsedRelationship:
    source_value: str
    source_type: str
    relation_type: str
    target_value: str
    target_type: str
    weight: float = 0.5


@dataclass
class ParseResult:
    entities: list[ParsedEntity] = field(default_factory=list)
    relationships: list[ParsedRelationship] = field(default_factory=list)
    summary: str = ""


class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw: str, target: str) -> ParseResult:
        ...
