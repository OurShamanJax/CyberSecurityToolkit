"""
Database models — cleaned up from v2.

Changes vs v2:
  * Investigation now owns a `scope` (JSON list) — the allowed targets.
  * New `Finding` model: results (vulns, open ports of note) are first-class,
    not just buried in raw text.
  * Clearer names and consistent JSON helpers.
"""
import json
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index,
)
from sqlalchemy.orm import relationship

from .db import Base


class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    scope_json = Column(Text, default="[]")   # allowed targets (list of strings)
    mode = Column(String(20), default="infra")  # infra | identity | traffic | wireless
    status = Column(String(50), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    runs = relationship("Run", back_populates="investigation", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")

    def scope(self) -> list:
        try:
            return json.loads(self.scope_json or "[]")
        except Exception:
            return []


class Run(Base):
    __tablename__ = "runs"
    id = Column(Integer, primary_key=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    tool_id = Column(String(100), nullable=False)
    target = Column(String(500), nullable=False)
    command = Column(Text, default="")
    noise = Column(String(20), default="silent")
    status = Column(String(50), default="queued")   # queued|running|done|failed|cancelled
    exit_code = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    output_file = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="runs")


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("investigation_id", "type", "value", name="uq_entity"),
        Index("ix_entity_inv_type", "investigation_id", "type"),
    )
    id = Column(Integer, primary_key=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    source_run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    type = Column(String(50), nullable=False)
    value = Column(String(1000), nullable=False)
    label = Column(String(255), nullable=True)
    metadata_json = Column(Text, default="{}")
    confidence = Column(Float, default=0.5)
    user_confirmed = Column(Boolean, default=False)
    times_seen = Column(Integer, default=1)
    lat = Column(Float, nullable=True)
    lng = Column(Float, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="entities")

    def metadata_dict(self) -> dict:
        try:
            return json.loads(self.metadata_json or "{}")
        except Exception:
            return {}


class Relationship(Base):
    __tablename__ = "relationships"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("entities.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("entities.id"), nullable=False)
    relation_type = Column(String(100), nullable=False)
    weight = Column(Float, default=0.5)
    created_at = Column(DateTime, default=datetime.utcnow)


class Finding(Base):
    """A noteworthy result surfaced to the user (vuln, exposure, weak config)."""
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    severity = Column(String(20), default="info")   # info|low|medium|high|critical
    title = Column(String(300), nullable=False)
    detail = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="findings")
