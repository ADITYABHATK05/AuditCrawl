from __future__ import annotations

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)
    scan_level: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    findings: Mapped[list["VulnerabilityFinding"]] = relationship(
        back_populates="scan_run", cascade="all, delete-orphan"
    )

    leaked_assets: Mapped[list["LeakedAsset"]] = relationship(
        back_populates="scan_run", cascade="all, delete-orphan"
    )


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(1024), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerable_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    fix_snippet: Mapped[str] = mapped_column(Text, nullable=False)

    scan_run: Mapped[ScanRun] = relationship(back_populates="findings")


class LeakedAsset(Base):
    __tablename__ = "leaked_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(128), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(1024), nullable=False)

    scan_run: Mapped[ScanRun] = relationship(back_populates="leaked_assets")
