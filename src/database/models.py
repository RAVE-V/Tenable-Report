"""SQLAlchemy ORM models for Tenable Report Generator"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, UniqueConstraint, Enum, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


class ConfidenceLevel(enum.Enum):
    """Confidence level for server-application mappings"""
    MANUAL = "manual"
    AUTO = "auto"
    INFERRED = "inferred"


class Server(Base):
    """Server inventory table"""
    __tablename__ = "servers"
    
    server_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String(255), unique=True, nullable=False, index=True)
    asset_uuid = Column(String(255), unique=True, index=True)
    ipv4 = Column(String(45))  # IPv4 address
    operating_system = Column(String(255))
    device_type = Column(String(50), default='unknown')  # server, workstation, network, unknown
    last_seen = Column(DateTime)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    mappings = relationship("ServerApplicationMap", back_populates="server", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Server(hostname='{self.hostname}', asset_uuid='{self.asset_uuid}')>"


class Application(Base):
    """Application/Service catalog table"""
    __tablename__ = "applications"
    
    app_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    app_name = Column(String(255), unique=True, nullable=False, index=True)
    app_type = Column(String(100))
    description = Column(Text)
    owner_team = Column(String(255))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    mappings = relationship("ServerApplicationMap", back_populates="application", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Application(app_name='{self.app_name}', owner_team='{self.owner_team}')>"


class ServerApplicationMap(Base):
    """Server to Application mapping table"""
    __tablename__ = "server_application_map"
    
    mapping_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    server_id = Column(String(36), ForeignKey("servers.server_id", ondelete="CASCADE"), nullable=False, index=True)
    app_id = Column(String(36), ForeignKey("applications.app_id", ondelete="CASCADE"), nullable=False, index=True)
    confidence = Column(Enum(ConfidenceLevel), nullable=False, default=ConfidenceLevel.AUTO)
    source = Column(String(255))  # Source of mapping (e.g., "manual", "cmdb", "auto-detected")
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by = Column(String(255))
    
    # Relationships
    server = relationship("Server", back_populates="mappings")
    application = relationship("Application", back_populates="mappings")
    
    # Constraints
    __table_args__ = (
        UniqueConstraint("server_id", "app_id", name="uq_server_app"),
    )
    
    def __repr__(self):
        return f"<ServerApplicationMap(server_id='{self.server_id}', app_id='{self.app_id}', confidence='{self.confidence.value}')>"


class VendorProductRule(Base):
    """Vendor/Product detection rules table"""
    __tablename__ = "vendor_product_rules"
    
    rule_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vendor_name = Column(String(255), nullable=False, index=True)
    product_family = Column(String(255))
    regex_pattern = Column(Text)
    keyword = Column(String(255))
    priority = Column(Integer, default=0, index=True)  # Higher priority rules checked first
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_by = Column(String(255))
    
    def __repr__(self):
        return f"<VendorProductRule(vendor='{self.vendor_name}', product='{self.product_family}', priority={self.priority})>"


class PatchCatalogOverride(Base):
    """Manual overrides for patch vendor/product categorization"""
    __tablename__ = "patch_catalog_overrides"
    
    override_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    plugin_id = Column(String(50), index=True)
    cve = Column(String(50), index=True)
    vendor_override = Column(String(255))
    product_override = Column(String(255))
    reason = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_by = Column(String(255))
    
    def __repr__(self):
        return f"<PatchCatalogOverride(plugin_id='{self.plugin_id}', cve='{self.cve}')>"


class ReportRun(Base):
    """Report generation audit trail"""
    __tablename__ = "report_runs"
    
    run_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    filters_json = Column(JSON)  # Store filter criteria as JSON
    export_job_uuid = Column(String(255))
    total_vulns = Column(Integer)
    total_assets = Column(Integer)
    total_patches = Column(Integer)
    runtime_seconds = Column(Float)
    generated_by = Column(String(255))
    
    def __repr__(self):
        return f"<ReportRun(run_id='{self.run_id}', timestamp='{self.timestamp}', total_vulns={self.total_vulns})>"
