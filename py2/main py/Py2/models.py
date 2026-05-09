"""
SQLAlchemy Models
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, Table, Enum
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum
from core.database import Base

# Association table for many-to-many relationships
investigation_entities = Table(
    'investigation_entities',
    Base.metadata,
    Column('investigation_id', Integer, ForeignKey('investigations.id')),
    Column('entity_id', Integer, ForeignKey('entities.id'))
)

class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(Enum(UserRole), default=UserRole.viewer)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    investigations = relationship("Investigation", back_populates="created_by_user")
    
    def __repr__(self):
        return f"<User {self.username}>"

class Investigation(Base):
    __tablename__ = "investigations"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    created_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    status = Column(String, default="pending")  # pending, running, completed, failed
    agent_logs = Column(Text, nullable=True)     # JSON string of agent steps
    
    # Relationships
    created_by_user = relationship("User", back_populates="investigations")
    entities = relationship("Entity", secondary=investigation_entities, back_populates="investigations")
    relationships = relationship("EntityRelationship", back_populates="investigation")
    timeline_events = relationship("TimelineEvent", back_populates="investigation")
    threat_indicators = relationship("ThreatIndicator", back_populates="investigation")
    
    def __repr__(self):
        return f"<Investigation {self.title}>"

class EntityType(str, enum.Enum):
    person = "person"
    organization = "organization"
    domain = "domain"
    ip_address = "ip_address"
    email = "email"
    phone = "phone"
    file_hash = "file_hash"
    url = "url"
    certificate = "certificate"
    location = "location"

class Entity(Base):
    __tablename__ = "entities"
    
    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum(EntityType), index=True)
    value = Column(String, unique=True, index=True)
    label = Column(String)
    description = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Custom metadata (JSON stored as Text)
    meta_data = Column(Text, nullable=True)  # JSON string
    
    # Relationships
    investigations = relationship("Investigation", secondary=investigation_entities, back_populates="entities")
    relationships_from = relationship("EntityRelationship", foreign_keys="EntityRelationship.source_id", back_populates="source")
    relationships_to = relationship("EntityRelationship", foreign_keys="EntityRelationship.target_id", back_populates="target")
    enrichment_data = relationship("EntityEnrichment", back_populates="entity")
    
    def __repr__(self):
        return f"<Entity {self.type}:{self.value}>"

class RelationshipType(str, enum.Enum):
    associated_with = "associated_with"
    communicates_with = "communicates_with"
    located_at = "located_at"
    owns = "owns"
    operates = "operates"
    targets = "targets"
    hosts = "hosts"
    used_by = "used_by"
    related_to = "related_to"

class EntityRelationship(Base):
    __tablename__ = "entity_relationships"
    
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey('investigations.id'))
    source_id = Column(Integer, ForeignKey('entities.id'))
    target_id = Column(Integer, ForeignKey('entities.id'))
    relationship_type = Column(Enum(RelationshipType))
    weight = Column(Float, default=0.5)
    confidence = Column(Float, default=0.5)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    cooccurrence_count = Column(Integer, default=1)
    meta_data = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    investigation = relationship("Investigation", back_populates="relationships")
    source = relationship("Entity", foreign_keys=[source_id], back_populates="relationships_from")
    target = relationship("Entity", foreign_keys=[target_id], back_populates="relationships_to")
    
    def __repr__(self):
        return f"<Relationship {self.source_id} -> {self.target_id}>"

class ThreatSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey('investigations.id'))
    indicator_type = Column(String)  # C2, DGA, FastFlux, etc.
    indicator_value = Column(String)
    severity = Column(Enum(ThreatSeverity), default=ThreatSeverity.medium)
    description = Column(Text)
    confidence = Column(Float, default=0.5)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    meta_data = Column(Text, nullable=True)  # JSON string
    
    investigation = relationship("Investigation", back_populates="threat_indicators")

class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey('investigations.id'))
    timestamp = Column(DateTime, index=True)
    event_type = Column(String)  # access, payload, execution, persistence, c2, etc.
    summary = Column(String)
    description = Column(Text, nullable=True)
    source_entity_id = Column(Integer, ForeignKey('entities.id'), nullable=True)
    target_entity_id = Column(Integer, ForeignKey('entities.id'), nullable=True)
    meta_data = Column(Text, nullable=True)  # JSON string
    
    investigation = relationship("Investigation", back_populates="timeline_events")

class EntityEnrichment(Base):
    __tablename__ = "entity_enrichments"
    
    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(Integer, ForeignKey('entities.id'))
    source = Column(String)  # VirusTotal, AbuseIPDB, GeoIP, etc.
    enrichment_type = Column(String)  # reputation, location, whois, etc.
    value = Column(Text)  # JSON data
    confidence = Column(Float, default=0.5)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    entity = relationship("Entity", back_populates="enrichment_data")

class ApiKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String)
    key_hash = Column(String, unique=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used = Column(DateTime, nullable=True)
