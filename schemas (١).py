"""
Pydantic Schemas for Request/Response
"""
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# ==================== USER & AUTH ====================

class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# ==================== INVESTIGATION ====================

class InvestigationCreate(BaseModel):
    title: str
    description: Optional[str] = None

class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None

class InvestigationResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    created_by: int
    created_at: datetime
    updated_at: datetime
    status: Optional[str] = "pending"
    agent_logs: Optional[List[Dict[str, Any]]] = None
    entities: List['EntityResponse'] = []
    
    class Config:
        from_attributes = True

# ==================== ENTITY ====================

class EntityType(str, Enum):
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

class EntityCreate(BaseModel):
    type: EntityType
    value: str
    label: Optional[str] = None
    description: Optional[str] = None
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None

class EntityUpdate(BaseModel):
    label: Optional[str] = None
    description: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None

class EntityResponse(BaseModel):
    id: int
    type: EntityType
    value: str
    label: Optional[str]
    description: Optional[str]
    confidence: float
    first_seen: datetime
    last_seen: datetime
    metadata: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

# ==================== RELATIONSHIPS ====================

class RelationshipType(str, Enum):
    associated_with = "associated_with"
    communicates_with = "communicates_with"
    located_at = "located_at"
    owns = "owns"
    operates = "operates"
    targets = "targets"
    hosts = "hosts"
    used_by = "used_by"
    related_to = "related_to"

class EntityRelationshipCreate(BaseModel):
    source_id: int
    target_id: int
    relationship_type: RelationshipType
    weight: float = 0.5
    confidence: float = 0.5
    metadata: Optional[Dict[str, Any]] = None

class EntityRelationshipResponse(BaseModel):
    id: int
    source_id: int
    target_id: int
    relationship_type: RelationshipType
    weight: float
    confidence: float
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    cooccurrence_count: int
    
    class Config:
        from_attributes = True

# ==================== THREATS ====================

class ThreatSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class ThreatIndicatorCreate(BaseModel):
    indicator_type: str
    indicator_value: str
    severity: ThreatSeverity
    description: str
    confidence: float = 0.5
    metadata: Optional[Dict[str, Any]] = None

class ThreatIndicatorResponse(BaseModel):
    id: int
    indicator_type: str
    indicator_value: str
    severity: ThreatSeverity
    description: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    
    class Config:
        from_attributes = True

# ==================== TIMELINE ====================

class TimelineEventCreate(BaseModel):
    timestamp: datetime
    event_type: str
    summary: str
    description: Optional[str] = None
    source_entity_id: Optional[int] = None
    target_entity_id: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

class TimelineEventResponse(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    summary: str
    description: Optional[str]
    source_entity_id: Optional[int]
    target_entity_id: Optional[int]
    
    class Config:
        from_attributes = True

# ==================== GRAPH ====================

class GraphNode(BaseModel):
    id: int
    type: str
    label: str
    value: str

class GraphLink(BaseModel):
    source: int
    target: int
    relationship_type: str
    weight: float

class GraphDataResponse(BaseModel):
    nodes: List[GraphNode]
    links: List[GraphLink]

# ==================== ENRICHMENT ====================

class EntityEnrichmentResponse(BaseModel):
    id: int
    source: str
    enrichment_type: str
    value: Dict[str, Any]
    confidence: float
    created_at: datetime
    
    class Config:
        from_attributes = True

# Update forward references
InvestigationResponse.update_forward_refs()
