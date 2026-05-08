from pydantic import BaseModel, Field, validator
from typing import Dict, Any, List, Optional
import re

class StrictAgentCheckIn(BaseModel):
    agent_id: str = Field(..., min_length=4, max_length=64, description="Unique Agent ID")
    data: str = Field(..., description="Encrypted payload")

    @validator("agent_id")
    def validate_agent_id(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Agent ID must be alphanumeric (dash/underscore allowed)")
        return v

class CommandRequest(BaseModel):
    agent_id: str = Field(..., min_length=4, max_length=64)
    command: str = Field(..., min_length=1, max_length=1024)

    @validator("command")
    def chaos_check(cls, v):
        # Basic sanity check to prevent obvious accidental destruction commands if needed
        # For a C2, we generally allow everything, but let's block 'rm -rf /' on the server itself via command injection
        # valid for agent execution though.
        return v

class EvidenceUpload(BaseModel):
    data: str = Field(..., description="Encrypted evidence payload")

class ConsultationRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=500, description="Strategic query for the AI")

class AutonomyRequest(BaseModel):
    enabled: bool
