from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class EvidenceType(str, Enum):
    CONFIGURATION = "configuration"
    LOG = "log"
    SCREENSHOT = "screenshot"
    DOCUMENT = "document"
    OTHER = "other"

class ComplianceLevel(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non-compliant"
    PARTIAL = "partial"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

class EvidenceSubmission(BaseModel):
    control_id: str = Field(..., description="NIST control ID (e.g., AC-2, AU-3)")
    evidence_type: EvidenceType
    evidence_data: str = Field(..., description="Base64 encoded evidence content")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    assessor_id: Optional[str] = Field(None, description="ID of the person submitting evidence")

class Finding(BaseModel):
    requirement: str
    status: ComplianceLevel
    explanation: str
    evidence_references: List[str] = Field(default_factory=list)

class Recommendation(BaseModel):
    priority: str = Field(..., description="high/medium/low")
    action: str
    rationale: str

class EvaluationResult(BaseModel):
    evaluation_id: str
    control_id: str
    overall_compliance: ComplianceLevel
    compliance_score: float = Field(..., ge=0.0, le=1.0, description="0.0 to 1.0")
    confidence_level: float = Field(..., ge=0.0, le=1.0, description="AI confidence in evaluation")
    findings: List[Finding]
    recommendations: List[Recommendation]
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    processing_time_seconds: float

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    error_details: Optional[Dict[str, Any]] = None

class ControlInfo(BaseModel):
    control_id: str
    title: str
    description: str
    family: str
    baseline_levels: List[str]

class EvidenceSearchQuery(BaseModel):
    control_id: Optional[str] = None
    assessor_id: Optional[str] = None
    compliance_level: Optional[ComplianceLevel] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=1000)