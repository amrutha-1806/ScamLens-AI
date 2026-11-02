"""
SCAMLENS AI - FastAPI Backend Pydantic Schemas
"""

from __future__ import annotations
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class MessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="Text message to analyze")
    user_id: Optional[str] = Field(None, description="Optional authenticated user ID for scan isolation")


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL string to analyze (never fetched)")
    user_id: Optional[str] = Field(None, description="Optional authenticated user ID for scan isolation")


class EmailAnalysisRequest(BaseModel):
    sender: str = Field("", max_length=500, description="Email sender / From header")
    subject: str = Field("", max_length=1000, description="Email subject line")
    body: str = Field(..., min_length=1, max_length=50000, description="Email body text or content")
    user_id: Optional[str] = Field(None, description="Optional authenticated user ID for scan isolation")


class AlertReviewRequest(BaseModel):
    review_status: str = Field(..., description="Review status: unreviewed, reviewed, flagged_fp, investigating")
    review_notes: Optional[str] = Field(None, max_length=2000, description="Analyst triage / verification notes")
    user_id: Optional[str] = Field(None, description="Optional authenticated user ID verifying ownership")


class UserFeedbackRequest(BaseModel):
    scan_id: int = Field(..., description="Target scan ID")
    actual_label: str = Field(..., description="User perceived label: Legitimate or Scam/Phishing")
    user_comment: Optional[str] = Field("", max_length=1000, description="Optional comment")


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class AnalysisResponse(BaseModel):
    prediction: str
    risk_level: str
    risk_score: float
    risk_probability: float
    indicators: List[str]
    guidance: str
    model: str = "Random Forest"
    scan_id: Optional[int] = None
    timestamp: Optional[str] = None
    # Rich extensions for Explainable AI & Intelligence
    explainability: Optional[Dict[str, Any]] = None
    language_info: Optional[Dict[str, Any]] = None
    embedded_urls: Optional[List[Dict[str, Any]]] = None
    url_intelligence: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    status: str
    model: str


class ModelInfoResponse(BaseModel):
    model_name: str
    dataset: str
    feature_extraction: str
    supported_analysis_types: List[str]
    version: Optional[str] = "1.0.0"
    classes: Optional[List[str]] = ["Legitimate", "Scam/Phishing"]
    metrics: Optional[Dict[str, Any]] = None


class ScanRecord(BaseModel):
    id: int
    timestamp: str
    input_type: str
    content: str
    prediction_label: str
    # Alias so Lovable frontend (which uses 'prediction') also works
    prediction: str = ""
    scam_probability: float
    risk_probability: float = 0.0   # alias for scam_probability (matches AnalysisResponse)
    risk_score: float
    risk_level: str
    explanation_summary: Optional[str] = None
    indicators: List[str] = []      # empty list if not stored; matches AnalysisResponse
    model: str = "Random Forest"
    # Security Alert & Multi-user fields
    user_id: Optional[str] = None
    review_status: Optional[str] = "unreviewed"
    review_notes: Optional[str] = None
    reviewed_at: Optional[str] = None


class HistoryResponse(BaseModel):
    # Original shape kept for backward-compat
    count: int
    records: List[ScanRecord]
    # Aliases expected by many Lovable-generated frontends
    total: int = 0
    items: List[ScanRecord] = []


class AlertsResponse(BaseModel):
    count: int
    alerts: List[ScanRecord]
    unreviewed_count: int = 0
    high_count: int = 0
    very_high_count: int = 0


class BatchResultItem(BaseModel):
    id: str = ""
    timestamp: str = ""
    row_index: int
    input_type: str = "message"
    input_text: str
    input_preview: str = ""
    prediction: str
    risk_level: str
    risk_score: float
    risk_probability: float
    indicators: List[str]
    guidance: str = ""
    model: str = "Random Forest"
    scan_id: Optional[int] = None


class BatchResponse(BaseModel):
    total: int
    results: List[BatchResultItem]
    total_rows: int = 0
    processed_rows: int = 0
    failed_rows: int = 0
    selected_column: str = "text"
    errors: List[str] = []


class ErrorResponse(BaseModel):
    detail: str
