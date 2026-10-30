"""
SCAMLENS AI — FastAPI Backend Pydantic Schemas
"""

from __future__ import annotations
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class MessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="Text message to analyze")


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL string to analyze (never fetched)")


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


class HistoryResponse(BaseModel):
    # Original shape kept for backward-compat
    count: int
    records: List[ScanRecord]
    # Aliases expected by many Lovable-generated frontends
    total: int = 0
    items: List[ScanRecord] = []


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
