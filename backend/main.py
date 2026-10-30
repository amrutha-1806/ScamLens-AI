"""
SCAMLENS AI — FastAPI Backend
Exposes the existing Random Forest ML pipeline via a REST API.

Start with:
    uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

All ML inference is performed entirely offline using the existing trained model.
URLs are NEVER opened, fetched, or visited — they are analyzed as static strings only.
"""

from __future__ import annotations
import sys
import csv
import io
import inspect
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Query, Form
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware

# Ensure project root on path before importing project modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.schemas import (
    AnalysisResponse,
    BatchResponse,
    BatchResultItem,
    HealthResponse,
    HistoryResponse,
    MessageRequest,
    ModelInfoResponse,
    ScanRecord,
    UrlRequest,
)
from backend.services.ml_service import analyze
from backend.services.history_service import get_history
from backend.services.report_service import generate_security_report_pdf

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SCAMLENS AI API",
    description=(
        "REST API exposing the SCAMLENS AI Random Forest scam/phishing detection model. "
        "All inference is 100% offline. URLs are analyzed as static strings only — "
        "they are never opened or visited."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# CORS — allow local development origins, Lovable domains, and Private Network Access
# ---------------------------------------------------------------------------
cors_kwargs = {
    "allow_origins": [
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:4173",
        "http://localhost:8080",
        "http://localhost:8501",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:4173",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8001",
        "http://127.0.0.1:8080",
    ],
    "allow_origin_regex": r"https://.*\.lovable\.(app|dev)|https://.*\.lovableproject\.com",
    "allow_credentials": True,
    "allow_methods": ["*"],
    "allow_headers": ["*"],
}

# Enable Private Network Access if supported by installed Starlette version
if "allow_private_network" in inspect.signature(CORSMiddleware.__init__).parameters:
    cors_kwargs["allow_private_network"] = True

app.add_middleware(CORSMiddleware, **cors_kwargs)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse, tags=["System"])
def health_check():
    """Check whether the API and ML model are ready."""
    try:
        # Trigger predictor load to verify model is accessible
        from backend.services.ml_service import _get_predictor
        _get_predictor()
        return HealthResponse(status="healthy", model="Random Forest")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Model not ready: {exc}")


# ---------------------------------------------------------------------------
# Analyze — message
# ---------------------------------------------------------------------------
@app.post("/api/analyze/message", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_message(request: MessageRequest):
    """
    Classify a text message as Legitimate or Scam/Phishing.
    Uses the existing offline Random Forest model and FeatureExtractor.
    """
    try:
        result = analyze(request.message)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction engine error: {exc}")
    return AnalysisResponse(**result)


# ---------------------------------------------------------------------------
# Analyze — URL (NEVER opened or fetched — static string only)
# ---------------------------------------------------------------------------
@app.post("/api/analyze/url", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_url(request: UrlRequest):
    """
    Analyze a URL string for scam/phishing risk.

    SECURITY: The submitted URL is treated as plain text.
    It is NEVER fetched, opened, resolved, crawled, or visited.
    The analysis is purely static: URL structure + ML model features.
    """
    try:
        result = analyze(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction engine error: {exc}")
    return AnalysisResponse(**result)


# ---------------------------------------------------------------------------
# Analyze — batch CSV upload
# ---------------------------------------------------------------------------
@app.post("/api/analyze/batch", response_model=BatchResponse, tags=["Analysis"])
async def analyze_batch(
    file: UploadFile = File(...),
    column: Optional[str] = Form(default=None),
):
    """
    Analyze a CSV file containing messages or URLs.

    Expected CSV format: one column named 'text' (or the user-selected column / first column).
    Returns real ML predictions for every row — no fabricated results.
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files (.csv) are accepted.")

    raw_bytes = await file.read()
    if len(raw_bytes) > 5_000_000:
        raise HTTPException(status_code=400, detail="CSV file exceeds the 5 MB limit.")
    if not raw_bytes.strip():
        raise HTTPException(status_code=400, detail="CSV file is empty.")

    try:
        content = raw_bytes.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {exc}")

    fieldnames = [f for f in (reader.fieldnames or []) if f is not None and f.strip() != ""]
    if not fieldnames:
        raise HTTPException(status_code=400, detail="No valid header columns found in CSV.")

    if not rows:
        raise HTTPException(status_code=400, detail="CSV file contains headers but no data rows.")

    # Determine which column contains the text
    if column and column in fieldnames:
        text_col = column
    else:
        lower_map = {f.lower().strip(): f for f in fieldnames}
        text_col = (
            lower_map.get("text")
            or lower_map.get("message")
            or lower_map.get("content")
            or lower_map.get("sms")
            or lower_map.get("email")
            or fieldnames[0]
        )

    results: List[BatchResultItem] = []
    errors: List[str] = []

    for idx, row in enumerate(rows):
        raw_val = row.get(text_col, "")
        input_text = str(raw_val if raw_val is not None else "").strip()
        if not input_text:
            errors.append(f"Row {idx + 1}: empty value in column '{text_col}' — skipped.")
            continue
        try:
            r = analyze(input_text)
            preview = input_text[:120] + ("…" if len(input_text) > 120 else "")
            input_type = "url" if input_text.lower().startswith(("http://", "https://")) else "message"
            results.append(BatchResultItem(
                id=str(r.get("scan_id") or (idx + 1)),
                timestamp=str(r.get("timestamp", "")),
                row_index=idx,
                input_type=input_type,
                input_text=preview,
                input_preview=preview,
                prediction=r["prediction"],
                risk_level=r["risk_level"],
                risk_score=r["risk_score"],
                risk_probability=r["risk_probability"],
                indicators=r["indicators"],
                guidance=r.get("guidance", ""),
                model=r.get("model", "Random Forest"),
                scan_id=r.get("scan_id"),
            ))
        except Exception as exc:
            errors.append(f"Row {idx + 1}: prediction failed — {exc}")

    return BatchResponse(
        total=len(results),
        results=results,
        total_rows=len(rows),
        processed_rows=len(results),
        failed_rows=len(errors),
        selected_column=text_col,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------
@app.get("/api/history", response_model=HistoryResponse, tags=["History"])
def scan_history(limit: int = Query(default=100, ge=1, le=500)):
    """Return recent scan records from the existing SQLite database."""
    try:
        records = get_history(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")

    scan_records = []
    for r in records:
        try:
            pred_label = r.get("prediction_label", "")
            scan_records.append(ScanRecord(
                id=r["id"],
                timestamp=str(r.get("timestamp", "")),
                input_type=r.get("input_type", "text"),
                content=r.get("content", ""),
                prediction_label=pred_label,
                prediction=pred_label,                          # alias
                scam_probability=float(r.get("scam_probability", 0.0)),
                risk_probability=float(r.get("scam_probability", 0.0)),  # alias
                risk_score=float(r.get("risk_score", 0.0)),
                risk_level=r.get("risk_level", ""),
                explanation_summary=r.get("explanation_summary"),
                indicators=[],  # not stored per-row; empty list is correct
            ))
        except Exception:
            continue

    return HistoryResponse(
        count=len(scan_records),
        records=scan_records,
        total=len(scan_records),     # alias field
        items=scan_records,          # alias field
    )


# ---------------------------------------------------------------------------
# Model info
# ---------------------------------------------------------------------------
@app.get("/api/model-info", response_model=ModelInfoResponse, tags=["System"])
def model_info():
    """
    Return factual information about the trained model.
    All metrics are read from the real evaluation report — nothing is invented.
    """
    import json
    import pandas as pd

    metrics: dict = {}

    # Read real metrics from model_comparison.csv
    csv_path = PROJECT_ROOT / "reports" / "model_results" / "model_comparison.csv"
    if csv_path.exists():
        try:
            df = pd.read_csv(csv_path)
            rf_row = df[df["model"].str.lower().str.replace(" ", "_") == "random_forest"]
            if not rf_row.empty:
                row = rf_row.iloc[0]
                metrics = {
                    "accuracy":  round(float(row.get("accuracy",  0)) * 100, 2),
                    "precision": round(float(row.get("precision", 0)) * 100, 2),
                    "recall":    round(float(row.get("recall",    0)) * 100, 2),
                    "f1_score":  round(float(row.get("f1_score",  0)) * 100, 2),
                    "macro_f1":  round(float(row.get("macro_f1",  0)) * 100, 2),
                    "roc_auc":   round(float(row.get("roc_auc",   0)), 4),
                    "unit": "%% (accuracy/precision/recall/f1); score 0-1 (roc_auc)",
                }
        except Exception:
            pass

    # Read metadata if available
    meta_path = PROJECT_ROOT / "saved_models" / "model_metadata.json"
    if meta_path.exists():
        try:
            with open(meta_path) as f:
                meta = json.load(f)
            metrics["training_samples"] = meta.get("train_samples", meta.get("training_samples", "N/A"))
            metrics["test_samples"]     = meta.get("test_samples", "N/A")
            metrics["total_samples"]    = meta.get("total_samples", "N/A")
        except Exception:
            pass

    return ModelInfoResponse(
        model_name="Random Forest Classifier (Class-Balanced)",
        dataset="UCI SMS Spam Collection - 5,574 labelled SMS messages",
        feature_extraction=(
            "TF-IDF word n-grams (5,000 features) + "
            "TF-IDF character n-grams (5,000 features) + "
            "43 statistical/URL lexical features = 10,043 total features"
        ),
        supported_analysis_types=["text message", "email text", "URL (static string only)"],
        version="1.0.0",
        classes=["Legitimate", "Scam/Phishing"],
        metrics=metrics if metrics else None,
    )


# ---------------------------------------------------------------------------
# Security Report PDF Generation
# ---------------------------------------------------------------------------
@app.get("/api/reports/pdf", tags=["Reports"])
def export_report_pdf(
    scope: str = Query(default="all", description="all | scam | legitimate | high_risk | message | url"),
    days: int = Query(default=0, ge=0, le=3650, description="0 = All time, or last N days"),
    limit: int = Query(default=250, ge=1, le=500),
):
    """
    Generate a multi-page PDF Security Analysis Report from real SQLite scan history.
    """
    from datetime import datetime, timedelta

    try:
        records = get_history(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")

    # Filter by date window if days > 0
    if days > 0:
        cutoff = datetime.now() - timedelta(days=days)
        filtered_by_date = []
        for r in records:
            ts_str = str(r.get("timestamp", "")).strip()
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", ""))
                if dt >= cutoff:
                    filtered_by_date.append(r)
            except Exception:
                filtered_by_date.append(r)
        records = filtered_by_date
        date_label = f"Last {days} Days"
    else:
        date_label = "All Time"

    # Filter by scope
    scope_norm = scope.lower().strip()
    scope_labels = {
        "all": "All Scans",
        "scam": "Scam / Phishing Only",
        "legitimate": "Legitimate Only",
        "high_risk": "High & Very High Risk",
        "message": "Text Messages Only",
        "url": "URLs Only",
    }
    scope_label = scope_labels.get(scope_norm, "All Scans")

    if scope_norm == "scam":
        records = [r for r in records if "scam" in str(r.get("prediction_label", "")).lower()]
    elif scope_norm == "legitimate":
        records = [r for r in records if "legit" in str(r.get("prediction_label", "")).lower()]
    elif scope_norm == "high_risk":
        records = [r for r in records if r.get("risk_level") in ("High", "Very High")]
    elif scope_norm == "message":
        records = [r for r in records if str(r.get("input_type", "")).lower() != "url"]
    elif scope_norm == "url":
        records = [r for r in records if str(r.get("input_type", "")).lower() == "url"]

    pdf_bytes = generate_security_report_pdf(
        records=records,
        scope_label=scope_label,
        date_range_label=date_label,
    )
    filename = f"SCAMLENS_AI_Report_{scope_norm}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
