"""
SCAMLENS AI — FastAPI Backend
Exposes the existing Random Forest ML pipeline and static cybersecurity intelligence engines via REST APIs.

Start with:
    uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload

All ML inference is performed entirely offline using the trained model.
URLs are NEVER opened, fetched, or visited — they are analyzed as static strings only.
"""

from __future__ import annotations
import sys
import csv
import io
import re
import inspect
from datetime import datetime, timezone
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
    AlertsResponse,
    AlertReviewRequest,
    UserFeedbackRequest,
    MessageRequest,
    EmailAnalysisRequest,
    ModelInfoResponse,
    ScanRecord,
    UrlRequest,
    UrlResolveRequest,
    UpiInspectRequest,
)
from contextlib import asynccontextmanager
from backend.services.ml_service import analyze, _get_predictor
from backend.services.url_intelligence import analyze_url_static, calculate_url_risk_verdict
from backend.services.url_resolver import inspect_url_advanced
from backend.services.upi_service import inspect_upi_or_qr_payload
from backend.services.email_service import analyze_email_phishing
from src.utils.database import log_scan_result, init_db
from src.utils.logger import get_logger

logger = get_logger("API")
from backend.services.history_service import (
    get_history,
    get_alerts,
    update_alert,
    get_scan,
    save_feedback,
)
from backend.services.report_service import (
    generate_security_report_pdf,
    generate_incident_report_pdf,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Preload SQLite schema and Random Forest ML model once on server startup."""
    try:
        init_db()
        _get_predictor()
    except Exception as exc:
        logger.warning(f"Startup preload warning: {exc}")
    yield


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SCAMLENS AI API",
    description=(
        "REST API exposing the SCAMLENS AI Random Forest scam/phishing detection model "
        "and static cybersecurity intelligence engines. "
        "All inference is 100% offline. URLs are analyzed as static strings only — "
        "they are never opened, fetched, or visited."
    ),
    version="1.1.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS — allow local development origins, Lovable domains, Vercel deployments, and Private Network Access
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
    # Allow HTTPS origins from Lovable preview/production domains and Vercel deployments (*.vercel.app)
    # Strict regex matching prevents arbitrary external origins without using an insecure wildcard
    "allow_origin_regex": r"https://.*\.lovable\.(app|dev)|https://.*\.lovableproject\.com|https://.*\.vercel\.app",
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
        from backend.services.ml_service import _get_predictor
        _get_predictor()
        return HealthResponse(status="healthy", model="Random Forest")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Model unavailable: {exc}")


# ---------------------------------------------------------------------------
# Analyze — message (with Explainable AI & Multilingual Script Detection)
# ---------------------------------------------------------------------------
@app.post("/api/analyze/message", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_message(request: MessageRequest):
    """
    Classify a text message as Legitimate or Scam/Phishing.
    Includes token-level Explainable AI attributions and multilingual script checks.
    When sandbox_demo=True, skips SQLite scan history logging.
    """
    try:
        result = analyze(
            request.message,
            user_id=request.user_id,
            include_explainability=True,
            skip_logging=bool(request.sandbox_demo),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction engine error: {exc}")
    return AnalysisResponse(**result)


# ---------------------------------------------------------------------------
# Analyze — URL (Deep Static Intelligence, zero execution)
# ---------------------------------------------------------------------------
@app.post("/api/analyze/url", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_url(request: UrlRequest):
    """
    Analyze a URL string for scam/phishing risk using static structural heuristics.
    Derives risk score, probability, risk level, and prediction purely from static
    URL intelligence, bypassing the SMS-trained Random Forest model.

    SECURITY: The submitted URL is treated strictly as plain text.
    It is NEVER fetched, opened, resolved, crawled, or visited.
    """
    try:
        # 1. Static URL Intelligence Decomposition
        url_intel = analyze_url_static(request.url)
        if not url_intel.get("valid", True):
            raise HTTPException(status_code=422, detail=url_intel.get("error", "Malformed URL"))

        # 2. Derive Verdict from Static URL Intelligence (Decoupled from SMS Random Forest)
        verdict = calculate_url_risk_verdict(url_intel)

        # 3. Database Logging (Safe SQLite recording; skipped for sandbox demo runs)
        scan_id = None
        if not bool(request.sandbox_demo):
            try:
                preview = request.url[:80] + ("..." if len(request.url) > 80 else "")
                scan_id = log_scan_result(
                    input_type="url",
                    content=preview,
                    prediction_label=verdict["prediction"],
                    scam_probability=verdict["risk_probability"],
                    risk_score=verdict["risk_score"],
                    risk_level=verdict["risk_level"],
                    explanation_summary="; ".join(verdict["indicators"][:3]),
                    user_id=request.user_id,
                )
            except Exception as e:
                logger.warning(f"Database logging failed for URL: {e}")

        response_data = {
            "prediction": verdict["prediction"],
            "risk_level": verdict["risk_level"],
            "risk_score": verdict["risk_score"],
            "risk_probability": verdict["risk_probability"],
            "indicators": verdict["indicators"],
            "guidance": verdict["guidance"],
            "model": verdict["model"],
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url_intelligence": url_intel,
            "explainability": None,
            "language_info": None,
            "embedded_urls": None,
        }

    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"URL inspection error: {exc}")

    return AnalysisResponse(**response_data)


# ---------------------------------------------------------------------------
# Analyze — Advanced URL Redirect Resolution & Homograph Inspection (SSRF-Safe)
# ---------------------------------------------------------------------------
@app.post("/api/analyze/url/resolve", tags=["Analysis"])
def resolve_url_advanced(request: UrlResolveRequest):
    """
    Safely inspect a URL for lookalike character substitutions, punycode/IDN homographs,
    shorteners, and (when enabled) trace HTTP/HTTPS redirects with strict SSRF and
    DNS-rebinding protection (no body content downloaded, max 5 hops, 2.5s timeout).
    Never claims a URL is safe just because no warning was detected.
    """
    try:
        return inspect_url_advanced(request.url, resolve_redirects=request.resolve_redirects)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Advanced URL inspection error: {exc}")


# ---------------------------------------------------------------------------
# Analyze — QR Code & UPI Payment Safety Checker
# ---------------------------------------------------------------------------
@app.post("/api/analyze/upi", tags=["Analysis"])
def analyze_upi_payload(request: UpiInspectRequest):
    """
    Inspect a UPI ID (username@handle) or decoded QR payment URI (upi://pay?...)
    for deceptive lures, handle typos, pre-filled debit amounts, and auto-debit mandates.
    Never initiates payments, never claims recipient verification, and does not log personal payment strings.
    """
    try:
        result = inspect_upi_or_qr_payload(request.payload, source_type=request.source_type)
        if not result.get("valid", True) and result.get("error"):
            raise HTTPException(status_code=422, detail=result["error"])
        return result
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"UPI inspection error: {exc}")


# ---------------------------------------------------------------------------
# Analyze — Email Phishing (Header, Spoofing, Multi-link, Body)
# ---------------------------------------------------------------------------
@app.post("/api/analyze/email", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze an email for phishing, credential theft, and display name spoofing.
    Includes sender header analysis, static URL inspection, and Explainable AI.
    """
    try:
        result = analyze_email_phishing(
            sender=request.sender,
            subject=request.subject,
            body=request.body,
            user_id=request.user_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email analysis error: {exc}")

    return AnalysisResponse(
        prediction=result["prediction"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        risk_probability=result["risk_probability"],
        indicators=result["indicators"],
        guidance=result["guidance"],
        model=result["model"],
        scan_id=result.get("scan_id"),
        timestamp=result.get("timestamp"),
        explainability=result.get("explainability"),
        language_info=result.get("language_info"),
        embedded_urls=result.get("embedded_urls"),
    )


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
            or lower_map.get("url")
            or lower_map.get("link")
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
            # Determine if this row represents a URL or a text message
            explicit_type = str(row.get("type") or row.get("input_type") or row.get("channel") or "").strip().lower()
            if explicit_type in ("url", "link"):
                is_url = True
            elif explicit_type in ("message", "text", "sms", "email"):
                is_url = False
            elif text_col.lower().strip() in ("url", "link"):
                is_url = True
            else:
                is_url = (
                    input_text.lower().startswith(("http://", "https://"))
                    or bool(re.match(r"^www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", input_text.lower()))
                )

            preview = input_text[:120] + ("…" if len(input_text) > 120 else "")
            row_user_id = str(row.get("user_id") or "").strip() or None

            if is_url:
                url_intel = analyze_url_static(input_text)
                if not url_intel.get("valid", True):
                    errors.append(f"Row {idx + 1}: invalid URL format — {url_intel.get('error', 'Malformed URL')}")
                    continue
                verdict = calculate_url_risk_verdict(url_intel)

                scan_id = None
                try:
                    scan_id = log_scan_result(
                        input_type="url",
                        content=preview,
                        prediction_label=verdict["prediction"],
                        scam_probability=verdict["risk_probability"],
                        risk_score=verdict["risk_score"],
                        risk_level=verdict["risk_level"],
                        explanation_summary="; ".join(verdict["indicators"][:3]),
                        user_id=row_user_id,
                    )
                except Exception as e:
                    logger.warning(f"Database logging failed for batch URL row: {e}")

                results.append(BatchResultItem(
                    id=str(scan_id or (idx + 1)),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    row_index=idx,
                    input_type="url",
                    input_text=preview,
                    input_preview=preview,
                    prediction=verdict["prediction"],
                    risk_level=verdict["risk_level"],
                    risk_score=verdict["risk_score"],
                    risk_probability=verdict["risk_probability"],
                    indicators=verdict["indicators"],
                    guidance=verdict.get("guidance", ""),
                    model=verdict.get("model", "Static URL Heuristic Engine"),
                    scan_id=scan_id,
                ))
            else:
                r = analyze(input_text, user_id=row_user_id, include_explainability=False)
                results.append(BatchResultItem(
                    id=str(r.get("scan_id") or (idx + 1)),
                    timestamp=str(r.get("timestamp", "")),
                    row_index=idx,
                    input_type="message",
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
# Scan history & Security Alert Center
# ---------------------------------------------------------------------------
@app.get("/api/history", response_model=HistoryResponse, tags=["History"])
def scan_history(
    limit: int = Query(default=100, ge=1, le=500),
    user_id: Optional[str] = Query(default=None, description="Optional user ID filter")
):
    """Return recent scan records from the SQLite database."""
    try:
        records = get_history(limit=limit, user_id=user_id)
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
                prediction=pred_label,
                scam_probability=float(r.get("scam_probability", 0.0)),
                risk_probability=float(r.get("scam_probability", 0.0)),
                risk_score=float(r.get("risk_score", 0.0)),
                risk_level=r.get("risk_level", ""),
                explanation_summary=r.get("explanation_summary"),
                indicators=[],
                model="Random Forest",
                user_id=r.get("user_id"),
                review_status=r.get("review_status", "unreviewed"),
                review_notes=r.get("review_notes"),
                reviewed_at=str(r.get("reviewed_at", "")) if r.get("reviewed_at") else None,
            ))
        except Exception:
            continue

    return HistoryResponse(
        count=len(scan_records),
        records=scan_records,
        total=len(scan_records),
        items=scan_records,
    )


@app.get("/api/alerts", response_model=AlertsResponse, tags=["Alerts"])
def security_alerts(
    status: Optional[str] = Query(default="all", description="all | unreviewed | reviewed | flagged_fp | investigating"),
    limit: int = Query(default=50, ge=1, le=200),
    user_id: Optional[str] = Query(default=None, description="Optional user ID filter")
):
    """
    Return high-risk detections for the Security Alert Center.
    Enables analysts to triage, review, and add notes to suspicious incidents.
    """
    try:
        records = get_alerts(limit=limit, status_filter=status, user_id=user_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")

    alert_records: List[ScanRecord] = []
    unreviewed = 0
    high = 0
    very_high = 0

    for r in records:
        try:
            pred_label = r.get("prediction_label", "")
            rlevel = r.get("risk_level", "")
            rstatus = r.get("review_status", "unreviewed")

            if rstatus == "unreviewed":
                unreviewed += 1
            if rlevel == "High":
                high += 1
            elif rlevel == "Very High":
                very_high += 1

            alert_records.append(ScanRecord(
                id=r["id"],
                timestamp=str(r.get("timestamp", "")),
                input_type=r.get("input_type", "text"),
                content=r.get("content", ""),
                prediction_label=pred_label,
                prediction=pred_label,
                scam_probability=float(r.get("scam_probability", 0.0)),
                risk_probability=float(r.get("scam_probability", 0.0)),
                risk_score=float(r.get("risk_score", 0.0)),
                risk_level=rlevel,
                explanation_summary=r.get("explanation_summary"),
                indicators=[],
                model="Random Forest",
                user_id=r.get("user_id"),
                review_status=rstatus,
                review_notes=r.get("review_notes"),
                reviewed_at=str(r.get("reviewed_at", "")) if r.get("reviewed_at") else None,
            ))
        except Exception:
            continue

    return AlertsResponse(
        count=len(alert_records),
        alerts=alert_records,
        unreviewed_count=unreviewed,
        high_count=high,
        very_high_count=very_high,
    )


@app.post("/api/alerts/{scan_id}/review", tags=["Alerts"])
def review_alert(scan_id: int, request: AlertReviewRequest):
    """
    Update the triage status and analyst notes for a high-risk security alert.
    """
    try:
        success = update_alert(
            scan_id=scan_id,
            review_status=request.review_status,
            review_notes=request.review_notes,
            user_id=request.user_id
        )
        if not success:
            raise HTTPException(status_code=404, detail=f"Alert with ID {scan_id} not found or unauthorized.")
        return {"success": True, "scan_id": scan_id, "review_status": request.review_status}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database update failed: {exc}")


@app.post("/api/feedback", tags=["History"])
def submit_feedback(request: UserFeedbackRequest):
    """Submit user verification feedback on a model scan."""
    try:
        fb_id = save_feedback(
            scan_id=request.scan_id,
            actual_label=request.actual_label,
            user_comment=request.user_comment or ""
        )
        return {"status": "recorded", "feedback_id": fb_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Feedback recording failed: {exc}")


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
                    "unit": "% (accuracy/precision/recall/f1); score 0-1 (roc_auc)",
                }
        except Exception:
            pass

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
        version="1.1.0",
        classes=["Legitimate", "Scam/Phishing"],
        metrics=metrics if metrics else None,
    )


# ---------------------------------------------------------------------------
# Security Reports & Incident PDF Generation
# ---------------------------------------------------------------------------
@app.get("/api/reports/pdf", tags=["Reports"])
def export_report_pdf(
    scope: str = Query(default="all", description="all | scam | legitimate | high_risk | message | url"),
    days: int = Query(default=0, ge=0, le=3650, description="0 = All time, or last N days"),
    limit: int = Query(default=250, ge=1, le=500),
    user_id: Optional[str] = Query(default=None)
):
    """
    Generate a multi-page PDF Security Analysis Report from real SQLite scan history.
    """
    from datetime import datetime, timedelta

    try:
        records = get_history(limit=limit, user_id=user_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}")

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


@app.get("/api/reports/incident-pdf/{scan_id}", tags=["Reports"])
def export_incident_pdf(
    scan_id: int,
    user_id: Optional[str] = Query(default=None)
):
    """
    Generate a 1-page formal security incident forensic dossier for a specific scan.
    """
    scan_record = get_scan(scan_id=scan_id, user_id=user_id)
    if not scan_record:
        raise HTTPException(status_code=404, detail=f"Incident scan ID {scan_id} not found or unauthorized.")

    try:
        pdf_bytes = generate_incident_report_pdf(scan_record)
        filename = f"SCAMLENS_Incident_SL{scan_id:06d}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Incident report generation failed: {exc}")
