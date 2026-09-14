"""
SecureCode AI — FastAPI Backend Application.
Coordinates multilingual language-aware security scanning, local ML severity inference,
single-call external AI contextual review, and professional PDF report export.
Fully compatible with existing React frontend.
"""

import re
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Response, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from sqlalchemy.orm import Session

load_dotenv(override=True)

from database.database import get_db
from database.models import User, GuestTrial
from auth.security import create_guest_token, decode_guest_token
from auth.dependencies import get_current_user, get_optional_current_user
from language_detector import detect_language
from security_rules import scan_security
from ml_severity_model import predict_finding_severity, get_ml_engine
from ai_pipeline import analyze_security_with_ai
from hybrid_security_engine import (
    apply_ai_severity,
    merge_findings,
    calculate_severity_summary,
    calculate_security_score,
)
from pdf_generator import generate_security_pdf
from auth import auth_router


# =========================================================
# FASTAPI APP SETUP
# =========================================================

app = FastAPI(
    title="SecureCode AI API",
    description="AI-Powered Secure Code Review and Vulnerability Detection Platform",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Auth-Required", "X-Guest-Trial-Token"],
)

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])



# =========================================================
# REQUEST MODELS
# =========================================================

class CodeRequest(BaseModel):
    code: str
    file_name: str = "unknown"
    language: str = "unknown"


# =========================================================
# SYSTEM ENDPOINTS
# =========================================================

@app.get("/")
def root():
    return {
        "message": "SecureCode AI Backend is running",
        "version": "2.0.0",
    }


@app.get("/health")
def health():
    ml_engine = get_ml_engine()
    return {
        "status": "ok",
        "service": "SecureCode AI Backend",
        "ml_model_trained": ml_engine.is_trained,
        "languages_supported": 15,
    }


# =========================================================
# MAIN ANALYSIS ENDPOINT
# =========================================================

@app.post("/analyze")
def analyze_code(
    data: CodeRequest,
    request: Request,
    response: Response,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    # Validate non-empty code
    if not data.code or not data.code.strip():
        raise HTTPException(
            status_code=400,
            detail="Source code cannot be empty.",
        )

    # 0. ACCESS CONTROL & GUEST TRIAL ENFORCEMENT
    # Authenticated users have unlimited analyses.
    # Unauthenticated guests are permitted exactly 1 free analysis.
    guest_trial = None
    guest_id = None

    if current_user:
        print("[AUTH] Authenticated analysis allowed")
    else:
        # Check guest trial token from cookie OR custom request header
        guest_token = request.cookies.get("guest_trial_token") or request.headers.get("x-guest-trial-token")
        if guest_token:
            try:
                decoded = decode_guest_token(guest_token.strip())
                guest_id = decoded.get("sub")
                if guest_id:
                    guest_trial = db.query(GuestTrial).filter(GuestTrial.id == guest_id).first()
            except Exception:
                guest_id = None
                guest_trial = None

        # If guest has already completed their free analysis, block immediately
        # BEFORE language detection, security scanning, ML, or AI invocation!
        if guest_trial and guest_trial.analysis_count >= 1:
            print("[GUEST] Additional analysis blocked")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You've used your free security analysis. Sign in or create an account to continue analyzing code.",
                headers={"X-Auth-Required": "true"},
            )

        print("[GUEST] Free analysis allowed")
        if not guest_id:
            guest_id = str(uuid.uuid4())

    analysis_start = time.perf_counter()

    print("\n===================================")
    print("[API] Analyze request received")
    print("[API] File:", data.file_name)
    print("[API] Language hint:", data.language)

    # 1. LANGUAGE DETECTION
    language_result = detect_language(
        code=data.code,
        file_name=data.file_name,
        frontend_hint=data.language,
    )
    detected_language = language_result.get("language", "Unknown")
    print(f"[LANGUAGE] Detected: {detected_language} (Confidence: {language_result.get('confidence')}%)")

    # 2. STATIC LANGUAGE-AWARE SECURITY SCAN (15 Languages)
    engine_findings = scan_security(
        code=data.code,
        language=detected_language,
    )
    # Ensure sequential IDs on engine findings for 1-to-1 AI assessment alignment
    for idx, f in enumerate(engine_findings, start=1):
        if "id" not in f:
            f["id"] = idx
        if "finding_id" not in f:
            f["finding_id"] = idx

    print(f"[SECURITY ENGINE] Raw deterministic findings: {len(engine_findings)}")

    # 3. LOCAL ML SEVERITY INFERENCE
    ml_engine = get_ml_engine()
    ml_status = "model not trained yet / deterministic fallback active"
    if ml_engine.is_trained:
        ml_status = "trained_model_active"

    for finding in engine_findings:
        ml_pred = predict_finding_severity(finding, detected_language, data.code)
        finding["ml_severity"] = ml_pred.get("ml_severity")
        finding["ml_confidence"] = ml_pred.get("ml_confidence")
        finding["ml_probabilities"] = ml_pred.get("ml_probabilities")
        finding["ml_status"] = ml_pred.get("model_status")

    # 4. ONE UNIFIED AI SECURITY REVIEW CALL
    ai_result = analyze_security_with_ai(
        code=data.code,
        language=detected_language,
        engine_findings=engine_findings,
    )

    ai_findings = ai_result.get("ai_findings", [])
    severity_results = ai_result.get("severity_results", [])
    ai_status = ai_result.get("ai_status", "unavailable")

    # 5. APPLY AI ASSESSMENTS (WITH ML PRIMARY POLICY)
    assessed_engine_findings = apply_ai_severity(
        engine_findings=engine_findings,
        severity_results=severity_results,
    )

    # 6. DEDUPLICATE & MERGE ENGINE + NEW AI FINDINGS (WITH LOCAL ML INFERENCE ON AI FINDINGS)
    final_findings = merge_findings(
        engine_findings=assessed_engine_findings,
        ai_findings=ai_findings,
        language=detected_language,
        code=data.code,
    )

    # 7. EXACT DETERMINISTIC SEVERITY SUMMARY
    severity_counts = calculate_severity_summary(final_findings)

    # 8. DETERMINISTIC SECURITY SCORE
    security_score = calculate_security_score(final_findings)

    # 9. TIMING
    analysis_end = time.perf_counter()
    elapsed = analysis_end - analysis_start
    analysis_time_ms = round(elapsed * 1000, 2)
    analysis_time_seconds = round(elapsed, 4)

    print(f"[RESULT] Final Issues: {len(final_findings)} | Score: {security_score} | AI Status: {ai_status} | Time: {analysis_time_ms}ms")
    print("===================================\n")

    # 10. EXACT FRONTEND CONTRACT
    ai_insight = ai_result.get("security_insight") or ai_result.get("ai_security_insight") or {}
    ai_remediation = ai_result.get("remediation") or ai_result.get("ai_remediation") or {}
    ai_comparison = ai_result.get("comparison") or ai_result.get("ai_comparison") or {}
    secure_code = ai_result.get("secure_code", data.code)

    # 11. PERSIST GUEST TRIAL ONLY AFTER SUCCESSFUL ANALYSIS COMPLETION
    new_guest_token = None
    if not current_user and guest_id:
        now = datetime.now(timezone.utc)
        if not guest_trial:
            guest_trial = GuestTrial(
                id=guest_id,
                analysis_count=1,
                last_analyzed_at=now,
            )
            db.add(guest_trial)
        else:
            guest_trial.analysis_count += 1
            guest_trial.last_analyzed_at = now

        try:
            db.commit()
            print("[GUEST] Trial marked as used")
        except Exception as err:
            db.rollback()
            print(f"[GUEST TRIAL ERROR] Failed to record guest analysis: {err}")

        new_guest_token = create_guest_token(guest_id)
        response.set_cookie(
            key="guest_trial_token",
            value=new_guest_token,
            max_age=365 * 86400,
            httponly=True,
            samesite="lax",
            secure=False,
            path="/",
        )
        response.headers["X-Guest-Trial-Token"] = new_guest_token

    response_payload = {
        "status": "success",
        "file_name": data.file_name,
        "detected_language": detected_language,
        "language_confidence": language_result.get("confidence", 0),
        "language_status": language_result.get("status", "unknown"),
        "parser_passed": language_result.get("parser_passed", False),

        # Security Metrics
        "security_score": security_score,
        "issues_found": len(final_findings),
        "severity_counts": severity_counts,
        "vulnerabilities": final_findings,

        # AI Outputs
        "ai_security_insight": ai_insight,
        "ai_remediation": ai_remediation,
        "secure_code": secure_code,
        "ai_comparison": ai_comparison,

        # Metadata
        "analysis_time_ms": analysis_time_ms,
        "analysis_time_seconds": analysis_time_seconds,
        "code": data.code,

        # Supplementary Diagnostic Fields
        "ai_status": ai_status,
        "ml_status": ml_status,
        "model_used": ai_result.get("model_used", "N/A"),
    }

    if new_guest_token:
        response_payload["guest_trial_token"] = new_guest_token

    return response_payload


# =========================================================
# PDF REPORT EXPORT ENDPOINT
# =========================================================

@app.post("/reports/pdf")
def export_pdf_report(
    payload: Dict[str, Any],
    current_user: User = Depends(get_current_user),
):
    """
    Generates a professional application/pdf security report
    using the provided analysis results.
    Requires user authentication (JWT access token).
    Does NOT issue any external LLM calls.
    """
    if not payload:
        raise HTTPException(
            status_code=400,
            detail="Report payload cannot be empty.",
        )

    try:
        pdf_bytes = generate_security_pdf(payload)
        file_name = payload.get("file_name", "SecureCode-AI")
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", str(file_name))
        download_filename = f"{safe_name}-security-report.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{download_filename}"',
                "Content-Type": "application/pdf",
            },
        )
    except Exception as err:
        print(f"[PDF ERROR] Generation failed: {err}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF report: {str(err)}",
        )