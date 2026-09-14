"""
Hybrid Security Engine.
Resolves final severity with ML as primary classifier and LLM as contextual advisor,
preserves authoritative deterministic evidence, deduplicates findings, calculates
exact severity summaries, and computes formulaic security scores.
"""

from typing import List, Dict, Any, Optional
from ml_severity_model import predict_finding_severity

SEVERITY_PENALTY = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 4,
}

EVIDENCE_LEVEL_WEIGHTS = {
    "CONFIRMED": 1.0,
    "data_flow_confirmed": 1.0,
    "buffer_overflow_confirmed": 1.0,
    "buffer_overflow_risk_confirmed": 0.95,
    "hardcoded_secret_confirmed": 0.95,
    "HIGH_CONFIDENCE": 0.85,
    "HEURISTIC": 0.70,
}


def normalize_type(name: str) -> str:
    return str(name or "").lower().replace("-", " ").replace("_", " ").strip()


def same_finding(first: Dict[str, Any], second: Dict[str, Any]) -> bool:
    """Checks whether two findings represent the same vulnerability."""
    first_type = normalize_type(first.get("type"))
    second_type = normalize_type(second.get("type"))

    aliases = {
        "cross site scripting (xss)": "xss",
        "cross site scripting": "xss",
        "reflected cross site scripting": "xss",
        "stored cross site scripting": "xss",
        "dom xss": "xss",
        "dom based xss": "xss",
        "path traversal": "path traversal",
        "directory traversal": "path traversal",
        "buffer overflow risk": "buffer overflow",
        "unsafe input / buffer overflow risk": "buffer overflow",
        "command injection": "command injection",
        "os command injection": "command injection",
        "sqli": "sql injection",
        "blind sql injection": "sql injection",
    }

    first_type = aliases.get(first_type, first_type)
    second_type = aliases.get(second_type, second_type)

    first_cwe = str(first.get("cwe", "")).upper().strip()
    second_cwe = str(second.get("cwe", "")).upper().strip()

    cwe_matches = bool(first_cwe and second_cwe and first_cwe == second_cwe)
    type_matches = (
        (first_type == second_type)
        or (first_type and second_type and (first_type in second_type or second_type in first_type))
        or cwe_matches
    )
    if not type_matches:
        return False

    line1 = int(first.get("line") or first.get("primary_line") or 0)
    line2 = int(second.get("line") or second.get("primary_line") or 0)

    # Check affected line sets for overlap
    aff1 = set(first.get("affected_lines", []))
    aff2 = set(second.get("affected_lines", []))
    if aff1 and aff2 and (aff1 & aff2):
        return True

    if not line1 or not line2:
        return True

    return abs(line1 - line2) <= 3


def apply_ai_severity(
    engine_findings: List[Dict[str, Any]],
    severity_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Combines deterministic engine findings with ML predictions and AI contextual reasoning.
    Preserves exact engine evidence (affected lines, sources, sinks, buffers, variables, entropy).
    Enriches with AI-generated description, why, impact, fix, and severity_reason.
    """
    if not engine_findings:
        return []

    assessment_map = {}
    for item in severity_results or []:
        try:
            f_id = int(item.get("id") or item.get("finding_id") or 0)
            if f_id > 0:
                assessment_map[f_id] = item
        except (ValueError, TypeError):
            continue

    resolved_findings = []

    for index, finding in enumerate(engine_findings, start=1):
        updated = dict(finding)
        assessment = assessment_map.get(finding.get("id")) or assessment_map.get(index)

        # 1. Authoritative Evidence Preservation: keep lines, sources, sinks, buffer, secret data
        # (These are not overwritten by AI guesses)

        # 2. Final Severity Policy
        ml_sev = updated.get("ml_severity")
        llm_sev = assessment.get("severity") if assessment else None

        if ml_sev:
            # Primary signal: Trained local ML model
            updated["severity"] = ml_sev
            updated["severity_source"] = "ML"
            updated["final_severity_policy"] = "ML_PRIMARY"
            if llm_sev:
                updated["llm_severity_advisory"] = llm_sev
        elif llm_sev:
            # Fallback signal: LLM contextual advisory
            updated["severity"] = llm_sev
            updated["severity_source"] = "AI_ADVISORY"
            updated["final_severity_policy"] = "DETERMINISTIC_PLUS_LLM_ADVISORY"
            updated["llm_severity_advisory"] = llm_sev
        else:
            # Deterministic baseline
            updated["severity_source"] = "ENGINE"
            updated["final_severity_policy"] = "DETERMINISTIC_ENGINE_BASELINE"

        # 3. Contextual Enhancements from AI
        if assessment:
            conf = assessment.get("confidence")
            if conf is not None:
                updated["confidence"] = conf
                updated["ai_confidence"] = conf
            if assessment.get("exploitability"):
                updated["exploitability"] = assessment["exploitability"]
            if assessment.get("severity_reason"):
                updated["severity_reason"] = assessment["severity_reason"]
            if assessment.get("description"):
                updated["description"] = assessment["description"]
            if assessment.get("why"):
                updated["why"] = assessment["why"]
                updated["ai_why"] = assessment["why"]
            if assessment.get("impact"):
                updated["impact"] = assessment["impact"]
                updated["ai_impact"] = assessment["impact"]
            if assessment.get("fix"):
                updated["fix"] = assessment["fix"]
                updated["ai_fix"] = assessment["fix"]
            if assessment.get("cwe") and not updated.get("cwe"):
                updated["cwe"] = assessment["cwe"]

            updated["ai_assessment"] = assessment
            updated["ai_assessed"] = True

        resolved_findings.append(updated)

    return resolved_findings


def merge_findings(
    engine_findings: List[Dict[str, Any]],
    ai_findings: List[Dict[str, Any]],
    language: str = "Unknown",
    code: str = "",
) -> List[Dict[str, Any]]:
    """
    Deduplicates engine findings and additional AI findings.
    Preserves strongest evidence; marks hybrid confirmations as HYBRID.
    Runs LOCAL ML severity inference on genuinely new AI-only findings (0 external calls).
    If ML cannot reliably classify an AI-only finding, retains the LLM advisory and marks severity_source.
    """
    final_findings = []
    used_ai = set()

    for engine_finding in engine_findings:
        merged = dict(engine_finding)
        merged.setdefault("detection_source", "ENGINE")

        for ai_index, ai_finding in enumerate(ai_findings):
            if ai_index in used_ai:
                continue

            if same_finding(engine_finding, ai_finding):
                merged["detection_source"] = "HYBRID"
                merged["ai_confidence"] = ai_finding.get("confidence")
                if not merged.get("cwe") and ai_finding.get("cwe"):
                    merged["cwe"] = ai_finding.get("cwe")
                used_ai.add(ai_index)
                break

        final_findings.append(merged)

    # Append genuinely new AI findings with local ML severity inference
    for ai_index, ai_finding in enumerate(ai_findings):
        if ai_index in used_ai:
            continue

        f = dict(ai_finding)
        f["detection_source"] = "AI"

        # Run LOCAL ML inference on genuinely new AI-only finding
        if code and predict_finding_severity:
            try:
                ml_pred = predict_finding_severity(f, language, code)
                f["ml_severity"] = ml_pred.get("ml_severity")
                f["ml_confidence"] = ml_pred.get("ml_confidence")
                f["ml_probabilities"] = ml_pred.get("ml_probabilities")
                f["ml_status"] = ml_pred.get("model_status")
            except Exception as err:
                print(f"[HYBRID ENGINE] Local ML inference on AI finding failed: {err}")

        # Final severity policy for AI-only findings
        if f.get("ml_severity"):
            f["llm_severity_advisory"] = f.get("severity")
            f["severity"] = f["ml_severity"]
            f["severity_source"] = "ML"
            f["final_severity_policy"] = "ML_PRIMARY_AI_FINDING"
        else:
            # Retain LLM severity advisory when local ML is not trained or features insufficient
            f["severity_source"] = "AI_ADVISORY"
            f["final_severity_policy"] = "LLM_ADVISORY"

        final_findings.append(f)

    # Assign 1-indexed sequential IDs
    for index, finding in enumerate(final_findings, start=1):
        finding["id"] = index

    return final_findings


def calculate_severity_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Deterministic exact count of finalized findings by severity.
    """
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        sev = str(finding.get("severity", "LOW")).upper()
        if sev == "CRITICAL":
            summary["critical"] += 1
        elif sev == "HIGH":
            summary["high"] += 1
        elif sev == "MEDIUM":
            summary["medium"] += 1
        else:
            summary["low"] += 1

    return summary


def calculate_security_score(findings: List[Dict[str, Any]]) -> int:
    """
    Deterministic Security Score calculation:
    Score starts at 100.0.
    Deductions are calculated per finding based on:
    - Base Severity Penalty (Critical: 30, High: 20, Medium: 10, Low: 4)
    - Confidence Factor: 0.7 + 0.3 * (confidence / 100)
    - Source Factor: HYBRID = 1.05, ENGINE = 1.0, AI = 0.90
    - Evidence Level Factor: CONFIRMED = 1.0, HIGH_CONFIDENCE = 0.85, HEURISTIC = 0.70
    - Rank-Based Diminishing Returns:
        To prevent realistic code with several mixed issues from collapsing to 0 prematurely,
        findings are ordered by raw impact descending, with diminishing weight on successive issues:
        Rank 1: 100%, Rank 2: 90%, Rank 3: 80%, Rank 4: 70%, Rank 5+: 60%.
    Final score bounded in [0, 100].
    """
    if not findings:
        return 100

    raw_deductions = []

    for finding in findings:
        sev = str(finding.get("severity", "LOW")).upper()
        penalty = SEVERITY_PENALTY.get(sev, 4)

        try:
            conf = float(finding.get("confidence", 80))
        except (ValueError, TypeError):
            conf = 80.0
        conf_factor = 0.7 + 0.3 * (max(0.0, min(100.0, conf)) / 100.0)

        source = str(finding.get("detection_source", "ENGINE")).upper()
        if source == "HYBRID":
            source_factor = 1.05
        elif source == "AI":
            source_factor = 0.90
        else:
            source_factor = 1.00

        ev_level = str(finding.get("evidence_level", "HIGH_CONFIDENCE"))
        ev_factor = EVIDENCE_LEVEL_WEIGHTS.get(ev_level, 0.85)

        raw_deductions.append(penalty * conf_factor * source_factor * ev_factor)

    # Sort descending so the most severe vulnerabilities take primary weight
    raw_deductions.sort(reverse=True)

    total_deduction = 0.0
    for rank, deduction in enumerate(raw_deductions):
        if rank == 0:
            weight = 1.00
        elif rank == 1:
            weight = 0.90
        elif rank == 2:
            weight = 0.80
        elif rank == 3:
            weight = 0.70
        else:
            weight = 0.60
        total_deduction += deduction * weight

    score = 100.0 - total_deduction
    return round(max(0.0, min(100.0, score)))