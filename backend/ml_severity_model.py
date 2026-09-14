"""
Machine Learning Severity & Risk Classification Module for SecureCode AI.

Implements feature extraction, model persistence, inference, and an explainable
deterministic fallback. Follows strict transparency: if no verified trained model
artifact is present, it explicitly reports:
"model not trained yet / deterministic fallback active"
without fabricating predictions or fake probabilities.
"""

import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Try importing joblib
try:
    import joblib
except ImportError:
    joblib = None

MODEL_PATH = Path(__file__).parent / "ml_model.joblib"

# CWE Base Risk Weights (Reference: CVSS baseline averages)
CWE_BASE_RISK = {
    "CWE-78": 0.95,   # Command Injection
    "CWE-89": 0.90,   # SQL Injection
    "CWE-120": 0.90,  # Buffer Overflow
    "CWE-502": 0.95,  # Insecure Deserialization
    "CWE-94": 0.95,   # Code Injection
    "CWE-918": 0.85,  # SSRF
    "CWE-22": 0.80,   # Path Traversal
    "CWE-79": 0.75,   # XSS
    "CWE-611": 0.80,  # XXE
    "CWE-798": 0.85,  # Hardcoded Secret
    "CWE-327": 0.50,  # Weak Cryptography
    "CWE-338": 0.60,  # Insecure Randomness
    "CWE-134": 0.85,  # Format String
    "CWE-416": 0.85,  # Use After Free
    "CWE-200": 0.55,  # Sensitive Data Exposure
}

CLASSES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class MLSeverityEngine:
    def __init__(self, model_file: Optional[Path] = None):
        self.model_path = model_file or MODEL_PATH
        self.model = None
        self.is_trained = False
        self._load_model()

    def _load_model(self):
        """Loads trained scikit-learn model artifact if available."""
        if joblib and self.model_path.exists():
            try:
                loaded = joblib.load(self.model_path)
                if hasattr(loaded, "predict_proba"):
                    self.model = loaded
                    self.is_trained = True
                    print(f"[ML SEVERITY] Loaded trained model from {self.model_path}")
            except Exception as err:
                print(f"[ML SEVERITY] Could not load model: {err}")
                self.model = None
                self.is_trained = False
        else:
            self.model = None
            self.is_trained = False

    def extract_features(
        self,
        finding: Dict[str, Any],
        language: str,
        code: str,
    ) -> List[float]:
        """
        Extracts 10 structured, deterministic signals from finding and context.
        """
        cwe = finding.get("cwe", "")
        base_cwe_weight = CWE_BASE_RISK.get(cwe, 0.65)

        has_source = 1.0 if finding.get("source") else 0.0
        has_sink = 1.0 if finding.get("sink") else 0.0

        ev_level = str(finding.get("evidence_level", "")).lower()
        is_flow_confirmed = 1.0 if ("confirmed" in ev_level or "flow" in ev_level) else 0.0

        desc = (finding.get("description", "") + " " + finding.get("fix", "")).lower()
        sanitization = 1.0 if any(w in desc for w in ("escap", "sanitiz", "parameter", "safe")) else 0.0

        evidence_count = float(len(finding.get("evidence", [])))
        affected_lines_count = float(len(finding.get("affected_lines", [])))

        try:
            raw_conf = float(finding.get("confidence", 80))
        except (ValueError, TypeError):
            raw_conf = 80.0
        norm_conf = max(0.0, min(raw_conf / 100.0, 1.0))

        exploitability_map = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.55, "LOW": 0.25}
        exploit_val = exploitability_map.get(str(finding.get("exploitability", "MEDIUM")).upper(), 0.55)

        code_lines = float(len(code.splitlines())) / 100.0 if code else 0.1

        return [
            base_cwe_weight,
            has_source,
            has_sink,
            is_flow_confirmed,
            sanitization,
            evidence_count,
            affected_lines_count,
            norm_conf,
            exploit_val,
            code_lines,
        ]

    def predict(
        self,
        finding: Dict[str, Any],
        language: str,
        code: str,
    ) -> Dict[str, Any]:
        """
        Infers severity using the trained ML model if available.
        Otherwise cleanly reports fallback status without generating fake probabilities.
        """
        features = self.extract_features(finding, language, code)

        if self.is_trained and self.model is not None:
            try:
                probs = self.model.predict_proba([features])[0]
                classes = list(getattr(self.model, "classes_", CLASSES))
                prob_dict = {
                    cls: round(float(prob), 4)
                    for cls, prob in zip(classes, probs)
                }
                predicted_class = classes[int(probs.argmax())]
                max_conf = round(float(probs.max()) * 100)

                return {
                    "ml_severity": predicted_class,
                    "ml_confidence": max_conf,
                    "ml_probabilities": prob_dict,
                    "model_status": "trained_model_active",
                    "features_used": len(features),
                }
            except Exception as err:
                print(f"[ML SEVERITY] Inference error: {err}")

        # Deterministic fallback when no trained model is available
        det_severity = finding.get("severity", "MEDIUM")
        return {
            "ml_severity": None,
            "ml_confidence": None,
            "ml_probabilities": None,
            "model_status": "model not trained yet / deterministic fallback active",
            "fallback_severity": det_severity,
            "features_used": len(features),
        }


# Global singleton instance
_ml_engine: Optional[MLSeverityEngine] = None


def get_ml_engine() -> MLSeverityEngine:
    global _ml_engine
    if _ml_engine is None:
        _ml_engine = MLSeverityEngine()
    return _ml_engine


def predict_finding_severity(
    finding: Dict[str, Any],
    language: str,
    code: str,
) -> Dict[str, Any]:
    """Public interface to predict severity for a single finding."""
    engine = get_ml_engine()
    return engine.predict(finding, language, code)
