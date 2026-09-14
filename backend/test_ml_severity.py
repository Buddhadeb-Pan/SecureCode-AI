"""
Test suite for ML Severity Interface and Feature Extractor.
"""

from ml_severity_model import predict_finding_severity, get_ml_engine


def test_feature_extraction_and_fallback():
    sample_finding = {
        "type": "SQL Injection",
        "severity": "HIGH",
        "confidence": 95,
        "exploitability": "HIGH",
        "cwe": "CWE-89",
        "affected_lines": [2, 6, 12],
        "source": {"line": 2, "code": "username = input()"},
        "sink": {"line": 12, "code": "cursor.execute(query)"},
        "evidence": [
            {"role": "source", "line": 2},
            {"role": "sink", "line": 12},
        ],
        "evidence_level": "data_flow_confirmed",
        "description": "User controlled data reaches SQL sink.",
        "fix": "Use parameterized queries.",
    }
    sample_code = """username = input()
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)"""

    engine = get_ml_engine()
    features = engine.extract_features(sample_finding, "Python", sample_code)
    
    assert len(features) == 10, f"Expected 10 features, got {len(features)}"
    assert features[1] == 1.0, "Expected has_source = 1.0"
    assert features[2] == 1.0, "Expected has_sink = 1.0"
    assert features[3] == 1.0, "Expected is_flow_confirmed = 1.0"

    res = predict_finding_severity(sample_finding, "Python", sample_code)
    assert "model_status" in res
    assert "features_used" in res
    assert res["features_used"] == 10

    print("test_feature_extraction_and_fallback PASSED")
    print("Result:", res)


if __name__ == "__main__":
    test_feature_extraction_and_fallback()
