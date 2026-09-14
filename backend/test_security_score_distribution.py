"""
Test Suite for Deterministic Security Score Distribution.
Tests the calibrated formula with rank-based diminishing returns:
1. Safe code ≈ 100
2. One Medium issue ≈ 92
3. One High issue ≈ 80
4. Multiple mixed issues (1 Crit, 1 High, 1 Med, 1 Low) ≈ 47 (healthy mid-range)
5. Intentionally highly vulnerable code (8+ critical/high flaws) = 0
"""

import sys
import os

# Ensure backend root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hybrid_security_engine import calculate_security_score


def test_score_distribution():
    print("=========================================================")
    print("TESTING DETERMINISTIC SECURITY SCORE DISTRIBUTION")
    print("=========================================================")

    # 1. Safe Code: 0 findings
    safe_findings = []
    score_safe = calculate_security_score(safe_findings)
    print(f"\n[SCENARIO 1] Safe Code (0 findings): {score_safe}/100")
    assert score_safe == 100, f"Expected 100 for safe code, got {score_safe}"
    print("  => PASS: Safe code receives 100.")

    # 2. One Medium Issue
    one_medium = [
        {
            "severity": "MEDIUM",
            "confidence": 85,
            "detection_source": "ENGINE",
            "evidence_level": "HIGH_CONFIDENCE",
        }
    ]
    score_med = calculate_security_score(one_medium)
    print(f"\n[SCENARIO 2] One Medium Issue: {score_med}/100")
    assert 88 <= score_med <= 95, f"Expected 88-95 for one medium issue, got {score_med}"
    print("  => PASS: One medium issue receives healthy minor penalty.")

    # 3. One High Issue
    one_high = [
        {
            "severity": "HIGH",
            "confidence": 92,
            "detection_source": "ENGINE",
            "evidence_level": "CONFIRMED",
        }
    ]
    score_high = calculate_security_score(one_high)
    print(f"\n[SCENARIO 3] One High Issue: {score_high}/100")
    assert 75 <= score_high <= 85, f"Expected 75-85 for one high issue, got {score_high}"
    print("  => PASS: One high issue receives appropriate deduction.")

    # 4. Multiple Mixed Issues (1 Critical, 1 High, 1 Medium, 1 Low)
    multiple_mixed = [
        {
            "severity": "CRITICAL",
            "confidence": 95,
            "detection_source": "ENGINE",
            "evidence_level": "CONFIRMED",
        },
        {
            "severity": "HIGH",
            "confidence": 90,
            "detection_source": "ENGINE",
            "evidence_level": "HIGH_CONFIDENCE",
        },
        {
            "severity": "MEDIUM",
            "confidence": 85,
            "detection_source": "ENGINE",
            "evidence_level": "HIGH_CONFIDENCE",
        },
        {
            "severity": "LOW",
            "confidence": 80,
            "detection_source": "ENGINE",
            "evidence_level": "HEURISTIC",
        },
    ]
    score_mixed = calculate_security_score(multiple_mixed)
    print(f"\n[SCENARIO 4] Multiple Mixed Issues (1 Crit, 1 High, 1 Med, 1 Low): {score_mixed}/100")
    assert 40 <= score_mixed <= 55, f"Expected 40-55 for multiple mixed issues, got {score_mixed}"
    print("  => PASS: Multiple mixed issues does not collapse to 0 prematurely.")

    # 5. Realistic Multi-Vulnerability Code (2 Criticals + 1 High)
    two_crit_one_high = [
        {"severity": "CRITICAL", "confidence": 95, "detection_source": "ENGINE", "evidence_level": "CONFIRMED"},
        {"severity": "CRITICAL", "confidence": 95, "detection_source": "ENGINE", "evidence_level": "CONFIRMED"},
        {"severity": "HIGH", "confidence": 90, "detection_source": "ENGINE", "evidence_level": "CONFIRMED"},
    ]
    score_two_crit = calculate_security_score(two_crit_one_high)
    print(f"\n[SCENARIO 4b] Realistic Severe Code (2 Crit + 1 High): {score_two_crit}/100")
    assert 20 <= score_two_crit <= 35, f"Expected 20-35 for 2 Crit + 1 High, got {score_two_crit}"
    print("  => PASS: Severe realistic code retains meaningful positive risk rating.")

    # 6. Intentionally Highly Vulnerable Code (3 Critical, 3 High, 2 Medium)
    highly_vulnerable = [
        {"severity": "CRITICAL", "confidence": 95, "detection_source": "ENGINE", "evidence_level": "CONFIRMED"},
        {"severity": "CRITICAL", "confidence": 90, "detection_source": "ENGINE", "evidence_level": "CONFIRMED"},
        {"severity": "CRITICAL", "confidence": 92, "detection_source": "ENGINE", "evidence_level": "CONFIRMED"},
        {"severity": "HIGH", "confidence": 90, "detection_source": "ENGINE", "evidence_level": "HIGH_CONFIDENCE"},
        {"severity": "HIGH", "confidence": 88, "detection_source": "ENGINE", "evidence_level": "HIGH_CONFIDENCE"},
        {"severity": "HIGH", "confidence": 85, "detection_source": "ENGINE", "evidence_level": "HIGH_CONFIDENCE"},
        {"severity": "MEDIUM", "confidence": 80, "detection_source": "ENGINE", "evidence_level": "HEURISTIC"},
        {"severity": "MEDIUM", "confidence": 80, "detection_source": "ENGINE", "evidence_level": "HEURISTIC"},
    ]
    score_extreme = calculate_security_score(highly_vulnerable)
    print(f"\n[SCENARIO 5] Intentionally Highly Vulnerable Code (8 critical/high/med flaws): {score_extreme}/100")
    assert score_extreme == 0, f"Expected 0 for catastrophic vulnerability density, got {score_extreme}"
    print("  => PASS: Catastrophic density properly bounds to 0.")

    print("\n=========================================================")
    print("ALL SECURITY SCORE DISTRIBUTION TESTS PASSED!")
    print("=========================================================")


if __name__ == "__main__":
    test_score_distribution()
