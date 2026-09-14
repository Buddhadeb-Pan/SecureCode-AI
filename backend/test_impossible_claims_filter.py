"""
Test Suite for Guarding Against Impossible / Speculative Static Claims.
Verifies Requirement 3:
- Standalone HTML file missing HTTP headers (CSP, HSTS, X-Frame-Options) is filtered out.
- Blanket Rust unsafe block claim without memory unsafety hazard is filtered out.
- Legitimate findings with evidence and within-bounds lines are preserved.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_pipeline import is_valid_ai_finding, AiVulnerability


def test_impossible_claims_filtering():
    print("=========================================================")
    print("TESTING FILTERING OF IMPOSSIBLE STATIC CLAIMS")
    print("=========================================================")

    # 1. Standalone HTML file with speculative HTTP headers claim
    html_code = """<!DOCTYPE html>
    <html>
    <head><title>Test</title></head>
    <body><h1>Hello</h1></body>
    </html>"""

    impossible_html_finding = AiVulnerability(
        type="Missing Content-Security-Policy Header",
        line=1,
        severity="MEDIUM",
        description="The HTML document is missing Content-Security-Policy header.",
        why="Missing CSP headers leaves site vulnerable to XSS.",
    )
    assert not is_valid_ai_finding(impossible_html_finding, "HTML", html_code), "Failed to filter missing CSP on standalone HTML"
    print("  [PASS] Successfully filtered out missing CSP header claim on standalone HTML.")

    impossible_hsts_finding = AiVulnerability(
        type="Missing Strict-Transport-Security Header",
        line=2,
        severity="LOW",
        description="HSTS header was not found in HTML source.",
        why="Lack of HSTS allows man-in-the-middle downgrade attacks.",
    )
    assert not is_valid_ai_finding(impossible_hsts_finding, "HTML", html_code), "Failed to filter missing HSTS on standalone HTML"
    print("  [PASS] Successfully filtered out missing HSTS header claim on standalone HTML.")

    # 2. Legitimate HTML finding (e.g. plaintext HTTP action or inline eval)
    legitimate_html_finding = AiVulnerability(
        type="Insecure Form Action",
        line=3,
        severity="HIGH",
        description="Form action submits sensitive data to plaintext http:// endpoint.",
        why="Data sent over HTTP can be intercepted in transit.",
    )
    assert is_valid_ai_finding(legitimate_html_finding, "HTML", html_code), "Incorrectly filtered legitimate HTML finding"
    print("  [PASS] Preserved legitimate HTML finding.")

    # 3. Blanket Rust unsafe block claim without memory safety hazard
    rust_code = """
    fn main() {
        unsafe {
            println!("Hello from unsafe");
        }
    }
    """
    blanket_rust_unsafe = AiVulnerability(
        type="Unsafe Block Used",
        line=3,
        severity="MEDIUM",
        description="The code contains an unsafe block.",
        why="Unsafe blocks bypass Rust compiler guarantees.",
    )
    assert not is_valid_ai_finding(blanket_rust_unsafe, "Rust", rust_code), "Failed to filter blanket Rust unsafe block"
    print("  [PASS] Successfully filtered out blanket Rust unsafe block claim.")

    # 4. Legitimate Rust memory safety flaw inside unsafe block
    legitimate_rust_finding = AiVulnerability(
        type="Unchecked Raw Pointer Dereference",
        line=3,
        severity="HIGH",
        description="Dereferencing raw pointer without checking for null.",
        why="Dereferencing a null or invalid raw pointer causes segmentation fault and undefined behavior.",
    )
    assert is_valid_ai_finding(legitimate_rust_finding, "Rust", rust_code), "Incorrectly filtered legitimate Rust pointer finding"
    print("  [PASS] Preserved legitimate Rust raw pointer dereference finding.")

    # 5. Out-of-bounds line finding
    out_of_bounds_finding = AiVulnerability(
        type="Command Injection",
        line=999,
        severity="CRITICAL",
        description="Spurious finding on non-existent line 999.",
        why="Speculative flaw.",
    )
    assert not is_valid_ai_finding(out_of_bounds_finding, "Python", "x = 1\ny = 2\n"), "Failed to filter out-of-bounds line finding"
    print("  [PASS] Successfully filtered out finding on non-existent line.")

    print("\n=========================================================")
    print("ALL IMPOSSIBLE CLAIM FILTERING TESTS PASSED!")
    print("=========================================================")


if __name__ == "__main__":
    test_impossible_claims_filtering()
