import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";

import {
  ShieldCheck,
  Code2,
  SearchCode,
  TriangleAlert,
  WandSparkles,
  FileChartColumn,
  Upload,
  Trash2,
  ScanSearch,
  CheckCircle2,
  ArrowRight,
  FileCode2,
  Sparkles,
  CircleAlert,
  Shield,
  Download,
  RotateCcw,
  ChevronDown,
  X,
} from "lucide-react";

import { API_BASE_URL, authFetch } from "../config/api.js";
import "./Features.css";

function Features() {
  const navigate = useNavigate();
  const location = useLocation();
  const [pageReady, setPageReady] = useState(false);
  const [code, setCode] = useState("");
  const [fileName, setFileName] = useState("untitled.code");
  const [language, setLanguage] = useState("Auto Detect");
  const [isAnalysing, setIsAnalysing] = useState(false);
  const [showResult, setShowResult] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authModalMsg, setAuthModalMsg] = useState("");

  const fileInputRef = useRef(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      setPageReady(true);
    }, 750);

    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!pageReady) return;

    if (location.hash === "#review") {
      const reviewEl = document.getElementById("review");
      if (reviewEl) {
        reviewEl.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, [pageReady, location.hash]);

  const detectLanguage = (name) => {
    const extension = name.split(".").pop()?.toLowerCase();

    const languages = {
      js: "JavaScript",
      jsx: "React JSX",
      ts: "TypeScript",
      tsx: "React TSX",
      py: "Python",
      java: "Java",
      cpp: "C++",
      c: "C",
      cs: "C#",
      php: "PHP",
      go: "Go",
      rs: "Rust",
    };

    return languages[extension] || "Auto Detect";
  };

  const handleFileUpload = (event) => {
    const file = event.target.files?.[0];

    if (!file) return;

    setFileName(file.name);
    setLanguage(detectLanguage(file.name));

    const reader = new FileReader();

    reader.onload = (e) => {
      setCode(e.target.result);
      setShowResult(false);
    };

    reader.readAsText(file);
  };

  const handleClear = () => {
    setCode("");
    setFileName("untitled.code");
    setLanguage("Auto Detect");
    setShowResult(false);

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleAnalyse = async () => {
    if (!code.trim()) return;

    try {
      setIsAnalysing(true);

      const response = await authFetch(`${API_BASE_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          code: code,
          file_name: fileName,
          language: language,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        if (
          response.status === 403 ||
          response.headers.get("X-Auth-Required") === "true" ||
          (errorData.detail && errorData.detail.includes("free security analysis"))
        ) {
          setIsAnalysing(false);
          setAuthModalMsg(
            errorData.detail ||
              "You've used your free security analysis. Sign in or create an account to continue analyzing code."
          );
          setShowAuthModal(true);
          return;
        }
        throw new Error(errorData.detail || "Backend analysis failed");
      }

      const result = await response.json();

      if (result.guest_trial_token) {
        localStorage.setItem("guest_trial_token", result.guest_trial_token);
      }

      setIsAnalysing(false);

      navigate("/dashboard", {
        state: {
          code: code,
          fileName: fileName,
          language: language,
          analysisResult: result,
        },
      });
    } catch (error) {
      console.error("Analysis error:", error);
      setIsAnalysing(false);
      if (
        error?.message &&
        (error.message.includes("free security analysis") ||
          error.message.includes("403") ||
          error.message.includes("free analysis"))
      ) {
        setAuthModalMsg(
          "You've used your free security analysis. Sign in or create an account to continue analyzing code."
        );
        setShowAuthModal(true);
      } else {
        alert(error?.message || "Backend server is not responding.");
      }
    }
  };

  const lineCount = Math.max(code.split("\n").length, 12);

  return (
    <main className="features-page">
      {!pageReady && (
        <div className="features-loader">
          <div className="features-loader-logo">
            <ShieldCheck size={34} />
          </div>

          <h2>
            SecureCode <span>AI</span>
          </h2>

          <div className="loader-line">
            <span />
          </div>

          <p>Preparing secure workspace...</p>
        </div>
      )}

      <div
        className={`features-content ${
          pageReady ? "features-content-ready" : ""
        }`}
      >
        {/* BACKGROUND MOVEMENT */}

        <div className="feature-bg-grid" />

        <span className="feature-floating-code feature-code-one">
          {"</>"}
        </span>

        <span className="feature-floating-code feature-code-two">
          {"{ }"}
        </span>

        <span className="feature-floating-code feature-code-three">
          AI
        </span>

        <span className="feature-particle particle-one" />
        <span className="feature-particle particle-two" />
        <span className="feature-particle particle-three" />

        {/* SIMPLE TOP BAR */}

        <header className="features-header">
          <Link to="/home" className="features-brand">
            <span className="features-brand-icon">
              <ShieldCheck size={27} strokeWidth={1.9} />
            </span>

            <span>
              SecureCode <strong>AI</strong>
            </span>
          </Link>
        </header>

        {/* HERO */}

        <section className="features-hero">
          <div className="features-mini-badge">
            <Sparkles size={15} />
            SECURITY REVIEW WORKSPACE
          </div>

          <h1>
            Review Code.
            <span>Discover Risk. Build Securely.</span>
          </h1>

          <p>
            A focused security workspace designed to analyse source code,
            highlight potential risks and provide clear remediation
            guidance.
          </p>
        </section>

        {/* FEATURE CARDS */}

        <section className="feature-showcase" id="features">
          <div className="feature-section-heading">
            <div>
              <span>Platform Capabilities</span>
              <h2>Everything in one secure workflow</h2>
            </div>

            <p>
              These capabilities are currently represented as frontend
              concepts and can evolve with the security engine.
            </p>
          </div>

          <div className="feature-card-grid">
            <article className="feature-card">
              <div className="feature-card-icon">
                <SearchCode size={25} />
              </div>

              <span className="feature-number">01</span>

              <h3>Smart Code Analysis</h3>

              <p>
                Review source code structure and identify areas that may
                require deeper security inspection.
              </p>

              <div className="feature-tags">
                <span>Analysis</span>
                <span>Auto Detect</span>
              </div>

              <Link to="/features/smart-code-analysis" className="feature-explore">
                Explore
                <ArrowRight size={16} />
              </Link>
            </article>

            <article className="feature-card">
              <div className="feature-card-icon">
                <Shield size={25} />
              </div>

              <span className="feature-number">02</span>

              <h3>Vulnerability Detection</h3>

              <p>
                Highlight suspicious patterns and potential weaknesses
                before they become serious security problems.
              </p>

              <div className="mini-risk-list">
                <span>
                  <i /> Unsafe Input
                </span>

                <span>
                  <i /> Validation Risk
                </span>
              </div>

              <Link to="/features/vulnerability-detection" className="feature-explore">
                Explore
                <ArrowRight size={16} />
              </Link>
            </article>

            <article className="feature-card">
              <div className="feature-card-icon">
                <TriangleAlert size={25} />
              </div>

              <span className="feature-number">03</span>

              <h3>Risk & Severity</h3>

              <p>
                Organise detected issues according to their potential
                security impact and priority.
              </p>

              <div className="severity-preview">
                <span>
                  HIGH <strong>02</strong>
                </span>

                <span>
                  MEDIUM <strong>03</strong>
                </span>

                <span>
                  LOW <strong>01</strong>
                </span>
              </div>

              <Link to="/features/risk-severity" className="feature-explore">
                Explore
                <ArrowRight size={16} />
              </Link>
            </article>

            <article className="feature-card">
              <div className="feature-card-icon">
                <WandSparkles size={25} />
              </div>

              <span className="feature-number">04</span>

              <h3>Secure Fix Guidance</h3>

              <p>
                Understand vulnerable code and receive clearer,
                security-focused remediation suggestions.
              </p>

              <div className="fix-preview">
                <span>Risky Code</span>
                <ArrowRight size={14} />
                <strong>Secure Fix</strong>
              </div>

              <Link to="/features/secure-fix-guidance" className="feature-explore">
                Explore
                <ArrowRight size={16} />
              </Link>
            </article>

            {/* 05 - SECURITY REPORT */}

            <article className="feature-card">
              <div className="feature-card-icon">
                <FileChartColumn size={25} />
              </div>

              <span className="feature-number">05</span>

              <h3>Security Report</h3>

              <p>
                View a structured security summary containing detected
                issues, risk information, explanations and recommendations.
              </p>

              <div className="report-preview">
                <div>
                  <span>Score</span>
                  <strong>78</strong>
                </div>

                <div>
                  <span>Issues</span>
                  <strong>06</strong>
                </div>

                <div>
                  <span>Status</span>
                  <strong>Review</strong>
                </div>
              </div>

              <Link to="/features/security-report" className="feature-explore">
                Explore
                <ArrowRight size={16} />
              </Link>
            </article>

            {/* 06 - VERIFIED CODE OPTIMIZATION */}

            <article className="feature-card">
              <div className="feature-card-icon">
                <CheckCircle2 size={25} />
              </div>

              <span className="feature-number">06</span>

              <h3>Verified Code Optimization</h3>

              <p>
                Compare original and corrected code, verify security
                improvements and understand why the recommended version
                is safer and better.
              </p>

              <div className="feature-tags">
                <span>Re-scan</span>
                <span>Verification</span>
                <span>Optimized</span>
              </div>

              <Link to="/features/code-optimization" className="feature-explore">
                Explore
                <ArrowRight size={16} />
              </Link>
            </article>
          </div>
        </section>

        {/* CODE WORKSPACE */}

        <section className="code-workspace-section" id="review">
          <div className="workspace-heading">
            <div className="workspace-heading-icon">
              <Code2 size={24} />
            </div>

            <div>
              <span>CODE REVIEW</span>
              <h2>Security Analysis Workspace</h2>
            </div>

            <div className="workspace-system-status">
              <span />
              System Ready
            </div>
          </div>

          <div className="code-workspace">
            <div className="workspace-scan-light" />

            <div className="workspace-toolbar">
              <div className="workspace-file">
                <FileCode2 size={19} />

                <div>
                  <strong>{fileName}</strong>
                  <span>Source file</span>
                </div>
              </div>

              <div className="workspace-toolbar-actions">
                <div className="language-detect">
                  <span>LANGUAGE</span>
                  <strong>{language}</strong>
                </div>

                <input
                  ref={fileInputRef}
                  type="file"
                  hidden
                  onChange={handleFileUpload}
                  accept=".js,.jsx,.ts,.tsx,.py,.java,.cpp,.c,.cs,.php,.go,.rs,.txt"
                />

                <button
                  type="button"
                  className="upload-code-button"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload size={17} />
                  Upload File
                </button>
              </div>
            </div>

            <div className="editor-shell">
              <div className="editor-line-numbers">
                {Array.from({ length: lineCount }, (_, index) => (
                  <span key={index}>{String(index + 1).padStart(2, "0")}</span>
                ))}
              </div>

              <textarea
                value={code}
                onChange={(event) => {
                  setCode(event.target.value);
                  setShowResult(false);
                }}
                spellCheck="false"
                placeholder={`// Paste your source code here...\n\n// SecureCode AI will prepare it for security review.`}
              />
            </div>

            <div className="workspace-bottom">
              <div className="workspace-info">
                <CheckCircle2 size={17} />
                Your code remains inside the review workspace.
              </div>

              <div className="workspace-bottom-actions">
                <button
                  type="button"
                  className="clear-code-button"
                  onClick={handleClear}
                >
                  <Trash2 size={17} />
                  Clear
                </button>

                <button
                  type="button"
                  className="analyse-code-button"
                  onClick={handleAnalyse}
                  disabled={!code.trim() || isAnalysing}
                >
                  {isAnalysing ? (
                    <>
                      <span className="analyse-spinner" />
                      Analysing Code
                    </>
                  ) : (
                    <>
                      <ScanSearch size={19} />
                      Analyse Code
                      <ArrowRight size={18} />
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* RESULT */}

        {showResult && (
          <section
            className="analysis-result-section"
            id="analysis-result"
          >
            <div className="result-complete">
              <CheckCircle2 size={20} />
              <span>ANALYSIS COMPLETE</span>
            </div>

            <div className="result-heading">
              <div>
                <span>SECURITY REVIEW RESULT</span>
                <h2>Analysis Overview</h2>
              </div>

              <button type="button" className="new-review-button">
                <RotateCcw size={17} />
                New Review
              </button>
            </div>

            <div className="result-summary-grid">
              <div className="result-summary-card score-result-card">
                <span>Security Score</span>

                <strong>
                  78
                  <small>/100</small>
                </strong>

                <p>Needs Review</p>
              </div>

              <div className="result-summary-card">
                <span>Issues Found</span>

                <strong>06</strong>

                <p>Potential findings</p>
              </div>

              <div className="result-summary-card">
                <span>Risk Level</span>

                <strong className="high-risk-text">HIGH</strong>

                <p>Priority attention</p>
              </div>

              <div className="result-summary-card">
                <span>Language</span>

                <strong className="result-language">
                  {language === "Auto Detect" ? "Detected" : language}
                </strong>

                <p>Source analysis</p>
              </div>
            </div>

            <div className="vulnerability-panel">
              <div className="vulnerability-panel-top">
                <div>
                  <CircleAlert size={21} />

                  <div>
                    <span>HIGH SEVERITY</span>
                    <h3>Potential Unsafe Input Handling</h3>
                  </div>
                </div>

                <span className="affected-line">Line 03</span>
              </div>

              <div className="vulnerability-content-grid">
                <div>
                  <span className="result-content-label">
                    Why this matters
                  </span>

                  <p>
                    User-controlled input may be processed without
                    sufficient validation or bounds checking.
                  </p>
                </div>

                <div>
                  <span className="result-content-label">
                    Potential Impact
                  </span>

                  <p>
                    Unsafe input handling may expose the application to
                    unexpected behaviour or security weaknesses.
                  </p>
                </div>

                <div className="recommended-fix">
                  <span className="result-content-label">
                    Recommended Fix
                  </span>

                  <p>
                    Apply validated and bounded input handling before
                    processing user-controlled data.
                  </p>
                </div>
              </div>
            </div>

            <div className="secure-code-panel">
              <div className="secure-code-top">
                <div>
                  <WandSparkles size={20} />

                  <div>
                    <span>REMEDIATION PREVIEW</span>
                    <h3>Suggested Secure Code</h3>
                  </div>
                </div>

                <span className="secure-badge">
                  <ShieldCheck size={15} />
                  Secure Fix
                </span>
              </div>

              <pre>
                <code>{`// Example secure remediation

std::string user;

std::getline(std::cin, user);

if (user.length() > MAX_ALLOWED_LENGTH) {
    // Reject invalid input
    return 1;
}`}</code>
              </pre>
            </div>

            <div className="result-footer">
              <p>
                Demo analysis result — final findings will later be generated
                by the backend security engine.
              </p>

              <button type="button" className="download-report-button">
                <Download size={18} />
                Download Report
              </button>
            </div>
          </section>
        )}
        {/* BACK TO HOME */}
<div className="features-back-home">
  <button
    type="button"
    className="features-home-arrow"
    onClick={() => navigate("/home")}
    aria-label="Back to Home"
  >
    <ChevronDown size={29} />
  </button>

  <span>Back to Home</span>
</div>

        <footer className="features-footer">
          <ShieldCheck size={17} />
          SecureCode AI · Intelligent Code Security Workspace
        </footer>
      </div>

      {showAuthModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(0, 0, 0, 0.78)",
            backdropFilter: "blur(6px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: "20px",
          }}
        >
          <div
            style={{
              backgroundColor: "#0d131f",
              border: "1px solid rgba(245, 158, 11, 0.35)",
              borderRadius: "16px",
              padding: "32px",
              maxWidth: "460px",
              width: "100%",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.8)",
              position: "relative",
              textAlign: "center",
            }}
          >
            <button
              type="button"
              onClick={() => setShowAuthModal(false)}
              style={{
                position: "absolute",
                top: "16px",
                right: "16px",
                background: "transparent",
                border: "none",
                color: "#9ca3af",
                cursor: "pointer",
                padding: "6px",
              }}
              aria-label="Close modal"
            >
              <X size={20} />
            </button>

            <div
              style={{
                width: "56px",
                height: "56px",
                borderRadius: "50%",
                backgroundColor: "rgba(245, 158, 11, 0.12)",
                color: "#f59e0b",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                margin: "0 auto 18px auto",
                border: "1px solid rgba(245, 158, 11, 0.25)",
              }}
            >
              <ShieldCheck size={30} />
            </div>

            <h3
              style={{
                fontSize: "20px",
                fontWeight: 700,
                color: "#ffffff",
                marginBottom: "10px",
              }}
            >
              Free Analysis Limit Reached
            </h3>

            <p
              style={{
                fontSize: "14px",
                color: "#94a3b8",
                lineHeight: "1.6",
                marginBottom: "24px",
              }}
            >
              {authModalMsg ||
                "You've used your free security analysis. Sign in or create an account to continue analyzing code."}
            </p>

            <div
              style={{
                display: "flex",
                gap: "12px",
                justifyContent: "center",
              }}
            >
              <button
                type="button"
                onClick={() => navigate("/login")}
                style={{
                  flex: 1,
                  padding: "11px 18px",
                  borderRadius: "8px",
                  backgroundColor: "#2563eb",
                  color: "#ffffff",
                  fontWeight: 600,
                  fontSize: "14px",
                  border: "none",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "6px",
                }}
              >
                Sign In
                <ArrowRight size={16} />
              </button>

              <button
                type="button"
                onClick={() => navigate("/register")}
                style={{
                  flex: 1,
                  padding: "11px 18px",
                  borderRadius: "8px",
                  backgroundColor: "rgba(255, 255, 255, 0.08)",
                  color: "#e2e8f0",
                  fontWeight: 600,
                  fontSize: "14px",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  cursor: "pointer",
                }}
              >
                Create Account
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

export default Features;