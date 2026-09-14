import { useState } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";

import {
  ShieldCheck,
  RotateCcw,
  CircleCheck,
  TriangleAlert,
  Bug,
  Code2,
  FileCode2,
  Sparkles,
  ShieldAlert,
  Download,
  Lightbulb,
  CircleAlert,
  Copy,
  Check,
  Clock,
  ChevronDown,
  ChevronUp,
  ScanSearch,
  WandSparkles,
  X,
  Lock,
  ArrowRight,
} from "lucide-react";

import { API_BASE_URL, getStoredToken } from "../config/api.js";
import "./Dashboard.css";


function AnalysisDashboard() {
  const location = useLocation();
  const navigate = useNavigate();

  const [copied, setCopied] = useState(false);
  const [openFinding, setOpenFinding] = useState(null);
  const [showAuthModal, setShowAuthModal] = useState(false);

  const {
    code = "",
    fileName: receivedFileName,
    language: frontendLanguage,
    analysisResult,
  } = location.state || {};

  const fileName =
    receivedFileName ||
    analysisResult?.file_name ||
    "untitled.code";

  const language =
    analysisResult?.detected_language ||
    (frontendLanguage === "Auto Detect"
      ? "Unknown"
      : frontendLanguage) ||
    "Unknown";

  const sourceCode =
    code ||
`int main() {
  char user[10];

  cin >> user;

  return 0;
}`;
const securityScore =
  analysisResult?.security_score ?? 100;

const issuesFound =
  analysisResult?.issues_found ?? 0;

const analysisTimeMs =
  analysisResult?.analysis_time_ms ?? 0;

const severityCounts =
  analysisResult?.severity_counts || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  // ==========================================
// AI DASHBOARD DATA
// ==========================================

const aiSecurityInsight =
  analysisResult?.ai_security_insight || {};

const aiRemediation =
  analysisResult?.ai_remediation || {};

const aiSecureCode =
  analysisResult?.secure_code || "";

const aiComparison =
  analysisResult?.ai_comparison || {};
const aiInsightConfidence = Math.round(
  Number(aiSecurityInsight.confidence ?? 0)
);

const remediationActions =
  Array.isArray(aiRemediation.actions)
    ? aiRemediation.actions
    : [];

const correctedCode =
  aiSecureCode ||
  "// AI secure code is not available for this analysis.";

const vulnerabilities =
  analysisResult?.vulnerabilities?.map((finding, index) => {
    const primaryLine =
      finding.line ||
      finding.primary_line ||
      finding.sink?.line ||
      0;

    const affectedLines =
      Array.isArray(finding.affected_lines) &&
      finding.affected_lines.length > 0
        ? finding.affected_lines
            .map(Number)
            .filter((line) => Number.isFinite(line) && line > 0)
        : primaryLine
          ? [Number(primaryLine)]
          : [];

    return {
      id: finding.id || index + 1,

      severity:
        finding.severity || "LOW",

      title:
        finding.type || "Security Issue",

      line:
        `Line ${String(primaryLine).padStart(2, "0")}`,

      primaryLine:
        Number(primaryLine),

      short:
        finding.description ||
        "Security issue detected.",

      why:
        finding.ai_why ||
        finding.ai_assessment?.why ||
        finding.why ||
        "AI explanation is not available for this finding.",

      impact:
        finding.ai_impact ||
        finding.ai_assessment?.impact ||
        finding.impact ||
        "AI impact analysis is not available for this finding.",

      fix:
        finding.ai_fix ||
        finding.ai_assessment?.fix ||
        finding.fix ||
        "AI remediation is not available for this finding.",

      confidence:
        finding.ai_confidence ??
        finding.severity_confidence ??
        finding.confidence ??
        0,

      source:
        finding.source || null,

      evidence:
        Array.isArray(finding.evidence)
          ? finding.evidence
          : [],

      sink:
        finding.sink || null,

      affectedLines,

      location:
        finding.location || {},

      evidenceLevel:
        finding.evidence_level || null,

      analysisMethod:
        finding.analysis_method || null,

      secretVariable:
        finding.variable || null,

      secretFormat:
        finding.secret_format || null,

      entropy:
        finding.entropy ?? null,

      placeholder:
        finding.placeholder ?? false,
    };
  }) || [];
const severityPriority = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const primaryFinding =
  [...vulnerabilities].sort(
    (a, b) =>
      (severityPriority[b.severity] || 0) -
      (severityPriority[a.severity] || 0)
  )[0] || null;

const detectedIssueLabel = primaryFinding
  ? issuesFound > 1
    ? `${primaryFinding.title} + ${issuesFound - 1} more`
    : primaryFinding.title
  : "No confirmed issue";

const secureFileName =
  fileName && fileName !== "untitled.code"
    ? `secure-${fileName}`
    : "secure-fix.code";

  const getEvidenceLineLabel = (item) => {
  if (!item) return "";

  const start =
    item.start_line ||
    item.line ||
    item.location?.start_line;

  const end =
    item.end_line ||
    item.line ||
    item.location?.end_line ||
    start;

  if (!start) return "";

  if (start === end) {
    return `Line ${String(start).padStart(2, "0")}`;
  }

  return `Lines ${String(start).padStart(2, "0")}–${String(
    end
  ).padStart(2, "0")}`;
};


const getEvidenceCode = (item) => {
  if (!item) return "";

  return (
    item.code ||
    item.text ||
    item.snippet ||
    item.expression ||
    ""
  );
};


const getFindingFlow = (finding) => {
  const flow = [];

  if (
  finding.title
    ?.toLowerCase()
    .includes("buffer overflow")
) {
  const flow = [];

  if (finding.source) {
    flow.push({
      ...finding.source,
      role: "buffer_declaration",
    });
  }

  if (finding.sink) {
    flow.push({
      ...finding.sink,
      role: "unsafe_write",
    });
  }

  return flow;
}

  if (finding.source) {
    flow.push({
      ...finding.source,
      role: "source",
    });
  }

  if (Array.isArray(finding.evidence)) {
    finding.evidence.forEach((item) => {
      const role = String(
        item.role ||
        item.kind ||
        item.type ||
        "propagation"
      ).toLowerCase();

      if (role === "source" || role === "sink") {
        return;
      }

      flow.push({
        ...item,
        role: "propagation",
      });
    });
  }

  if (finding.sink) {
    flow.push({
      ...finding.sink,
      role: "sink",
    });
  }

  return flow;
};


const formatAffectedLines = (lines = []) => {
  const numbers = [
    ...new Set(
      lines
        .map(Number)
        .filter(
          (line) =>
            Number.isFinite(line) && line > 0
        )
    ),
  ].sort((a, b) => a - b);

  if (numbers.length === 0) {
    return "No exact line information";
  }

  const ranges = [];

  let start = numbers[0];
  let previous = numbers[0];

  for (let i = 1; i <= numbers.length; i += 1) {
    const current = numbers[i];

    if (current === previous + 1) {
      previous = current;
      continue;
    }

    ranges.push(
      start === previous
        ? String(start).padStart(2, "0")
        : `${String(start).padStart(
            2,
            "0"
          )}–${String(previous).padStart(
            2,
            "0"
          )}`
    );

    start = current;
    previous = current;
  }

  return ranges.join(", ");
};


const affectedLineMap = new Map();

vulnerabilities.forEach((finding) => {
  finding.affectedLines.forEach((line) => {
    if (!affectedLineMap.has(line)) {
      affectedLineMap.set(line, finding);
    }
  });
});

  

  const handleCopyCode = async () => {
    try {
      await navigator.clipboard.writeText(correctedCode);

      setCopied(true);

      setTimeout(() => {
        setCopied(false);
      }, 1800);
    } catch (error) {
      console.error("Unable to copy code:", error);
    }
  };


  const handleNewReview = () => {
    navigate("/features");
  };


  const handleDownloadReport = async () => {
    const token = getStoredToken();

    // 1. If user is NOT logged in:
    // - Do not call the PDF endpoint
    // - Do not show the raw backend alert
    // - Show the professional modal
    if (!token) {
      setShowAuthModal(true);
      return;
    }

    // 2. If user IS logged in:
    // - Send the JWT access token with the report request:
    //   Authorization: Bearer <access_token>
    // - PDF download should work normally
    try {
      const response = await fetch(`${API_BASE_URL}/reports/pdf`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        credentials: "include",
        body: JSON.stringify({
          file_name: fileName,
          language: language,
          code: sourceCode,
          security_score: securityScore,
          issues_found: issuesFound,
          severity_counts: severityCounts,
          vulnerabilities: analysisResult?.vulnerabilities || [],
          ai_security_insight: analysisResult?.ai_security_insight || {},
          ai_remediation: analysisResult?.ai_remediation || {},
          secure_code: analysisResult?.secure_code || "",
          ai_comparison: analysisResult?.ai_comparison || {},
          analysis_time_ms: analysisResult?.analysis_time_ms || 0,
          analysis_time_seconds: analysisResult?.analysis_time_seconds || 0,
        }),
      });

      // If token expired or invalid (401), open login/register modal instead of raw alert
      if (response.status === 401) {
        localStorage.removeItem("token");
        setShowAuthModal(true);
        return;
      }

      if (!response.ok) {
        let detailMsg = "";
        try {
          const errorData = await response.json();
          detailMsg = errorData?.detail || "";
        } catch (_) {}

        if (detailMsg && detailMsg.toLowerCase().includes("authentication")) {
          localStorage.removeItem("token");
          setShowAuthModal(true);
          return;
        }

        throw new Error(
          detailMsg || `PDF generation failed with status ${response.status}`
        );
      }

      const pdfBlob = await response.blob();
      const downloadUrl = URL.createObjectURL(pdfBlob);
      const anchor = document.createElement("a");
      const safeFileName = fileName
        .replace(/\.[^/.]+$/, "")
        .replace(/[^a-zA-Z0-9-_]/g, "-");

      anchor.href = downloadUrl;
      anchor.download = `${safeFileName || "SecureCode-AI"}-security-report.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(downloadUrl);
    } catch (error) {
      console.error("Unable to download PDF report:", error);
      // Suppress any raw auth credential errors from alert
      if (
        error?.message &&
        (error.message.toLowerCase().includes("credentials") ||
          error.message.toLowerCase().includes("authentication") ||
          error.message.includes("401"))
      ) {
        setShowAuthModal(true);
      } else {
        alert(
          "PDF report could not be generated. Please make sure the backend is running."
        );
      }
    }
  };



  const toggleFinding = (id) => {
    setOpenFinding((current) =>
      current === id ? null : id
    );
  };


  return (
    <main className="dashboard-page">

      {/* ===============================
          BACKGROUND VISUALS
      =============================== */}

      <div className="dashboard-grid-background" />

      <div className="dashboard-glow dashboard-glow-one" />
      <div className="dashboard-glow dashboard-glow-two" />

      <span className="dashboard-floating-symbol dashboard-symbol-one">
        {"</>"}
      </span>

      <span className="dashboard-floating-symbol dashboard-symbol-two">
        {"{ }"}
      </span>

      <span className="dashboard-floating-symbol dashboard-symbol-three">
        AI
      </span>


      {/* ===============================
          HEADER
      =============================== */}

      <header className="dashboard-header">

        <Link
          to="/home"
          className="dashboard-brand"
        >
          <span className="dashboard-brand-icon">
            <ShieldCheck
              size={27}
              strokeWidth={1.9}
            />
          </span>

          <span className="dashboard-brand-name">
            SecureCode <strong>AI</strong>
          </span>
        </Link>


        <button
          type="button"
          className="dashboard-new-review"
          onClick={handleNewReview}
        >
          <RotateCcw size={19} />

          New Review
        </button>

      </header>


      <div className="dashboard-container">

        {/* ===============================
            INTRO
        =============================== */}

        <section className="dashboard-intro">

          <div className="dashboard-intro-left">

            <div className="analysis-complete-badge">
              <CircleCheck size={17} />

              ANALYSIS COMPLETE
            </div>

            <h1>
              Security Analysis
            </h1>

            <p>
              Review identified risks, affected code,
              security insights and recommended remediation.
            </p>


            <div className="dashboard-file-meta">

              <FileCode2 size={20} />

              <span>{fileName}</span>

              <i />

              <span>{language}</span>

              <i />

              <span className="complete-meta">
                Completed
              </span>

            </div>

          </div>


          <div className="dashboard-engine-status">

            <span className="engine-live-dot" />

            <div>
              <small>
                SECURECODE ENGINE
              </small>

              <strong>
                Analysis Ready
              </strong>
            </div>

          </div>

        </section>



        {/* ===============================
            SUMMARY CARDS
        =============================== */}

        <section className="dashboard-summary-grid">

          {/* LANGUAGE */}

          <article className="summary-card">

            <div className="summary-card-header">

              <span>Language</span>

              <div className="summary-icon">
                <Code2 size={21} />
              </div>

            </div>

            <strong className="summary-main-value">
              {language}
            </strong>

            <p>
              Source language detected
            </p>

          </article>


          {/* SCORE */}

          <article className="summary-card security-score-card">

            <div className="summary-card-header">

              <span>Security Score</span>

              <div className="summary-icon">
                <ShieldCheck size={21} />
              </div>

            </div>


            <div className="score-content">

              <div className="security-score-ring">

                <div>
                  <strong>{securityScore}</strong>

                  <span>/100</span>
                </div>

              </div>


              <div className="score-text">

                <strong>
                  {issuesFound > 0 ? "Needs Review" : "Secure"}
                </strong>

                <p>
                  Security improvements recommended
                </p>

              </div>

            </div>

          </article>


          {/* STATUS */}

          <article className="summary-card">

            <div className="summary-card-header">

              <span>Status</span>

              <div className="summary-icon warning-summary-icon">
                <ShieldAlert size={21} />
              </div>

            </div>

            <strong className="summary-main-value status-review">
              {issuesFound > 0 ? "Needs Review" : "Secure"}
            </strong>

            

          </article>


          {/* ANALYSIS TIME */}

          <article className="summary-card">

            <div className="summary-card-header">

              <span>Analysis Time</span>

              <div className="summary-icon">
                <Clock size={21} />
              </div>

            </div>

            <strong className="summary-main-value">
              {analysisTimeMs >= 1000
    ? `${(analysisTimeMs / 1000).toFixed(2)} sec`
    : `${analysisTimeMs.toFixed(2)} ms`}
            </strong>

            <p>
              Security review completed
            </p>

          </article>

        </section>



        {/* ===============================
            SEVERITY
        =============================== */}

        <section className="dashboard-section severity-section">

  <div className="dashboard-section-heading">
    <div>
      <span>SECURITY OVERVIEW</span>

      <h2>Severity Summary</h2>

      <p>
        Findings grouped by their estimated
        security impact.
      </p>
    </div>

    <TriangleAlert size={25} />
  </div>


  <div className="severity-layout">

    <div className="severity-card-grid">

      {/* CRITICAL */}
      <article className="severity-card severity-critical">
        <span>Critical</span>

        <strong>
          {String(severityCounts.critical).padStart(2, "0")}
        </strong>

        <p>Immediate risks</p>
      </article>


      {/* HIGH */}
      <article className="severity-card severity-high">
        <span>High</span>

        <strong>
          {String(severityCounts.high).padStart(2, "0")}
        </strong>

        <p>Priority findings</p>
      </article>


      {/* MEDIUM */}
      <article className="severity-card severity-medium">
        <span>Medium</span>

        <strong>
          {String(severityCounts.medium).padStart(2, "0")}
        </strong>

        <p>Review recommended</p>
      </article>


      {/* LOW */}
      <article className="severity-card severity-low">
        <span>Low</span>

        <strong>
          {String(severityCounts.low).padStart(2, "0")}
        </strong>

        <p>Minor findings</p>
      </article>

    </div>


    {/* RISK DISTRIBUTION */}
    <div className="risk-distribution-card">

      <div className="risk-distribution-heading">
        <div>
          <span>RISK DISTRIBUTION</span>
          <h3>Finding Distribution</h3>
        </div>

        <ScanSearch size={22} />
      </div>


      <div className="risk-distribution-list">

        {/* HIGH */}
        <div className="risk-distribution-row">

          <div className="risk-row-label">
            <span>High</span>

            <strong>
              {String(severityCounts.high).padStart(2, "0")}
            </strong>
          </div>

          <div className="risk-progress-track">
            <span className="risk-progress-high" />
          </div>

        </div>


        {/* MEDIUM */}
        <div className="risk-distribution-row">

          <div className="risk-row-label">
            <span>Medium</span>

            <strong>
              {String(severityCounts.medium).padStart(2, "0")}
            </strong>
          </div>

          <div className="risk-progress-track">
            <span className="risk-progress-medium" />
          </div>

        </div>


        {/* LOW */}
        <div className="risk-distribution-row">

          <div className="risk-row-label">
            <span>Low</span>

            <strong>
              {String(severityCounts.low).padStart(2, "0")}
            </strong>
          </div>

          <div className="risk-progress-track">
            <span className="risk-progress-low" />
          </div>

        </div>

      </div>

    </div>

  </div>

</section>


        {/* ===============================
            VULNERABILITIES
        =============================== */}

        <section className="dashboard-section vulnerabilities-section">

          <div className="dashboard-section-heading">

            <div>
              <span>
                SECURITY FINDINGS
              </span>

              <h2>
                Detected Vulnerabilities
              </h2>

              <p>
                Review potential security issues found
                during the code analysis.
              </p>
            </div>

            <Bug size={25} />

          </div>


          <div className="vulnerability-list">

            {vulnerabilities.map((finding) => {

              const isOpen =
                openFinding === finding.id;

              return (
                <article
                  key={finding.id}
                  className={`vulnerability-card severity-${finding.severity.toLowerCase()}-finding ${
                    isOpen
                      ? "vulnerability-card-open"
                      : ""
                  }`}
                >

                  <button
                    type="button"
                    className="vulnerability-main"
                    onClick={() =>
                      toggleFinding(finding.id)
                    }
                  >

                    <div className="vulnerability-left">

                      <div
                        className={`vulnerability-badge vulnerability-${finding.severity.toLowerCase()}`}
                      >
                        {finding.severity}
                      </div>


                      <div className="vulnerability-title-area">

                        <h3>
                          {finding.title}
                        </h3>

                        <p>
                          {finding.short}
                        </p>

                      </div>

                    </div>


                    <div className="vulnerability-right">

                      <span className="vulnerability-line">
                        {finding.line}
                      </span>


                      <span className="view-details-text">

                        {isOpen
                          ? "Hide Details"
                          : "View Details"}

                        {isOpen ? (
                          <ChevronUp size={19} />
                        ) : (
                          <ChevronDown size={19} />
                        )}

                      </span>

                    </div>

                  </button>


                  {isOpen && (
                    <div className="vulnerability-details">
                    {finding.title === "Hardcoded Secret" && (
  <div className="finding-flow-section">

    <div className="finding-flow-header">
      <div>
        <span>SECRET EVIDENCE</span>
        <h4>Hardcoded Credential Analysis</h4>
      </div>

      {finding.evidenceLevel && (
        <strong className="evidence-level-badge">
          {finding.evidenceLevel
            .replaceAll("_", " ")
            .toUpperCase()}
        </strong>
      )}
    </div>

    <div className="finding-detail-box">
      <span>Sensitive Variable</span>
      <p>
        {finding.secretVariable || "Unknown"}
      </p>
    </div>

    <div className="finding-detail-box">
      <span>Secret Format</span>
      <p>
        {finding.secretFormat || "Sensitive literal"}
      </p>
    </div>

    <div className="finding-detail-box">
      <span>Entropy</span>
      <p>
        {finding.entropy !== null
          ? finding.entropy
          : "Not available"}
      </p>
    </div>

    <div className="finding-detail-box">
      <span>Detection Confidence</span>
      <p>{finding.confidence}%</p>
    </div>

    <div className="affected-lines-summary">
      <span>Secret Declaration Line</span>

      <strong>
        {formatAffectedLines(
          finding.affectedLines
        )}
      </strong>
    </div>

    {finding.analysisMethod && (
      <div className="analysis-method-summary">
        <span>Analysis Method</span>

        <strong>
          {finding.analysisMethod}
        </strong>
      </div>
    )}

  </div>
)}
{finding.title !== "Hardcoded Secret" &&
  getFindingFlow(finding).length > 0 && (
  <div className="finding-flow-section">

    <div className="finding-flow-header">
      <div>
        <span>DATA-FLOW EVIDENCE</span>
        <h4>
          {finding.title
            ?.toLowerCase()
            .includes("buffer overflow")
            ? "Buffer Declaration → Unsafe Write"
            : "Source → Propagation → Sink"}
        </h4>
      </div>

      {finding.evidenceLevel && (
        <strong className="evidence-level-badge">
          {finding.evidenceLevel
            .replaceAll("_", " ")
            .toUpperCase()}
        </strong>
      )}
    </div>


    <div className="finding-flow-list">

      {getFindingFlow(finding).map(
        (item, flowIndex) => {

          const role =
            item.role ||
            item.type ||
            (flowIndex === 0
              ? "source"
              : flowIndex ===
                  getFindingFlow(finding).length - 1
                ? "sink"
                : "propagation");

          return (
            <div
              className="finding-flow-step"
              key={`${finding.id}-${flowIndex}`}
            >

              <div
                className={`flow-role flow-role-${String(role).toLowerCase()}`}
              >
                {String(role).toUpperCase()}
              </div>


              <div className="flow-step-content">

                <span className="flow-line-label">
                  {getEvidenceLineLabel(item)}
                </span>

                {getEvidenceCode(item) && (
                  <code>
                    {getEvidenceCode(item)}
                  </code>
                )}

              </div>


              {flowIndex <
                getFindingFlow(finding).length -
                  1 && (
                <div className="flow-arrow">
                  ↓
                </div>
              )}

            </div>
          );
        }
      )}

    </div>


    <div className="affected-lines-summary">
      <span>
        Exact Affected Lines
      </span>

      <strong>
        {formatAffectedLines(
          finding.affectedLines
        )}
      </strong>
    </div>


    {finding.analysisMethod && (
      <div className="analysis-method-summary">
        <span>Analysis Method</span>

        <strong>
          {finding.analysisMethod}
        </strong>
      </div>
    )}

  </div>
)}

                      <div className="finding-detail-box">

                        <span>
                          Why this matters
                        </span>

                        <p>
                          {finding.why}
                        </p>

                      </div>


                      <div className="finding-detail-box impact-box">

                        <span>
                          Potential Impact
                        </span>

                        <p>
                          {finding.impact}
                        </p>

                      </div>


                      <div className="finding-detail-box fix-box">

                        <span>
                          Recommended Fix
                        </span>

                        <p>
                          {finding.fix}
                        </p>

                      </div>

                    </div>
                  )}

                </article>
              );
            })}

          </div>

        </section>



        {/* ===============================
            CODE + AI
        =============================== */}

        <section className="dashboard-section">

          <div className="dashboard-section-heading">

            <div>
              <span>
                SECURITY CONTEXT
              </span>

              <h2>
                Code & AI Security Insight
              </h2>

              <p>
                Understand where the risk occurs
                and why it matters.
              </p>
            </div>

            <Sparkles size={25} />

          </div>


          <div className="code-insight-layout">

            {/* AFFECTED CODE */}

            <article className="affected-code-panel">

              <div className="panel-top">

                <div>
                  <FileCode2 size={21} />

                  <div>
                    <span>
                      AFFECTED CODE
                    </span>

                    <h3>
                      Vulnerable Source
                    </h3>
                  </div>

                </div>


                <span className="code-risk-badge">
  {issuesFound > 0
    ? `${issuesFound} AFFECTED FINDING${
        issuesFound > 1 ? "S" : ""
      }`
    : "NO AFFECTED CODE"}
</span>
              </div>


              <div className="code-viewer">

                <div className="code-scan-line" />

                {sourceCode
                  .split("\n")
                  .map((line, index) => {

                    const lineNumber =
                      index + 1;

                    const affectedFinding =
  affectedLineMap.get(lineNumber);

const risky =
  Boolean(affectedFinding);

                    return (
                      <div
                        className={`dashboard-code-line ${
                          risky
                            ? "dashboard-risky-code-line"
                            : ""
                        }`}
                        key={index}
                      >

                        <span className="dashboard-line-number">
                          {String(lineNumber).padStart(
                            2,
                            "0"
                          )}
                        </span>

                        <code>
                          {line || " "}
                        </code>

                        {risky && (
  <span className="code-line-warning">
    {affectedFinding.severity}
  </span>
)}

                      </div>
                    );
                  })}

              </div>

            </article>



            {/* AI INSIGHT */}

            <article className="ai-insight-panel">

              <div className="ai-panel-glow" />

              <div className="panel-top">

                <div>
                  <Sparkles size={21} />

                  <div>
                    <span>
                      AI SECURITY INSIGHT
                    </span>

                    <h3>
                      Intelligent Explanation
                    </h3>
                  </div>

                </div>


                <span className="ai-badge">
                  AI
                </span>

              </div>


              <div className="ai-insight-content">
                <div className="ai-insight-item">
                  <div className="ai-insight-icon">
                    <Lightbulb size={20} />
                  </div>

                  <div>
                    <h4>Why this matters</h4>
                    <p>
                      {aiSecurityInsight.why_it_matters ||
                        "AI security insight is not available for this analysis."}
                    </p>
                  </div>
                </div>

                <div className="ai-insight-item">
                  <div className="ai-insight-icon warning-ai-icon">
                    <CircleAlert size={20} />
                  </div>

                  <div>
                    <h4>Potential Impact</h4>
                    <p>
                      {aiSecurityInsight.potential_impact ||
                        "AI impact analysis is not available for this analysis."}
                    </p>
                  </div>
                </div>

                <div className="ai-confidence">
                  <span>Analysis Confidence</span>

                  <div className="ai-confidence-bar">
                    <span
                      style={{
                        width: `${Math.min(100, Math.max(0, aiInsightConfidence))}%`,
                      }}
                    />
                  </div>

                  <strong>{aiInsightConfidence}%</strong>
                </div>
              </div>

            </article>

          </div>

        </section>



        {/* ===============================
            REMEDIATION
        =============================== */}

        <section className="dashboard-section">
          <div className="remediation-panel">
            <div className="remediation-icon">
              <WandSparkles size={27} />
            </div>

            <div className="remediation-content">
              <span>RECOMMENDED REMEDIATION</span>

              <h2>
                {aiRemediation.title || "AI Remediation"}
              </h2>

              <p>
                {aiRemediation.summary ||
                  "AI remediation is not available for this analysis."}
              </p>

              <div className="remediation-points">
                {remediationActions.length > 0 ? (
                  remediationActions.map((action, index) => (
                    <span key={`remediation-${index}`}>
                      <CircleCheck size={18} />
                      {action}
                    </span>
                  ))
                ) : (
                  <span>
                    <CircleAlert size={18} />
                    No AI remediation actions were returned.
                  </span>
                )}
              </div>
            </div>
          </div>
        </section>



        {/* ===============================
            CORRECTED CODE
        =============================== */}

        <section className="dashboard-section corrected-code-section">

          <div className="dashboard-section-heading">

            <div>
              <span>
                SECURE REMEDIATION
              </span>

              <h2>
                Corrected / Secure Code
              </h2>

              <p>
                Review the suggested safer
                implementation before applying it.
              </p>
            </div>

            <ShieldCheck size={25} />

          </div>


          <div className="corrected-code-card">

            <div className="corrected-code-toolbar">

              <div className="corrected-code-file">

                <FileCode2 size={20} />

                <div>
                  <strong>
                    {secureFileName}
                  </strong>

                  <span>
                    Suggested remediation
                  </span>
                </div>

              </div>


              <button
                type="button"
                className={`copy-code-button ${
                  copied
                    ? "copy-code-success"
                    : ""
                }`}
                onClick={handleCopyCode}
              >

                {copied ? (
                  <>
                    <Check size={18} />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy size={18} />
                    Copy Code
                  </>
                )}

              </button>

            </div>


            <div className="corrected-code-viewer">

              {correctedCode
                .split("\n")
                .map((line, index) => (
                  <div
                    className="secure-code-line"
                    key={index}
                  >

                    <span>
                      {String(index + 1).padStart(
                        2,
                        "0"
                      )}
                    </span>

                    <code>
                      {line || " "}
                    </code>

                  </div>
                ))}

            </div>

          </div>

        </section>

        {/* =========================================
    SECURITY FIX COMPARISON
========================================= */}

<section className="dashboard-section fix-comparison-section">

  <div className="dashboard-section-heading">
    <div>
      <span>SECURITY FIX COMPARISON</span>
      <h2>Why is the corrected code better?</h2>
    </div>

    <p>
      AI-generated comparison of the submitted implementation and the
      recommended secure version.
    </p>
  </div>

  <div className="fix-comparison-grid">

    {/* ORIGINAL */}
    <article className="comparison-code-card original-comparison-card">
      <div className="comparison-card-header">
        <div className="comparison-header-icon original-icon">
          <TriangleAlert size={23} />
        </div>

        <div>
          <span>USER SUBMISSION</span>
          <h3>Original Code</h3>
        </div>

        <span className="comparison-status original-status">
          {issuesFound > 0 ? "NEEDS REVIEW" : "SECURE"}
        </span>
      </div>

      <div className="comparison-summary">
        <div>
          <span>Security Status</span>
          <strong className="comparison-risk-text">
            {aiComparison.original_security_status ||
              (issuesFound > 0 ? "Higher Risk" : "No Confirmed Risk")}
          </strong>
        </div>

        <div>
          <span>Detected Issue</span>
          <strong>{detectedIssueLabel}</strong>
        </div>

        <div>
          <span>Severity</span>
          <strong className="comparison-high-text">
            {primaryFinding?.severity || "NONE"}
          </strong>
        </div>
      </div>

      <div className="comparison-explanation">
        <span>WHY THIS CODE IS AFFECTED</span>
        <p>
          {aiComparison.original_reason ||
            aiSecurityInsight.why_it_matters ||
            primaryFinding?.why ||
            "AI comparison reasoning is not available for this analysis."}
        </p>
      </div>

      <div className="comparison-points">
        {vulnerabilities.length > 0 ? (
          vulnerabilities.slice(0, 3).map((finding) => (
            <span
              className="comparison-negative-point"
              key={`original-${finding.id}`}
            >
              <TriangleAlert size={17} />
              {finding.title} — {finding.line}
            </span>
          ))
        ) : (
          <span className="comparison-positive-point">
            <CircleCheck size={17} />
            No confirmed vulnerable finding was detected.
          </span>
        )}
      </div>
    </article>

    {/* CORRECTED */}
    <article className="comparison-code-card corrected-comparison-card">
      <div className="comparison-card-header">
        <div className="comparison-header-icon corrected-icon">
          <ShieldCheck size={23} />
        </div>

        <div>
          <span>SECURE RECOMMENDATION</span>
          <h3>Corrected Code</h3>
        </div>

        <span className="comparison-status corrected-status">
          {aiSecureCode ? "RECOMMENDED" : "AI PENDING"}
        </span>
      </div>

      <div className="comparison-summary">
        <div>
          <span>Security Status</span>
          <strong className="comparison-safe-text">
            {aiComparison.corrected_security_status ||
              (aiSecureCode ? "Safer" : "Not Available")}
          </strong>
        </div>

        <div>
          <span>Risk Handling</span>
          <strong>{aiSecureCode ? "AI Improved" : "Pending"}</strong>
        </div>

        <div>
          <span>Recommendation</span>
          <strong className="comparison-safe-text">
            {aiSecureCode ? "REVIEW & APPLY" : "WAIT"}
          </strong>
        </div>
      </div>

      <div className="comparison-explanation">
        <span>WHY THIS CODE IS RECOMMENDED</span>
        <p>
          {aiComparison.corrected_reason ||
            aiComparison.security ||
            aiRemediation.summary ||
            (primaryFinding?.fix
              ? `Remediates ${primaryFinding.title} (${primaryFinding.line}) by applying recommended security practices: ${primaryFinding.fix}`
              : "Remediates detected vulnerabilities and eliminates insecure execution sinks.")}
        </p>
      </div>

      <div className="comparison-points">
        {[aiComparison.security, aiComparison.validation, aiComparison.functionality]
          .filter(Boolean)
          .length > 0 ? (
          [aiComparison.security, aiComparison.validation, aiComparison.functionality]
            .filter(Boolean)
            .map((point, index) => (
              <span
                className="comparison-positive-point"
                key={`corrected-${index}`}
              >
                <CircleCheck size={17} />
                {point}
              </span>
            ))
        ) : (
          <span className="comparison-positive-point">
            <CircleCheck size={17} />
            {primaryFinding?.fix || "Remediates detected vulnerabilities with secure code practices."}
          </span>
        )}
      </div>
    </article>
  </div>

  {/* AI REASONING */}
  <div className="why-better-panel">
    <div className="why-better-heading">
      <div className="why-better-icon">
        <WandSparkles size={25} />
      </div>

      <div>
        <span>AI SECURITY REASONING</span>
        <h3>Why choose the corrected code?</h3>
      </div>
    </div>

    <div className="why-better-grid">
      <article>
        <span>01</span>
        <h4>Security</h4>
        <p>
          {aiComparison.security ||
            (primaryFinding
              ? `Eliminates ${primaryFinding.title} security flaw by applying safe coding practices.`
              : "Maintains safe baseline security.")}
        </p>
      </article>

      <article>
        <span>02</span>
        <h4>Validation</h4>
        <p>
          {aiComparison.validation ||
            "Input validation and boundary checks enforced on incoming data."}
        </p>
      </article>

      <article>
        <span>03</span>
        <h4>Functionality</h4>
        <p>
          {aiComparison.functionality ||
            "Core business logic, routes, and function signatures preserved."}
        </p>
      </article>

      <article>
        <span>04</span>
        <h4>Maintainability</h4>
        <p>
          {aiComparison.maintainability ||
            "Structured according to clean code and security best practices."}
        </p>
      </article>

      <article>
        <span>05</span>
        <h4>Performance</h4>
        <p>
          {aiComparison.performance ||
            "Executes with minimal constant-time overhead for security validation."}
        </p>
      </article>

      <article>
        <span>06</span>
        <h4>Time Complexity</h4>
        <p>
          {aiComparison.original_time_complexity && aiComparison.corrected_time_complexity
            ? `${aiComparison.original_time_complexity} → ${aiComparison.corrected_time_complexity}${aiComparison.complexity_reason ? ` · ${aiComparison.complexity_reason}` : ""}`
            : aiComparison.complexity_reason || "O(1) constant-time validation overhead."}
        </p>
      </article>

      <article>
        <span>07</span>
        <h4>Space Complexity</h4>
        <p>
          {aiComparison.original_space_complexity && aiComparison.corrected_space_complexity
            ? `${aiComparison.original_space_complexity} → ${aiComparison.corrected_space_complexity}`
            : "O(1) auxiliary space."}
        </p>
      </article>
    </div>
  </div>

  {/* FINAL VERDICT */}
  <div className="fix-verdict-panel">
    <div className="fix-verdict-icon">
      <ShieldCheck size={28} />
    </div>

    <div className="fix-verdict-content">
      <span>FINAL RECOMMENDATION</span>
      <h3>AI Security Recommendation</h3>
      <p>
        {aiComparison.final_recommendation ||
          (primaryFinding
            ? `Review and apply the recommended fix for ${primaryFinding.title} before production deployment.`
            : "Code meets security standards and is approved for deployment.")}
      </p>
    </div>

    <div className="fix-verdict-badge">
      <CircleCheck size={18} />
      {aiSecureCode ? "AI REVIEWED" : "PENDING"}
    </div>
  </div>

</section>



        {/* ===============================
            BOTTOM ACTIONS
        =============================== */}

        <section className="dashboard-bottom-actions">

          <div>

            <ShieldCheck size={22} />

            <p>
              Security analysis completed.
              Review all findings before applying
              suggested changes.
            </p>

          </div>


          <div className="dashboard-action-buttons">

            <button
              type="button"
              className="bottom-new-review-button"
              onClick={handleNewReview}
            >
              <RotateCcw size={19} />

              New Review
            </button>


            <button
              type="button"
              className="download-report-button"
              onClick={handleDownloadReport}
            >
              <Download size={19} />

              Download Report
            </button>

          </div>

        </section>

      </div>
      {/* BACK TO FEATURES */}

<div className="dashboard-back-features">
  <button
    type="button"
    className="back-features-arrow"
    onClick={() => navigate("/features")}
    aria-label="Back to Code Review"
  >
    <ChevronDown size={28} />
  </button>

  <span>Back to Code Review</span>
</div>


      <footer className="dashboard-footer">

        <ShieldCheck size={18} />

        SecureCode AI · Intelligent Security Analysis

      </footer>

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
              border: "1px solid rgba(59, 130, 246, 0.35)",
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
                backgroundColor: "rgba(59, 130, 246, 0.12)",
                color: "#60a5fa",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                margin: "0 auto 18px auto",
                border: "1px solid rgba(59, 130, 246, 0.25)",
              }}
            >
              <Lock size={28} />
            </div>

            <h3
              style={{
                fontSize: "20px",
                fontWeight: 700,
                color: "#ffffff",
                marginBottom: "10px",
              }}
            >
              Sign In Required
            </h3>

            <p
              style={{
                fontSize: "15px",
                fontWeight: 500,
                color: "#e2e8f0",
                lineHeight: "1.6",
                marginBottom: "24px",
              }}
            >
              Sign in to download your complete security report.
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
                Log In
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
                Register
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}


export default AnalysisDashboard;
