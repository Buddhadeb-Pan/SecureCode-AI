import { useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  Code2,
  SearchCode,
  Shield,
  TriangleAlert,
  WandSparkles,
  FileChartColumn,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  ChevronDown,
  Sparkles,
  Lock,
  Layers,
  FileCode,
  Check,
  Terminal,
  Activity,
  Cpu,
  FileText,
  AlertOctagon,
  Scale,
} from "lucide-react";

import "./FeatureDetail.css";

const FEATURES_DATA = {
  "smart-code-analysis": {
    slug: "smart-code-analysis",
    number: "01",
    title: "Smart Code Analysis",
    icon: <SearchCode size={26} />,
    heroPurpose:
      "Understands the submitted source code structure and language environment before executing security inspection.",
    whatItDoes:
      "Before running deep security checks, SecureCode AI identifies the programming language, parses syntax, and prepares language-aware structural models. This ensures static rules, AST inspection, and contextual analysis are tailored specifically to the programming language rather than treating source code as raw unstructured text.",
    whatBullets: [
      "Auto-detects language from file extensions, syntax patterns, or manual selection",
      "Performs language-aware parsing using AST, Tree-sitter, or supported static models",
      "Extracts functions, call graphs, variables, and control structures",
      "Normalizes findings into a consistent structure with line-level evidence",
    ],
    howItWorksSteps: [
      {
        num: "01",
        title: "Source Code Input",
        desc: "Developer inputs source code directly or uploads a supported file into the workspace.",
        icon: <Code2 size={20} />,
      },
      {
        num: "02",
        title: "Language Detection",
        desc: "Identifies the language environment (Python, C/C++, Java, JS/TS, Go, Rust, PHP, C#).",
        icon: <SearchCode size={20} />,
      },
      {
        num: "03",
        title: "Language-Aware Parsing",
        desc: "Parses syntax into abstract syntax trees (AST) and language-specific structural models.",
        icon: <Layers size={20} />,
      },
      {
        num: "04",
        title: "Rules & Flow Inspection",
        desc: "Applies taint, pattern, and contextual inspection suited to that specific language.",
        icon: <Cpu size={20} />,
      },
      {
        num: "05",
        title: "Normalized Findings",
        desc: "Standardizes security observations with accurate line references and evidence.",
        icon: <CheckCircle2 size={20} />,
      },
    ],
    howItWorksNote:
      "Note: Analysis techniques depend on the programming language and vulnerability type. Techniques vary appropriately by runtime environment.",
    whatYouGet: [
      {
        icon: <FileCode size={20} />,
        title: "Detected Language",
        desc: "Identifies programming language, syntax version, and file context.",
      },
      {
        icon: <AlertOctagon size={20} />,
        title: "Relevant Security Findings",
        desc: "Language-specific vulnerability detections tailored to framework semantics.",
      },
      {
        icon: <Layers size={20} />,
        title: "Affected Code & Lines",
        desc: "Precise line numbers highlighting exactly where suspicious logic begins and ends.",
      },
      {
        icon: <Terminal size={20} />,
        title: "Analysis Evidence",
        desc: "Concrete evidence extracted directly from code structure and data-flow paths.",
      },
    ],
    example: {
      sourceLabel: "Input / Source Code (Python)",
      sourceCode: `def read_user_file(filename):\n    # Unsanitized path concatenation\n    with open("/var/uploads/" + filename) as f:\n        return f.read()`,
      detectTitle: "What SecureCode AI Detects",
      detectText:
        "Identifies language as Python. Parses AST and detects direct string concatenation inside open(), creating a Path Traversal vulnerability (CWE-22) where an attacker can access unauthorized files using directory navigation.",
      recommendTitle: "What SecureCode AI Recommends",
      recommendText:
        "Validate input using path normalization: os.path.basename(filename) or pathlib.Path.resolve() combined with a base directory check to guarantee the path remains within /var/uploads/.",
    },
    whyItMatters:
      "Every programming language has distinct security models, standard libraries, and syntax idioms. Analyzing code without language awareness leads to false alarms or missed vulnerabilities. By parsing code according to its specific language grammar, SecureCode AI ensures security findings are accurate, reproducible, and actionable.",
    pipelineStep: "Code",
  },

  "vulnerability-detection": {
    slug: "vulnerability-detection",
    number: "02",
    title: "Vulnerability Detection",
    icon: <Shield size={26} />,
    heroPurpose:
      "Identifies security weaknesses through deterministic rule scanning combined with contextual AI review.",
    whatItDoes:
      "SecureCode AI inspects source code for dangerous patterns and potential exploit vectors. It scans for SQL Injection, Cross-Site Scripting (XSS), Command Injection, Path Traversal, Hardcoded Secrets, Buffer Overflows (in native code), Unsafe Deserialization, and SSRF. It combines deterministic pattern matching with contextual AI inspection to evaluate both syntax flaws and surrounding program logic.",
    whatBullets: [
      "Scans for major vulnerability classes including SQLi, XSS, Command Injection, and Path Traversal",
      "Detects hardcoded secrets, API tokens, and insecure configuration defaults",
      "Rule engine identifies evidence-based source-to-sink data flow and known weakness signatures",
      "Contextual AI adds semantic reasoning on complex logic (without assuming AI is infallible)",
    ],
    howItWorksSteps: [
      {
        num: "01",
        title: "Untrusted Input",
        desc: "Identifies sources of external data: request parameters, HTTP headers, CLI args, or files.",
        icon: <Terminal size={20} />,
      },
      {
        num: "02",
        title: "Propagation & Pattern",
        desc: "Tracks how input travels through variables, functions, and transformations.",
        icon: <Activity size={20} />,
      },
      {
        num: "03",
        title: "Sensitive Sink",
        desc: "Checks whether untrusted input reaches critical sinks (database queries, system exec, DOM).",
        icon: <AlertOctagon size={20} />,
      },
      {
        num: "04",
        title: "Security Finding",
        desc: "Generates an evidence-backed security finding mapped to standard CWE definitions.",
        icon: <ShieldCheck size={20} />,
      },
    ],
    howItWorksNote:
      "Deterministic static rules verify evidence-based patterns and source/sink relationships. AI contextual review adds broader code comprehension to identify logic risks that pure regex cannot see.",
    whatYouGet: [
      {
        icon: <ShieldCheck size={20} />,
        title: "Vulnerability Type & CWE",
        desc: "Clear vulnerability name (e.g. SQL Injection) mapped to industry CWE identifiers.",
      },
      {
        icon: <Cpu size={20} />,
        title: "Detection Source",
        desc: "Indicates whether finding originated from static deterministic rules or contextual AI analysis.",
      },
      {
        icon: <Layers size={20} />,
        title: "Affected Code Lines",
        desc: "Pinpoints exactly which line and code snippet contains the security vulnerability.",
      },
      {
        icon: <Activity size={20} />,
        title: "Evidence & Data Flow",
        desc: "Explains how the untrusted source reaches the sensitive sink without required validation.",
      },
    ],
    example: {
      sourceLabel: "Input / Source Code (JavaScript)",
      sourceCode: `const query = "SELECT * FROM accounts WHERE id = '" + req.params.id + "'";\ndb.execute(query);`,
      detectTitle: "What SecureCode AI Detects",
      detectText:
        "SQL Injection (CWE-89): Untrusted request parameter `req.params.id` is concatenated directly into a raw SQL query string and passed to database execution sink.",
      recommendTitle: "What SecureCode AI Recommends",
      recommendText:
        "Use parameterized queries with placeholders: db.execute('SELECT * FROM accounts WHERE id = ?', [req.params.id]). Never concatenate external input directly into SQL statements.",
    },
    whyItMatters:
      "Vulnerabilities that reach production environments can lead to data exfiltration, system compromise, or unauthorized access. Identifying security weaknesses early in the development lifecycle allows engineers to resolve bugs before code is committed or deployed.",
    pipelineStep: "Detection",
  },

  "risk-severity": {
    slug: "risk-severity",
    number: "03",
    title: "Risk & Severity",
    icon: <TriangleAlert size={26} />,
    heroPurpose:
      "Organizes security findings by criticality and calculates an overall project-level security score.",
    whatItDoes:
      "Not all code issues present equal risk. SecureCode AI organizes all detected findings into four distinct severity levels: CRITICAL, HIGH, MEDIUM, and LOW. The severity classification considers multiple signals including vulnerability category, evidence strength, confidence, exploitability context, and deterministic analysis. It calculates a project-level Security Score from 0 to 100.",
    whatBullets: [
      "Categorizes issues into CRITICAL, HIGH, MEDIUM, and LOW tiers",
      "Evaluates multi-signal criteria: vulnerability type, confidence, evidence, and context",
      "Summarizes counts across all severity levels for rapid triage",
      "Computes a project-level Security Score representing overall health for the submitted code",
    ],
    howItWorksSteps: [
      {
        num: "01",
        title: "Severity Classification",
        desc: "Evaluates each finding based on potential exploit impact and attacker accessibility.",
        icon: <TriangleAlert size={20} />,
      },
      {
        num: "02",
        title: "Multi-Signal Scoring",
        desc: "Weighs vulnerability type, evidence confidence, and local ML severity when available.",
        icon: <Activity size={20} />,
      },
      {
        num: "03",
        title: "Summary Breakdown",
        desc: "Tallies the count of Critical, High, Medium, and Low vulnerabilities.",
        icon: <Layers size={20} />,
      },
      {
        num: "04",
        title: "Security Score",
        desc: "Calculates a 0–100 score as a project-level health indicator for the submitted analysis.",
        icon: <ShieldCheck size={20} />,
      },
    ],
    howItWorksNote:
      "The Security Score is a project-level security indicator for the submitted analysis, providing a clear reference for triage rather than a universal certification.",
    whatYouGet: [
      {
        icon: <AlertOctagon size={20} />,
        title: "CRITICAL Severity",
        desc: "Immediate threats such as Remote Code Execution or unauthenticated data exposure.",
      },
      {
        icon: <TriangleAlert size={20} />,
        title: "HIGH Severity",
        desc: "Severe risks such as SQL Injection, Stored XSS, or path traversal.",
      },
      {
        icon: <Activity size={20} />,
        title: "MEDIUM / LOW Severity",
        desc: "Validation hygiene, sensitive information leaks, and missing security safeguards.",
      },
      {
        icon: <Scale size={20} />,
        title: "Security Score (0–100)",
        desc: "Synthesized health rating indicating how secure the code is before and after fixes.",
      },
    ],
    example: {
      sourceLabel: "Triage Evaluation",
      sourceCode: `Finding A: os.system("rm -rf " + user_input)  --> CRITICAL (Arbitrary Command Execution)\nFinding B: Missing X-Frame-Options Header     --> LOW (Clickjacking Defense)`,
      detectTitle: "What SecureCode AI Detects",
      detectText:
        "Distinguishes critical server-compromise vectors from lower-risk configuration defenses, calculating an aggregate Security Score reflecting high-priority risks.",
      recommendTitle: "What SecureCode AI Recommends",
      recommendText:
        "Remediate CRITICAL and HIGH severity findings immediately before addressing lower-severity hygiene notices to maximize security risk reduction.",
    },
    whyItMatters:
      "Engineering teams face constant time constraints. Without severity ranking, developers waste time on minor style warnings while critical vulnerabilities remain unpatched. Risk scoring gives teams the clarity to prioritize the most dangerous threats first.",
    pipelineStep: "Severity",
  },

  "secure-fix-guidance": {
    slug: "secure-fix-guidance",
    number: "04",
    title: "Secure Fix Guidance",
    icon: <WandSparkles size={26} />,
    heroPurpose:
      "Provides clear explanations of why code is risky, its potential impact, and concrete remediation steps.",
    whatItDoes:
      "SecureCode AI does not merely flag errors and leave developers guessing. For every finding, it delivers structured guidance divided into three practical dimensions: WHY the code is risky, IMPACT of what could happen if exploited, and FIX explaining what should be changed. It provides concrete secure recommendations that preserve sound business logic.",
    whatBullets: [
      "WHY: Explains the underlying vulnerability mechanism in clear, practical terms",
      "IMPACT: Describes real-world consequences such as data leaks or account takeovers",
      "FIX: Delivers step-by-step remediation instructions tailored to the developer's code",
      "Preserves good existing business logic and avoids unnecessary full-file rewrites",
    ],
    howItWorksSteps: [
      {
        num: "01",
        title: "Vulnerable Code",
        desc: "Isolates the specific lines and operations creating the security vulnerability.",
        icon: <Code2 size={20} />,
      },
      {
        num: "02",
        title: "Security Finding",
        desc: "Identifies the core vulnerability pattern and its associated risk profile.",
        icon: <AlertOctagon size={20} />,
      },
      {
        num: "03",
        title: "Why / Impact / Fix",
        desc: "Deconstructs the flaw into cause, threat impact, and remediation instructions.",
        icon: <FileText size={20} />,
      },
      {
        num: "04",
        title: "Secure Recommendation",
        desc: "Generates corrected, hardened code ready for review and implementation.",
        icon: <CheckCircle2 size={20} />,
      },
    ],
    howItWorksNote:
      "Remediation guidance focuses strictly on security-sensitive changes, keeping valid algorithm logic intact and avoiding intrusive rewrites.",
    whatYouGet: [
      {
        icon: <SearchCode size={20} />,
        title: "The 'Why' Explanation",
        desc: "Plain-English explanation of why the syntax or logic creates an attack surface.",
      },
      {
        icon: <TriangleAlert size={20} />,
        title: "The 'Impact' Assessment",
        desc: "Details of what an attacker could achieve if the vulnerability is triggered.",
      },
      {
        icon: <Check size={20} />,
        title: "The 'Fix' Action",
        desc: "Specific, actionable modification instructions to remove the flaw safely.",
      },
      {
        icon: <Code2 size={20} />,
        title: "Recommended Secure Code",
        desc: "Concrete code replacement showing the secure implementation in context.",
      },
    ],
    example: {
      sourceLabel: "Input / Source Code (C++)",
      sourceCode: `int main() {\n    char user[10];\n    cin >> user; // Unbounded input into 10-byte buffer\n    return 0;\n}`,
      detectTitle: "What SecureCode AI Detects",
      detectText:
        "Buffer Overflow (CWE-120): Reading input into fixed-size char buffer without boundary check.",
      recommendTitle: "Why / Impact / Fix Guidance",
      recommendText:
        "• WHY: cin >> user does not limit characters written to memory.\n• IMPACT: Writing >9 characters overflows stack memory, causing crashes or arbitrary execution.\n• FIX: Replace char array with std::string user; cin >> user; or enforce width limit cin >> setw(10) >> user;.",
    },
    whyItMatters:
      "Generic error messages force developers to spend hours researching security documentation. By providing explicit Why, Impact, and Fix guidance along with verified code snippets, SecureCode AI accelerates secure development and educates engineers on best practices.",
    pipelineStep: "AI Explanation",
  },

  "security-report": {
    slug: "security-report",
    number: "05",
    title: "Security Report",
    icon: <FileChartColumn size={26} />,
    heroPurpose:
      "Compiles comprehensive analysis findings into a structured summary and downloadable documentation.",
    whatItDoes:
      "SecureCode AI organizes the entire analysis outcome into a structured security report. The report includes file metadata, detected language, overall security score, severity counts, itemized findings with CWE mappings, AI security insights, remediation action items, and side-by-side corrected code. Authenticated users can download an official PDF report for audits and team sharing.",
    whatBullets: [
      "Structured summary containing file name, language, timestamp, and security score",
      "Itemized vulnerability catalog with CWE IDs, line numbers, Why, Impact, and Fix",
      "Executive AI security insights and high-level remediation takeaways",
      "Downloadable PDF report for signed-in accounts; interactive dashboard for all users",
    ],
    howItWorksSteps: [
      {
        num: "01",
        title: "Analysis Results",
        desc: "Gathers findings, severity metrics, and language metadata from the scan.",
        icon: <Activity size={20} />,
      },
      {
        num: "02",
        title: "Report Assembly",
        desc: "Structures findings into clean sections: score, catalog, insights, and code fixes.",
        icon: <Layers size={20} />,
      },
      {
        num: "03",
        title: "Interactive Dashboard",
        desc: "Presents an on-screen view with interactive filters, code viewing, and metrics.",
        icon: <FileChartColumn size={20} />,
      },
      {
        num: "04",
        title: "Export & Compliance",
        desc: "Generates a formatted PDF report for authenticated users to share with teams.",
        icon: <FileText size={20} />,
      },
    ],
    howItWorksNote:
      "Report download requires account authentication according to existing access control; guests can review full interactive findings directly on the analysis dashboard.",
    whatYouGet: [
      {
        icon: <Scale size={20} />,
        title: "Executive Summary",
        desc: "High-level overview including overall security score and severity breakdown.",
      },
      {
        icon: <FileCode size={20} />,
        title: "Detailed Vulnerability List",
        desc: "Each finding with line numbers, severity tier, CWE mapping, and description.",
      },
      {
        icon: <Sparkles size={20} />,
        title: "AI Security Insights",
        desc: "Strategic assessment of project posture and key remediation recommendations.",
      },
      {
        icon: <FileText size={20} />,
        title: "Audit-Ready PDF Export",
        desc: "Formatted PDF document ready for pull requests, compliance, and client handoffs.",
      },
    ],
    example: {
      sourceLabel: "Report Structure Overview",
      sourceCode: `Security Analysis Report\n├── File / Language: payment_api.py (Python)\n├── Security Score: 78 / 100\n├── Severity Summary: [0 Critical | 2 High | 1 Med | 0 Low]\n├── Detected Vulnerabilities (CWE-89, CWE-798)\n│   └── Line references, Why, Impact, Fix\n├── AI Security Insight & Remediation Plan\n└── Original vs Corrected Code Comparison`,
      detectTitle: "What SecureCode AI Detects",
      detectText:
        "Synthesizes raw findings into an organized audit document linking code locations to specific remediation steps and security scores.",
      recommendTitle: "What SecureCode AI Recommends",
      recommendText:
        "Review interactive dashboard findings, implement recommended code modifications, and export the official PDF audit report for pull request records.",
    },
    whyItMatters:
      "Engineering teams need verifiable documentation to prove code security to stakeholders, clients, and compliance auditors. A clean security report bridges the gap between automated detection and human governance.",
    pipelineStep: "Comparison / Report",
  },

  "code-optimization": {
    slug: "code-optimization",
    number: "06",
    title: "Verified Code Optimization",
    icon: <CheckCircle2 size={26} />,
    heroPurpose:
      "Compares original and corrected code through a security-oriented comparison to evaluate safety, validation, and performance.",
    whatItDoes:
      "SecureCode AI performs a security-oriented comparison between the submitted code and the recommended corrected version to help developers understand what changed and why. (Note: 'Verified' refers to comparative security and quality evaluation, not formal mathematical software verification). It evaluates Security, Validation, Functionality, Maintainability, Performance, and Complexity.",
    whatBullets: [
      "Compares submitted code side-by-side with the recommended secure version",
      "Evaluates 7 key dimensions: Security, Validation, Functionality, Maintainability, Performance, Time Complexity, Space Complexity",
      "Preserves sound existing algorithms and avoids unnecessary or disruptive rewrites",
      "Ensures security fixes do not introduce performance regressions or algorithmic slowdowns",
    ],
    howItWorksSteps: [
      {
        num: "01",
        title: "Original Implementation",
        desc: "Analyzes the submitted code's structure, working logic, and performance.",
        icon: <Code2 size={20} />,
      },
      {
        num: "02",
        title: "Security Hardening",
        desc: "Formulates a corrected version resolving vulnerabilities with minimal code changes.",
        icon: <ShieldCheck size={20} />,
      },
      {
        num: "03",
        title: "Multi-Dimension Evaluation",
        desc: "Compares security, validation, maintainability, performance, and complexity.",
        icon: <Scale size={20} />,
      },
      {
        num: "04",
        title: "Transparent Assessment",
        desc: "Shows what changed; transparently notes when complexity cannot be reliably inferred.",
        icon: <CheckCircle2 size={20} />,
      },
    ],
    howItWorksNote:
      "We use security-oriented comparison rather than claiming formal mathematical verification. The goal is ensuring security fixes preserve good algorithms and maintainability.",
    whatYouGet: [
      {
        icon: <Layers size={20} />,
        title: "Side-by-Side Code Diff",
        desc: "Original vs Corrected code viewer with highlighted security modifications.",
      },
      {
        icon: <ShieldCheck size={20} />,
        title: "Security & Validation Delta",
        desc: "Shows how attack surfaces are eliminated through proper input sanitization.",
      },
      {
        icon: <Cpu size={20} />,
        title: "Performance & Complexity",
        desc: "Compares time and space complexity to ensure fixes do not degrade speed.",
      },
      {
        icon: <Check size={20} />,
        title: "Maintainability Assessment",
        desc: "Confirms that clean code readability and framework conventions are maintained.",
      },
    ],
    example: {
      sourceLabel: "Security-Oriented Comparison",
      sourceCode: `Dimension         Original Code             Corrected Recommendation\nSecurity:         High Risk (SQL Injection)  Secure (Parameterized)\nValidation:       Missing parameter check    Sanitized & Bound\nPerformance:      O(1) Direct Lookup        O(1) Single Query (Preserved)\nMaintainability:  Concatenated String        Clean Prepared Statement`,
      detectTitle: "What SecureCode AI Detects",
      detectText:
        "Verifies that replacing vulnerable string concatenation with parameterized queries eliminates the vulnerability while maintaining identical single-lookup time complexity.",
      recommendTitle: "What SecureCode AI Recommends",
      recommendText:
        "Adopt the secure recommendation knowing that business logic, query performance, and memory footprint remain optimal without unwanted architectural overhead.",
    },
    whyItMatters:
      "A security fix that makes code 10x slower or introduces confusing dependencies will often be rejected by developers. Evaluating fixes across safety, validation, and performance guarantees that recommendations are practical, efficient, and production-ready.",
    pipelineStep: "Comparison / Report",
  },
};

const PIPELINE_NODES = [
  { key: "Code", label: "01 Code", icon: <Code2 size={16} /> },
  { key: "Detection", label: "02 Detection", icon: <Shield size={16} /> },
  { key: "Severity", label: "03 Severity", icon: <TriangleAlert size={16} /> },
  { key: "AI Explanation", label: "04 AI Explanation", icon: <WandSparkles size={16} /> },
  { key: "Secure Fix", label: "05 Secure Fix", icon: <CheckCircle2 size={16} /> },
  { key: "Comparison / Report", label: "06 Report & Optimization", icon: <FileChartColumn size={16} /> },
];

function FeatureDetail({ featureKey }) {
  const { slug: paramSlug } = useParams();
  const navigate = useNavigate();

  const activeSlug = featureKey || paramSlug || "smart-code-analysis";
  const feature = FEATURES_DATA[activeSlug] || FEATURES_DATA["smart-code-analysis"];

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [activeSlug]);

  const handleBackToReview = () => {
    navigate("/features#review");
  };

  return (
    <main className="feature-detail-page">
      <div className="fd-grid-bg" />
      <div className="fd-glow fd-glow-top" />
      <div className="fd-glow fd-glow-mid" />

      <div className="fd-container">
        {/* HEADER */}
        <header className="fd-header">
          <Link to="/home" className="fd-brand">
            <span className="fd-brand-icon">
              <ShieldCheck size={24} />
            </span>
            <span>
              SecureCode <strong>AI</strong>
            </span>
          </Link>

          <Link to="/features" className="fd-top-back-btn">
            <ArrowLeft size={16} />
            <span>Back to Features</span>
          </Link>
        </header>

        {/* =========================================
            A. FEATURE HERO
        ========================================= */}
        <section className="fd-hero">
          <div className="fd-hero-badge">
            <Sparkles size={14} />
            <span>FEATURE {feature.number}</span>
          </div>

          <h1>
            {feature.title}
          </h1>

          <p className="fd-hero-purpose">{feature.heroPurpose}</p>
        </section>

        {/* =========================================
            B. WHAT IT DOES
        ========================================= */}
        <section className="fd-section">
          <div className="fd-section-header">
            <div className="fd-section-header-icon">{feature.icon}</div>
            <h2>What It Does</h2>
            <span>Section B</span>
          </div>

          <p className="fd-what-text">{feature.whatItDoes}</p>

          <div className="fd-what-bullets">
            {feature.whatBullets.map((bullet, idx) => (
              <div key={idx} className="fd-what-item">
                <Check size={17} />
                <span>{bullet}</span>
              </div>
            ))}
          </div>
        </section>

        {/* =========================================
            C. HOW IT WORKS (Workflow Pipeline)
        ========================================= */}
        <section className="fd-section">
          <div className="fd-section-header">
            <div className="fd-section-header-icon">
              <Layers size={20} />
            </div>
            <h2>How It Works</h2>
            <span>Section C</span>
          </div>

          <div className="fd-pipeline-container">
            {feature.howItWorksSteps.map((step, idx) => (
              <div key={idx} style={{ display: "contents" }}>
                <div className="fd-pipeline-step">
                  <span className="fd-step-num">Step {step.num}</span>
                  <div className="fd-step-icon">{step.icon}</div>
                  <h4>{step.title}</h4>
                  <p>{step.desc}</p>
                </div>
                {idx < feature.howItWorksSteps.length - 1 && (
                  <div className="fd-pipeline-arrow">
                    <ArrowRight size={18} />
                  </div>
                )}
              </div>
            ))}
          </div>

          {feature.howItWorksNote && (
            <div className="fd-workflow-note">{feature.howItWorksNote}</div>
          )}
        </section>

        {/* =========================================
            D. WHAT THE USER GETS
        ========================================= */}
        <section className="fd-section">
          <div className="fd-section-header">
            <div className="fd-section-header-icon">
              <CheckCircle2 size={20} />
            </div>
            <h2>What You Receive</h2>
            <span>Section D</span>
          </div>

          <div className="fd-output-grid">
            {feature.whatYouGet.map((item, idx) => (
              <div key={idx} className="fd-output-card">
                <div className="fd-output-card-header">
                  {item.icon}
                  <strong>{item.title}</strong>
                </div>
                <p>{item.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* =========================================
            E. SIMPLE EXAMPLE
        ========================================= */}
        <section className="fd-section">
          <div className="fd-section-header">
            <div className="fd-section-header-icon">
              <Terminal size={20} />
            </div>
            <h2>Practical Example</h2>
            <span>Section E</span>
          </div>

          <div className="fd-example-box">
            <div className="fd-example-step">
              <span className="fd-example-label source-label">
                <Code2 size={14} />
                {feature.example.sourceLabel}
              </span>
              <pre className="fd-example-code">{feature.example.sourceCode}</pre>
            </div>

            <div className="fd-example-down-arrow">
              <ChevronDown size={22} />
            </div>

            <div className="fd-example-step">
              <span className="fd-example-label detect-label">
                <AlertOctagon size={14} />
                {feature.example.detectTitle}
              </span>
              <p className="fd-example-desc">{feature.example.detectText}</p>
            </div>

            <div className="fd-example-down-arrow">
              <ChevronDown size={22} />
            </div>

            <div className="fd-example-step">
              <span className="fd-example-label fix-label">
                <CheckCircle2 size={14} />
                {feature.example.recommendTitle}
              </span>
              <p className="fd-example-desc">{feature.example.recommendText}</p>
            </div>
          </div>
        </section>

        {/* =========================================
            F. WHY IT MATTERS
        ========================================= */}
        <section className="fd-section">
          <div className="fd-section-header">
            <div className="fd-section-header-icon">
              <Lock size={20} />
            </div>
            <h2>Why It Matters in Real Development</h2>
            <span>Section F</span>
          </div>

          <div className="fd-why-content">
            <div className="fd-why-icon-box">
              <ShieldCheck size={28} />
            </div>
            <p className="fd-why-text">{feature.whyItMatters}</p>
          </div>
        </section>

        {/* =========================================
            G. RELATED WORKFLOW (Highlighted Pipeline)
        ========================================= */}
        <section className="fd-section">
          <div className="fd-section-header">
            <div className="fd-section-header-icon">
              <Activity size={20} />
            </div>
            <h2>Overall Security Pipeline Context</h2>
            <span>Section G</span>
          </div>

          <p
            style={{
              fontSize: "0.92rem",
              color: "#94a3b8",
              marginBottom: "16px",
            }}
          >
            Where this capability sits within the complete SecureCode AI analysis
            workflow:
          </p>

          <div className="fd-workflow-pipeline">
            {PIPELINE_NODES.map((node, idx) => {
              const isCurrent =
                feature.pipelineStep.includes(node.key) ||
                (node.key === "Code" && feature.pipelineStep === "Code") ||
                (node.key === "Comparison / Report" &&
                  (feature.slug === "security-report" ||
                    feature.slug === "code-optimization"));
              return (
                <div key={idx} style={{ display: "contents" }}>
                  <div className={`fd-wf-node ${isCurrent ? "active" : ""}`}>
                    <span className="fd-wf-node-icon">{node.icon}</span>
                    <span>{node.label}</span>
                    {isCurrent && (
                      <span
                        style={{
                          fontSize: "0.68rem",
                          color: "#38bdf8",
                          fontWeight: 700,
                        }}
                      >
                        [Current Feature]
                      </span>
                    )}
                  </div>
                  {idx < PIPELINE_NODES.length - 1 && (
                    <span className="fd-wf-arrow">→</span>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        {/* =========================================
            10. BACK TO REVIEW & BACK TO FEATURES NAVIGATION
        ========================================= */}
        <div className="fd-bottom-nav">
          <button
            type="button"
            className="fd-review-arrow-btn"
            onClick={handleBackToReview}
            aria-label="Back to Code Review"
          >
            <ChevronDown size={30} />
          </button>

          <span className="fd-review-label">Back to Code Review</span>

          <Link to="/features" className="fd-back-features-bottom">
            <ArrowLeft size={16} />
            <span>← Back to Features</span>
          </Link>
        </div>
      </div>
    </main>
  );
}

export default FeatureDetail;
