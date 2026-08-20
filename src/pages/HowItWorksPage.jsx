import { Link, useNavigate } from "react-router-dom";

import {
  ShieldCheck,
  Sparkles,
  Code2,
  ScanSearch,
  Brain,
  TriangleAlert,
  Wrench,
  FileText,
  ChevronDown,
  ArrowRight,
  CircleCheck,
} from "lucide-react";

import "./HowItWorksPage.css";


const workflowSteps = [
  {
    number: "01",
    icon: <Code2 size={27} />,
    title: "Provide Source Code",
    shortTitle: "Code Input",
    description:
      "The review begins when source code is pasted directly into the workspace or provided through a supported source file.",
    points: [
      "Paste source code",
      "Upload a code file",
      "Prepare the code for review",
    ],
  },

  {
    number: "02",
    icon: <ScanSearch size={27} />,
    title: "Understand the Code",
    shortTitle: "Code Understanding",
    description:
      "The platform is designed to recognise the programming language and understand the structure of the submitted source code before deeper security review.",
    points: [
      "Identify language",
      "Understand code structure",
      "Prepare security context",
    ],
  },

  {
    number: "03",
    icon: <ShieldCheck size={27} />,
    title: "Perform Security Analysis",
    shortTitle: "Security Analysis",
    description:
      "The source code is examined for potentially unsafe patterns, validation weaknesses and other areas that may require security attention.",
    points: [
      "Inspect risky patterns",
      "Locate suspicious code",
      "Identify possible weaknesses",
    ],
  },

  {
    number: "04",
    icon: <TriangleAlert size={27} />,
    title: "Assess Risk & Severity",
    shortTitle: "Risk Assessment",
    description:
      "Detected findings are organised according to their potential security impact so that higher-priority problems can be reviewed first.",
    points: [
      "Organise findings",
      "Assign severity",
      "Prioritise important risks",
    ],
  },

  {
    number: "05",
    icon: <Brain size={27} />,
    title: "Generate Intelligent Insight",
    shortTitle: "AI Insight",
    description:
      "Security findings are presented with clearer context to help developers understand why a weakness may matter and what impact it could create.",
    points: [
      "Explain the finding",
      "Describe potential impact",
      "Improve understanding",
    ],
  },

  {
    number: "06",
    icon: <Wrench size={27} />,
    title: "Recommend a Secure Fix",
    shortTitle: "Secure Fix",
    description:
      "The platform is designed to provide remediation-oriented guidance and safer coding suggestions for identified security concerns.",
    points: [
      "Suggest remediation",
      "Present safer code",
      "Support secure development",
    ],
  },

  {
    number: "07",
    icon: <FileText size={27} />,
    title: "Present the Final Report",
    shortTitle: "Security Report",
    description:
      "The complete review is organised into a structured security result containing findings, severity information, explanations and recommendations.",
    points: [
      "Security overview",
      "Detailed findings",
      "Actionable recommendations",
    ],
  },
];


function HowItWorksPage() {
  const navigate = useNavigate();

  return (
    <main className="how-page">

      {/* BACKGROUND */}
      <div className="how-grid-background" />

      <div className="how-glow how-glow-one" />
      <div className="how-glow how-glow-two" />

      <span className="how-floating-symbol how-symbol-one">
        {"</>"}
      </span>

      <span className="how-floating-symbol how-symbol-two">
        {"{ }"}
      </span>

      <span className="how-floating-symbol how-symbol-three">
        AI
      </span>


      {/* HEADER - NO NAVBAR */}
      <header className="how-header">
        <Link to="/home" className="how-brand">

          <span className="how-brand-icon">
            <ShieldCheck size={27} />
          </span>

          <span className="how-brand-text">
            SecureCode <strong>AI</strong>
          </span>

        </Link>
      </header>


      {/* HERO */}
      <section className="how-hero">

        <div className="how-hero-badge">
          <Sparkles size={17} />
          HOW IT WORKS
        </div>

        <h1>
          From Source Code
          <span>To Security Insight.</span>
        </h1>

        <p>
          SecureCode AI is designed around a structured review workflow
          that transforms source code into understandable security
          findings, risk information and remediation guidance.
        </p>


        <div className="how-mini-flow">

          <span>CODE</span>
          <ArrowRight size={18} />

          <span>ANALYSE</span>
          <ArrowRight size={18} />

          <span>UNDERSTAND</span>
          <ArrowRight size={18} />

          <span>SECURE</span>

        </div>

      </section>


      <div className="how-container">

        {/* OVERVIEW */}
        <section className="how-overview">

          <div className="how-overview-left">

            <span>SECURITY WORKFLOW</span>

            <h2>
              One connected process.
              <br />
              Seven clear stages.
            </h2>

          </div>


          <p>
            Each stage focuses on a different part of the review process,
            beginning with source-code input and ending with a structured
            security result that developers can understand and act on.
          </p>

        </section>


        {/* MAIN VERTICAL WORKFLOW */}
        <section className="workflow-section">

          <div className="workflow-line">
            <span className="workflow-moving-dot" />
          </div>


          <div className="workflow-list">

            {workflowSteps.map((step, index) => (

              <article
                className={`workflow-item ${
                  index % 2 === 0
                    ? "workflow-left"
                    : "workflow-right"
                }`}
                key={step.number}
              >

                <div className="workflow-node">
                  <span />
                </div>


                <div className="workflow-card">

                  <span className="workflow-number">
                    {step.number}
                  </span>


                  <div className="workflow-card-top">

                    <div className="workflow-icon">
                      {step.icon}
                    </div>

                    <div>
                      <span className="workflow-label">
                        {step.shortTitle}
                      </span>

                      <h3>
                        {step.title}
                      </h3>
                    </div>

                  </div>


                  <p className="workflow-description">
                    {step.description}
                  </p>


                  <div className="workflow-points">

                    {step.points.map((point) => (
                      <span key={point}>
                        <CircleCheck size={18} />
                        {point}
                      </span>
                    ))}

                  </div>

                </div>

              </article>

            ))}

          </div>

        </section>


        {/* RESULT SECTION */}
        <section className="how-result-section">

          <div className="how-result-heading">

            <span>THE RESULT</span>

            <h2>
              Security information that is easier to act on.
            </h2>

            <p>
              The purpose of the workflow is not only to identify
              potential weaknesses, but also to organise the information
              in a way that makes the next development decision clearer.
            </p>

          </div>


          <div className="how-result-grid">

            <article className="how-result-card">

              <span>01</span>

              <TriangleAlert size={26} />

              <h3>
                Understand the Risk
              </h3>

              <p>
                See where potential security concerns exist and
                understand their relative importance.
              </p>

            </article>


            <article className="how-result-card">

              <span>02</span>

              <Brain size={26} />

              <h3>
                Understand the Reason
              </h3>

              <p>
                Receive clearer context explaining why a particular
                code pattern may create a security concern.
              </p>

            </article>


            <article className="how-result-card">

              <span>03</span>

              <Wrench size={26} />

              <h3>
                Understand the Fix
              </h3>

              <p>
                Review remediation guidance designed to support
                safer implementation decisions.
              </p>

            </article>


            <article className="how-result-card">

              <span>04</span>

              <FileText size={26} />

              <h3>
                Keep the Result
              </h3>

              <p>
                Present the complete review through a structured
                security summary and report.
              </p>

            </article>

          </div>

        </section>


        {/* FINAL FLOW */}
        <section className="how-final-panel">

          <div className="how-final-icon">
            <ShieldCheck size={34} />
          </div>


          <span>SECURECODE AI WORKFLOW</span>

          <h2>
            Review. Understand. Improve.
          </h2>

          <p>
            A developer-focused approach to making source-code security
            review more structured, understandable and actionable.
          </p>


          <div className="how-final-flow">

            <div>
              <Code2 size={20} />
              <span>Source Code</span>
            </div>

            <ArrowRight size={20} />

            <div>
              <ScanSearch size={20} />
              <span>Review</span>
            </div>

            <ArrowRight size={20} />

            <div>
              <Brain size={20} />
              <span>Insight</span>
            </div>

            <ArrowRight size={20} />

            <div>
              <ShieldCheck size={20} />
              <span>Secure Result</span>
            </div>

          </div>

        </section>


        {/* BACK HOME */}
        <div className="how-back-home">

          <button
            type="button"
            className="how-home-arrow"
            onClick={() => navigate("/home")}
            aria-label="Back to Home"
          >
            <ChevronDown size={29} />
          </button>

          <span>
            Back to Home
          </span>

        </div>

      </div>


      {/* FOOTER */}
      <footer className="how-footer">

        <ShieldCheck size={18} />

        <span>
          SecureCode AI · Intelligent Secure Code Review
        </span>

      </footer>

    </main>
  );
}


export default HowItWorksPage;