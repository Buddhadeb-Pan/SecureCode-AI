import {
  ArrowRight,
  Code2,
  ShieldCheck,
  CircleCheck,
} from "lucide-react";

function Hero() {
  return (
    <section className="home-hero" id="home">

      {/* LEFT */}
      <div className="hero-left">

        <div className="hero-badge">
          <ShieldCheck size={17} />
          <span>AI-POWERED CODE SECURITY</span>
        </div>

        <h1 className="hero-title">
          Find Vulnerabilities
          <span>Before Attackers Do.</span>
        </h1>

        <p className="hero-description">
          Analyse source code, discover potential security risks,
          understand vulnerable code, and receive intelligent remediation
          guidance through one secure AI-powered platform.
        </p>

        <div className="hero-actions">
          <a href="#code-review" className="hero-primary-btn">
            Start Code Review
            <ArrowRight size={20} />
          </a>

          <a href="#features" className="hero-secondary-btn">
            Explore Features
          </a>
        </div>

      </div>


      {/* RIGHT */}
      <div className="hero-visual">

        {/* AUTOMATIC MOVING ELEMENTS */}
        <div className="motion-symbol motion-symbol-one">
          {"</>"}
        </div>

        <div className="motion-symbol motion-symbol-two">
          {"{ }"}
        </div>

        <div className="motion-symbol motion-symbol-three">
          AI
        </div>

        <div className="data-dot data-dot-one" />
        <div className="data-dot data-dot-two" />
        <div className="data-dot data-dot-three" />

        {/* MAIN CARD */}
        <div className="hero-code-card">

          <div className="code-card-top">
            <div className="code-file">
              <Code2 size={20} />
              <span>secure-login.cpp</span>
            </div>

            <div className="window-dots">
              <span />
              <span />
              <span />
            </div>
          </div>

          <div className="code-status">

            <div className="status-box">
              <span className="status-label">
                Language
              </span>

              <strong>--</strong>
            </div>

            <div className="status-box">
              <span className="status-label">
                Analysis
              </span>

              <strong className="status-ready">
                Ready
              </strong>
            </div>

          </div>

          {/* SCANNING AREA */}
          <div className="code-preview">

            <div className="automatic-scan-line" />

            <div className="code-line">
              <span className="line-number">01</span>
              <span>
                <span className="code-keyword">int</span> main() {"{"}
              </span>
            </div>

            <div className="code-line">
              <span className="line-number">02</span>
              <span>
                &nbsp;&nbsp;
                <span className="code-keyword">char</span> user[10];
              </span>
            </div>

            <div className="code-line code-warning-line">
              <span className="line-number">03</span>
              <span>
                &nbsp;&nbsp;cin &gt;&gt; user;
              </span>
            </div>

            <div className="code-line">
              <span className="line-number">04</span>
              <span>{"}"}</span>
            </div>

          </div>

          <div className="visual-footer">
            <div className="visual-ready">
              <CircleCheck size={18} />

              <span>Ready for security analysis</span>
            </div>
          </div>

        </div>

        {/* ENGINE STATUS */}
        <div className="hero-floating-card">

          <span className="engine-pulse" />

          <ShieldCheck size={19} />

          <div>
            <span>SecureCode Engine</span>
            <strong>System Ready</strong>
          </div>

        </div>

      </div>

    </section>
  );
}

export default Hero;