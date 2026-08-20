import { useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  ShieldCheck,
  ArrowRight,
  LogIn,
  Code2,
  ScanSearch,
  Sparkles,
  X,
} from "lucide-react";

import "./Welcome.css";

function Welcome() {
  const navigate = useNavigate();

  // Popup প্রথমে visible থাকবে
  const [showWelcomePopup, setShowWelcomePopup] = useState(true);

  const handleLogin = () => {
    navigate("/login");
  };

  const handleGetStarted = () => {
    navigate("/home");
  };

  return (
    <main className="welcome-page">

      {/* =========================
          WELCOME POPUP
      ========================== */}
      {showWelcomePopup && (
        <div className="welcome-popup-overlay">
          <div className="welcome-popup">

            <button
              type="button"
              className="welcome-popup-close"
              onClick={() => setShowWelcomePopup(false)}
              aria-label="Close popup"
            >
              <X size={18} />
            </button>

            <div className="welcome-popup-icon">
              <ShieldCheck size={30} />
            </div>

            <p className="welcome-popup-small">
              WELCOME TO
            </p>

            <h2>
              SecureCode <span>AI</span>
            </h2>

            <p className="welcome-popup-text">
              AI-powered secure code review and vulnerability detection.
            </p>

            <button
              type="button"
              className="welcome-popup-button"
              onClick={() => setShowWelcomePopup(false)}
            >
              Continue
              <ArrowRight size={17} />
            </button>

          </div>
        </div>
      )}

      {/* =========================
          EXISTING PAGE
      ========================== */}

      <div className="welcome-grid" aria-hidden="true" />
      <div
        className="welcome-glow welcome-glow-one"
        aria-hidden="true"
      />
      <div
        className="welcome-glow welcome-glow-two"
        aria-hidden="true"
      />

      <div className="welcome-container">

        {/* Brand */}
        <header className="welcome-brand">
          <div className="welcome-logo">
            <ShieldCheck size={28} strokeWidth={1.8} />
          </div>

          <span className="welcome-brand-name">
            SecureCode <strong>AI</strong>
          </span>
        </header>

        {/* Main Content */}
        <section className="welcome-content">

          <div className="welcome-badge">
            <Sparkles size={15} />
            <span>AI-POWERED CODE SECURITY</span>
          </div>

          <h1 className="welcome-title">
            Secure Your Code.
            <span> Build With Confidence.</span>
          </h1>

          <p className="welcome-subtitle">
            An AI-powered secure code review and vulnerability detection
            platform built to identify security risks, explain vulnerabilities,
            and provide intelligent remediation guidance.
          </p>

          {/* Small project visual */}
          <div className="welcome-process">

            <div className="process-item">
              <Code2 size={20} />
              <span>Your Code</span>
            </div>

            <div className="process-line" />

            <div className="process-item">
              <ScanSearch size={20} />
              <span>Security Analysis</span>
            </div>

            <div className="process-line" />

            <div className="process-item">
              <ShieldCheck size={20} />
              <span>Secure Fix</span>
            </div>

          </div>
        </section>

        {/* Bottom Action Section */}
        <section className="welcome-actions">

          {/* Login Card */}
          <div className="welcome-action-card">

            <span className="action-number">01</span>

            <div>
              <p className="action-label">
                Already have access?
              </p>

              <h2>Welcome Back.</h2>

              <p className="action-description">
                Sign in and continue your secure code review experience.
              </p>
            </div>

            <button
              type="button"
              className="welcome-btn welcome-btn-secondary"
              onClick={handleLogin}
            >
              <LogIn size={18} />
              Login
              <ArrowRight size={17} />
            </button>

          </div>

          {/* Get Started Card */}
          <div className="welcome-action-card welcome-action-primary">

            <span className="action-number">02</span>

            <div>
              <p className="action-label">
                New to SecureCode AI?
              </p>

              <h2>
                Start Securing Your Code.
              </h2>

              <p className="action-description">
                Explore AI-assisted code analysis and discover potential
                vulnerabilities in your source code.
              </p>
            </div>

            <button
              type="button"
              className="welcome-btn welcome-btn-primary"
              onClick={handleGetStarted}
            >
              Get Started
              <ArrowRight size={18} />
            </button>

          </div>

        </section>
      </div>
    </main>
  );
}

export default Welcome;