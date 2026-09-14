import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  Code2,
  ShieldCheck,
  CircleCheck,
} from "lucide-react";

const SUPPORTED_LANGUAGES = [
  "C",
  "C++",
  "Python",
  "Java",
  "JavaScript",
  "TypeScript",
  "PHP",
  "C#",
  "Go",
  "Rust",
  "Kotlin",
  "Swift",
  "Ruby",
  "SQL",
  "Bash",
];

const ANALYSIS_STATUSES = [
  "Ready",
  "Scanning",
  "Parsing",
  "Detecting",
  "Reviewing",
];

function CodeSnippetBlock({ isClone = false }) {
  return (
    <div className="code-block" aria-hidden={isClone ? "true" : undefined}>
      <div className="code-line">
        <span className="line-number">01</span>
        <span><span className="code-keyword">#include</span> <span className="code-string">&lt;iostream&gt;</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">02</span>
        <span><span className="code-keyword">#include</span> <span className="code-string">&lt;string&gt;</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">03</span>
        <span><span className="code-keyword">#include</span> <span className="code-string">&lt;openssl/evp.h&gt;</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">04</span>
        <span><span className="code-keyword">#include</span> <span className="code-string">&lt;argon2.h&gt;</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">05</span>
        <span>&nbsp;</span>
      </div>
      <div className="code-line">
        <span className="line-number">06</span>
        <span><span className="code-keyword">namespace</span> <span className="code-type">Security</span> {"{"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">07</span>
        <span>&nbsp;</span>
      </div>
      <div className="code-line">
        <span className="line-number">08</span>
        <span><span className="code-keyword">class</span> <span className="code-type">AuthSession</span> {"{"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">09</span>
        <span><span className="code-keyword">private:</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">10</span>
        <span>&nbsp;&nbsp;<span className="code-type">std::string</span> session_id;</span>
      </div>
      <div className="code-line">
        <span className="line-number">11</span>
        <span>&nbsp;&nbsp;<span className="code-type">uint32_t</span> failure_count;</span>
      </div>
      <div className="code-line">
        <span className="line-number">12</span>
        <span>&nbsp;&nbsp;<span className="code-type">bool</span> is_rate_limited;</span>
      </div>
      <div className="code-line">
        <span className="line-number">13</span>
        <span>&nbsp;</span>
      </div>
      <div className="code-line">
        <span className="line-number">14</span>
        <span><span className="code-keyword">public:</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">15</span>
        <span>&nbsp;&nbsp;<span className="code-type">bool</span> verify_credentials(</span>
      </div>
      <div className="code-line">
        <span className="line-number">16</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">const</span> <span className="code-type">std::string</span>&amp; username,</span>
      </div>
      <div className="code-line">
        <span className="line-number">17</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">const</span> <span className="code-type">std::string</span>&amp; password_hash</span>
      </div>
      <div className="code-line">
        <span className="line-number">18</span>
        <span>&nbsp;&nbsp;) {"{"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">19</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">if</span> (username.empty() || username.length() &gt; 64) {"{"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">20</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;log_security_event(<span className="code-string">"AUTH_INVALID_LENGTH"</span>);</span>
      </div>
      <div className="code-line">
        <span className="line-number">21</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">return</span> <span className="code-keyword">false</span>;</span>
      </div>
      <div className="code-line">
        <span className="line-number">22</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;{"}"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">23</span>
        <span>&nbsp;</span>
      </div>
      <div className="code-line code-warning-line">
        <span className="line-number">24</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-type">char</span> raw_buffer[64];</span>
      </div>
      <div className="code-line code-warning-line">
        <span className="line-number">25</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;strcpy(raw_buffer, username.c_str()); <span className="code-comment">// [VULN: UNCHECKED COPY]</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">26</span>
        <span>&nbsp;</span>
      </div>
      <div className="code-line">
        <span className="line-number">27</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-comment">// Constant-time hash verification</span></span>
      </div>
      <div className="code-line">
        <span className="line-number">28</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">if</span> (argon2_verify(password_hash.c_str(), user_hash.c_str())) {"{"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">29</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">this</span>-&gt;failure_count = 0;</span>
      </div>
      <div className="code-line">
        <span className="line-number">30</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">return</span> regenerate_session_token();{!isClone && <span className="code-scanner-cursor" aria-hidden="true" />}</span>
      </div>
      <div className="code-line">
        <span className="line-number">31</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;{"}"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">32</span>
        <span>&nbsp;</span>
      </div>
      <div className="code-line">
        <span className="line-number">33</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">this</span>-&gt;failure_count++;</span>
      </div>
      <div className="code-line">
        <span className="line-number">34</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">if</span> (<span className="code-keyword">this</span>-&gt;failure_count &gt;= 5) {"{"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">35</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">this</span>-&gt;is_rate_limited = <span className="code-keyword">true</span>;</span>
      </div>
      <div className="code-line">
        <span className="line-number">36</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;enforce_backoff_cooldown(60);</span>
      </div>
      <div className="code-line">
        <span className="line-number">37</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;{"}"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">38</span>
        <span>&nbsp;&nbsp;&nbsp;&nbsp;<span className="code-keyword">return</span> <span className="code-keyword">false</span>;</span>
      </div>
      <div className="code-line">
        <span className="line-number">39</span>
        <span>&nbsp;&nbsp;{"}"}</span>
      </div>
      <div className="code-line">
        <span className="line-number">40</span>
        <span>{"}"};</span>
      </div>
      <div className="code-line">
        <span className="line-number">41</span>
        <span>{"}"} <span className="code-comment">// namespace Security</span></span>
      </div>
    </div>
  );
}

function Hero() {
  const [langIndex, setLangIndex] = useState(0);
  const [isLangTransitioning, setIsLangTransitioning] = useState(false);

  const [statusIndex, setStatusIndex] = useState(0);
  const [isStatusTransitioning, setIsStatusTransitioning] = useState(false);

  useEffect(() => {
    // 1-second language rotation
    const langTimer = setInterval(() => {
      setIsLangTransitioning(true);
      setTimeout(() => {
        setLangIndex((prev) => (prev + 1) % SUPPORTED_LANGUAGES.length);
        setIsLangTransitioning(false);
      }, 160);
    }, 1100);

    // 2.2-second analysis status rotation
    const statusTimer = setInterval(() => {
      setIsStatusTransitioning(true);
      setTimeout(() => {
        setStatusIndex((prev) => (prev + 1) % ANALYSIS_STATUSES.length);
        setIsStatusTransitioning(false);
      }, 200);
    }, 2200);

    return () => {
      clearInterval(langTimer);
      clearInterval(statusTimer);
    };
  }, []);

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
          <Link to="/features#review" className="hero-primary-btn">
            Start Code Review
            <ArrowRight size={20} />
          </Link>

          <Link to="/features" className="hero-secondary-btn">
            Explore Features
          </Link>
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

              <div className="status-value-wrap">
                <strong className={`status-val ${isLangTransitioning ? "val-transitioning" : ""}`}>
                  {SUPPORTED_LANGUAGES[langIndex]}
                </strong>
              </div>
            </div>

            <div className="status-box">
              <span className="status-label">
                Analysis
              </span>

              <div className="status-value-wrap">
                <strong className={`status-ready ${isStatusTransitioning ? "val-transitioning" : ""} ${statusIndex !== 0 ? "status-active-pulse" : ""}`}>
                  {ANALYSIS_STATUSES[statusIndex]}
                </strong>
              </div>
            </div>

          </div>

          {/* SCANNING AREA */}
          <div className="code-preview" aria-label="Simulated real-time security code analysis">

            <div className="automatic-scan-ambient" aria-hidden="true" />
            <div className="automatic-scan-line" aria-hidden="true" />

            <div className="code-scroll-track">
              {/* BLOCK A */}
              <CodeSnippetBlock isClone={false} />

              {/* BLOCK B (Seamless clone for continuous loop) */}
              <CodeSnippetBlock isClone={true} />
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