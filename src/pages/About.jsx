import { Link, useNavigate } from "react-router-dom";

import {
  ShieldCheck,
  Sparkles,
  Target,
  TriangleAlert,
  Code2,
  SearchCode,
  Brain,
  Wrench,
  FileText,
  CheckCircle2,
  Monitor,
  Shield,
  BarChart3,
  Rocket,
  ExternalLink,
  GitBranch,
  Mail,
  ChevronDown,
  ArrowRight,
  Users,
  Lightbulb,
  LockKeyhole,
} from "lucide-react";

import "./About.css";


const teamMembers = [
  {
    id: 1,
    initials: "BP",
    name: "Buddhadeb Pan",
    role: "Frontend Developer",
    description:
      "Contributing to the design, development and research of SecureCode AI.",
    Externallink: "https://www.linkedin.com/",
    GitBranch: "https://github.com/",
    email: "member2@example.com",
  },

  {
    id: 2,
    initials: "SM",
    name: "Sayan Modak",
    role: "Backend Developer",
    description:
      "Working on backend development, API integration and security analysis for the platform.",
    Externallink: "https://www.linkedin.com/",
    GitBranch: "https://github.com/",
    email: "member2@example.com",
  },

  {
    id: 3,
    initials: "KB",
    name: "Kamalakanta Bera",
    role: "Deployment",
    description:
      "Deployment the project",
    Externallink: "https://www.linkedin.com/",
    GitBranch: "https://github.com/",
    email: "member3@example.com",
  },

  {
    id: 4,
    initials: "SM",
    name: "Suriyadwip Maity",
    role: "UI Design",
    description:
      "Analysis and create A great design",
    Externallink: "https://www.linkedin.com/",
    GitBranch: "https://github.com/",
    email: "member4@example.com",
  },

  {
    id: 5,
    initials: "RP",
    name: "Rajarshi pal",
    role: "Database Management",
    description:
      "Database management and security analysis",
    Externallink: "https://www.linkedin.com/",
    GitBranch: "https://github.com/",
    email: "member5@example.com",
  },
];


const objectives = [
  {
    number: "01",
    icon: <Shield size={24} />,
    title: "Improve Code Security",
    description:
      "Help identify potential security weaknesses before they become serious application risks.",
  },

  {
    number: "02",
    icon: <Lightbulb size={24} />,
    title: "Simplify Security Understanding",
    description:
      "Present technical security findings in a clear and developer-friendly form.",
  },

  {
    number: "03",
    icon: <TriangleAlert size={24} />,
    title: "Prioritize Security Risks",
    description:
      "Organise findings based on their severity and potential security impact.",
  },

  {
    number: "04",
    icon: <LockKeyhole size={24} />,
    title: "Support Secure Development",
    description:
      "Provide remediation-oriented guidance to encourage safer coding practices.",
  },

  {
    number: "05",
    icon: <FileText size={24} />,
    title: "Create Actionable Reports",
    description:
      "Transform analysis findings into structured and useful security reports.",
  },
];


function About() {
  const navigate = useNavigate();


  return (
    <main className="about-page">

      {/* =====================================
          BACKGROUND
      ====================================== */}

      <div className="about-grid-background" />

      <div className="about-background-glow about-glow-one" />
      <div className="about-background-glow about-glow-two" />

      <span className="about-floating-symbol about-symbol-one">
        {"</>"}
      </span>

      <span className="about-floating-symbol about-symbol-two">
        {"{ }"}
      </span>

      <span className="about-floating-symbol about-symbol-three">
        AI
      </span>

      <span className="about-particle about-particle-one" />
      <span className="about-particle about-particle-two" />
      <span className="about-particle about-particle-three" />


      {/* =====================================
          SIMPLE HEADER - NO NAVBAR
      ====================================== */}

      <header className="about-header">

        <Link
          to="/home"
          className="about-brand"
        >
          <span className="about-brand-icon">
            <ShieldCheck
              size={27}
              strokeWidth={1.9}
            />
          </span>

          <span className="about-brand-text">
            SecureCode <strong>AI</strong>
          </span>
        </Link>

      </header>


      {/* =====================================
          HERO
      ====================================== */}

      <section className="about-hero">

        <div className="about-hero-badge">
          <Sparkles size={17} />
          ABOUT SECURECODE AI
        </div>


        <h1>
          Building Safer Code
          <span>Through Intelligent Security.</span>
        </h1>


        <p className="about-hero-description">
          SecureCode AI is an intelligent code security platform
          designed to help developers understand potential
          vulnerabilities, evaluate security risks and discover
          safer approaches to building software.
        </p>


        <div className="about-hero-status">

          <div>
            <span className="about-live-dot" />

            <strong>
              Secure Development
            </strong>
          </div>

          <i />

          <div>
            <Code2 size={18} />

            <strong>
              Intelligent Review
            </strong>
          </div>

          <i />

          <div>
            <ShieldCheck size={18} />

            <strong>
              Security Focused
            </strong>
          </div>

        </div>

      </section>


      <div className="about-container">

        {/* =====================================
            MISSION + WHY
        ====================================== */}

        <section className="about-section">

          <div className="about-section-heading centered-about-heading">

            <span>OUR PURPOSE</span>

            <h2>
              Security should be easier to understand.
            </h2>

            <p>
              SecureCode AI is designed around one central idea:
              helping developers understand code security without
              making the review process unnecessarily complicated.
            </p>

          </div>


          <div className="mission-grid">

            <article className="mission-card">

              <div className="about-large-card-icon">
                <Target size={28} />
              </div>

              <span className="mission-card-label">
                OUR MISSION
              </span>

              <h3>
                Make secure coding more accessible.
              </h3>

              <p>
                Our mission is to create an intelligent environment
                where developers can review source code, understand
                potential security weaknesses and receive structured
                guidance for improving code security.
              </p>

              <div className="mission-card-footer">
                <CheckCircle2 size={18} />
                Developer-focused security
              </div>

            </article>


            <article className="mission-card">

              <div className="about-large-card-icon">
                <ShieldCheck size={28} />
              </div>

              <span className="mission-card-label">
                WHY IT MATTERS
              </span>

              <h3>
                Security begins during development.
              </h3>

              <p>
                Security weaknesses can remain unnoticed during
                normal development. A clearer review process can
                help developers recognise risky patterns earlier
                and make more informed security decisions.
              </p>

              <div className="mission-card-footer">
                <CheckCircle2 size={18} />
                Security-aware development
              </div>

            </article>

          </div>

        </section>



        {/* =====================================
            PROBLEM
        ====================================== */}

        <section className="about-section">

          <div className="problem-panel">

            <div className="problem-panel-icon">
              <TriangleAlert size={31} />
            </div>


            <div className="problem-panel-content">

              <span>
                THE PROBLEM WE ADDRESS
              </span>

              <h2>
                Security weaknesses can hide inside everyday code.
              </h2>

              <p>
                Modern applications depend heavily on source code,
                yet vulnerabilities can be introduced through unsafe
                input handling, insufficient validation, insecure
                coding patterns and other development mistakes.
              </p>

              <p>
                Manual security review can also require significant
                time and specialised knowledge. SecureCode AI aims
                to make this process more structured, understandable
                and developer-friendly.
              </p>


              <div className="problem-points">

                <span>
                  <CheckCircle2 size={18} />
                  Detect potential risky patterns
                </span>

                <span>
                  <CheckCircle2 size={18} />
                  Explain findings clearly
                </span>

                <span>
                  <CheckCircle2 size={18} />
                  Support remediation decisions
                </span>

              </div>

            </div>

          </div>

        </section>



        {/* =====================================
            APPROACH
        ====================================== */}

        <section className="about-section">

          <div className="about-section-heading">

            <span>OUR APPROACH</span>

            <h2>
              From source code to security guidance.
            </h2>

            <p>
              SecureCode AI follows a structured security workflow
              designed to transform source code into understandable
              findings and remediation guidance.
            </p>

          </div>


          <div className="approach-flow">

            <article className="approach-step">

              <span className="approach-number">
                01
              </span>

              <div className="approach-icon">
                <Code2 size={25} />
              </div>

              <h3>Source Code</h3>

              <p>
                Paste or upload the code that needs to be reviewed.
              </p>

            </article>


            <div className="approach-connector">
              <span />
              <ArrowRight size={21} />
            </div>


            <article className="approach-step">

              <span className="approach-number">
                02
              </span>

              <div className="approach-icon">
                <SearchCode size={25} />
              </div>

              <h3>Security Analysis</h3>

              <p>
                Inspect code structure and potential insecure patterns.
              </p>

            </article>


            <div className="approach-connector">
              <span />
              <ArrowRight size={21} />
            </div>


            <article className="approach-step">

              <span className="approach-number">
                03
              </span>

              <div className="approach-icon">
                <TriangleAlert size={25} />
              </div>

              <h3>Risk Discovery</h3>

              <p>
                Organise potential findings based on security impact.
              </p>

            </article>


            <div className="approach-connector">
              <span />
              <ArrowRight size={21} />
            </div>


            <article className="approach-step">

              <span className="approach-number">
                04
              </span>

              <div className="approach-icon">
                <Brain size={25} />
              </div>

              <h3>AI Insight</h3>

              <p>
                Provide clearer context and security-focused explanation.
              </p>

            </article>


            <div className="approach-connector">
              <span />
              <ArrowRight size={21} />
            </div>


            <article className="approach-step">

              <span className="approach-number">
                05
              </span>

              <div className="approach-icon">
                <Wrench size={25} />
              </div>

              <h3>Secure Fix</h3>

              <p>
                Present remediation-oriented suggestions and safer code.
              </p>

            </article>


            <div className="approach-connector">
              <span />
              <ArrowRight size={21} />
            </div>


            <article className="approach-step">

              <span className="approach-number">
                06
              </span>

              <div className="approach-icon">
                <FileText size={25} />
              </div>

              <h3>Final Report</h3>

              <p>
                Present findings in a structured security report.
              </p>

            </article>

          </div>

        </section>



        {/* =====================================
            OBJECTIVES
        ====================================== */}

        <section className="about-section">

          <div className="about-section-heading centered-about-heading">

            <span>PROJECT OBJECTIVES</span>

            <h2>
              What SecureCode AI aims to achieve.
            </h2>

            <p>
              The platform focuses on practical goals that support
              safer software development and clearer security awareness.
            </p>

          </div>


          <div className="objectives-grid">

            {objectives.map((objective) => (
              <article
                className="objective-card"
                key={objective.number}
              >

                <span className="objective-number">
                  {objective.number}
                </span>

                <div className="objective-icon">
                  {objective.icon}
                </div>

                <h3>
                  {objective.title}
                </h3>

                <p>
                  {objective.description}
                </p>

              </article>
            ))}

          </div>

        </section>



        {/* =====================================
            TECHNOLOGY VISION
        ====================================== */}

        <section className="about-section">

          <div className="about-section-heading">

            <span>TECHNOLOGY VISION</span>

            <h2>
              Designed as a complete security experience.
            </h2>

            <p>
              The platform combines multiple areas of software
              development and security into one connected workflow.
            </p>

          </div>


          <div className="technology-grid">

            <article className="technology-card">

              <div className="technology-icon">
                <Monitor size={26} />
              </div>

              <span>FRONTEND EXPERIENCE</span>

              <h3>
                Interactive Interface
              </h3>

              <p>
                A responsive, modern environment designed to make
                code review simple and comfortable.
              </p>

            </article>


            <article className="technology-card">

              <div className="technology-icon">
                <Shield size={26} />
              </div>

              <span>SECURITY ANALYSIS</span>

              <h3>
                Code Security Review
              </h3>

              <p>
                Security-oriented inspection designed to identify
                and organise potential code weaknesses.
              </p>

            </article>


            <article className="technology-card">

              <div className="technology-icon">
                <Brain size={26} />
              </div>

              <span>INTELLIGENCE</span>

              <h3>
                Intelligent Explanation
              </h3>

              <p>
                Clearer interpretation of findings and meaningful
                security guidance for developers.
              </p>

            </article>


            <article className="technology-card">

              <div className="technology-icon">
                <BarChart3 size={26} />
              </div>

              <span>REPORTING</span>

              <h3>
                Structured Results
              </h3>

              <p>
                Security scores, severity information, findings and
                recommendations presented in a useful format.
              </p>

            </article>

          </div>

        </section>



        {/* =====================================
            FUTURE VISION
        ====================================== */}

        <section className="about-section">

          <div className="future-vision-panel">

            <div className="future-vision-icon">
              <Rocket size={31} />
            </div>


            <div className="future-vision-content">

              <span>
                OUR FUTURE VISION
              </span>

              <h2>
                More than a code scanner.
              </h2>

              <p>
                Our long-term vision is to develop SecureCode AI
                into a practical security assistant that supports
                developers throughout the secure software development
                lifecycle.
              </p>


              <div className="future-path">

                <div>
                  <Code2 size={20} />
                  <span>Code Review</span>
                </div>

                <ArrowRight size={20} />

                <div>
                  <Brain size={20} />
                  <span>Intelligent Assistance</span>
                </div>

                <ArrowRight size={20} />

                <div>
                  <ShieldCheck size={20} />
                  <span>Secure Development</span>
                </div>

              </div>

            </div>

          </div>

        </section>



        {/* =====================================
            TEAM
        ====================================== */}

        <section className="about-section team-section">

          <div className="about-section-heading centered-about-heading">

            <span>MEET THE TEAM</span>

            <h2>
              The people behind SecureCode AI.
            </h2>

            <p>
              A collaborative team working together on the design,
              development, research and evolution of the project.
            </p>

          </div>


          <div className="team-grid">

            {teamMembers.map((member) => (
              <article
                className="team-card"
                key={member.id}
              >

                <span className="team-card-number">
                  0{member.id}
                </span>


                <div className="team-avatar">
                  {member.initials}
                </div>


                <h3>
                  {member.name}
                </h3>

                <span className="team-role">
                  {member.role}
                </span>


                <p>
                  {member.description}
                </p>


                <div className="team-socials">

                  <a
                    href={member.linkedin}
                    target="_blank"
                    rel="noreferrer"
                    aria-label={`${member.name} LinkedIn`}
                  >
                    <ExternalLink size={19} />
                    <span>LinkedIn</span>
                  </a>


                  <a
                    href={member.github}
                    target="_blank"
                    rel="noreferrer"
                    aria-label={`${member.name} GitHub`}
                  >
                    <GitBranch size={19} />
                    <span>GitHub</span>
                  </a>


                  <a
                    href={`mailto:${member.email}`}
                    aria-label={`Email ${member.name}`}
                  >
                    <Mail size={19} />
                    <span>Email</span>
                  </a>

                </div>

              </article>
            ))}

          </div>

        </section>



        {/* =====================================
            CONTACT
        ====================================== */}

        <section className="about-section">

          <div className="connect-panel">

            <div className="connect-icon">
              <Users size={29} />
            </div>


            <span>
              CONNECT WITH OUR TEAM
            </span>

            <h2>
              Questions, collaboration or project discussion?
            </h2>

            <p>
              Connect with the SecureCode AI team to learn more
              about the project, its development and future direction.
            </p>


            <div className="connect-actions">

              <a
                href="mailto:securecodeai@example.com"
                className="connect-primary-button"
              >
                <Mail size={19} />

                Contact Team
              </a>


              <a
                href="https://www.linkedin.com/"
                target="_blank"
                rel="noreferrer"
                className="connect-secondary-button"
              >
                <ExternalLink size={19} />

                LinkedIn

                <ArrowRight size={17} />
              </a>

            </div>

          </div>

        </section>



        {/* =====================================
            BACK HOME ARROW
        ====================================== */}

        <div className="about-back-home">

          <button
            type="button"
            className="about-home-arrow"
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


      {/* =====================================
          FOOTER
      ====================================== */}

      <footer className="about-footer">

        <ShieldCheck size={18} />

        <span>
          SecureCode AI · Building Safer Software Through Intelligent Security
        </span>

      </footer>

    </main>
  );
}


export default About;