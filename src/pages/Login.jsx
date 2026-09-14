import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Mail, Lock, ArrowRight, AlertCircle } from "lucide-react";
import { API_BASE_URL, setStoredToken, setStoredUser } from "../config/api.js";
import "./Auth.css";

function Login() {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const handleChange = (event) => {
    const { name, value } = event.target;

    setFormData((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setErrorMessage("");

    const normalizedEmail = formData.email.trim().toLowerCase();
    if (!normalizedEmail || !formData.password) {
      setErrorMessage("Please enter both email and password.");
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          email: normalizedEmail,
          password: formData.password,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.detail || "Invalid email or password");
      }

      if (data.access_token) {
        setStoredToken(data.access_token);

        // Fetch user profile to store name/email
        try {
          const meRes = await fetch(`${API_BASE_URL}/auth/me`, {
            headers: {
              Authorization: `Bearer ${data.access_token}`,
            },
            credentials: "include",
          });
          if (meRes.ok) {
            const meData = await meRes.json();
            setStoredUser(meData);
          }
        } catch (_) {}
      }

      navigate("/home");
    } catch (err) {
      console.error("[AUTH] Login error:", err);
      if (err.name === "TypeError" && err.message.includes("fetch")) {
        setErrorMessage("Unable to connect to the authentication server. Please ensure the backend is running.");
      } else {
        setErrorMessage(err.message || "Invalid email or password");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <ShieldCheck size={30} />
        </div>

        <p className="auth-label">SECURECODE AI</p>

        <h1>Welcome Back</h1>

        <p className="auth-description">
          Sign in to continue your secure code review experience.
        </p>

        {errorMessage && (
          <div className="auth-alert auth-alert-error">
            <AlertCircle size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
            <span>{errorMessage}</span>
          </div>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            Email Address
          </label>

          <div className="auth-input">
            <Mail size={18} />

            <input
              type="email"
              name="email"
              placeholder="you@example.com"
              value={formData.email}
              onChange={handleChange}
              disabled={isSubmitting}
              required
            />
          </div>

          <label>
            Password
          </label>

          <div className="auth-input">
            <Lock size={18} />

            <input
              type="password"
              name="password"
              placeholder="Enter your password"
              value={formData.password}
              onChange={handleChange}
              disabled={isSubmitting}
              required
            />
          </div>

          <div className="auth-forgot-row">
            <button
              type="button"
              className="auth-forgot-link"
              onClick={() => navigate("/forgot-password")}
              disabled={isSubmitting}
            >
              Forgot Password?
            </button>
          </div>

          <button type="submit" className="auth-submit" disabled={isSubmitting}>
            {isSubmitting ? "Signing In..." : "Login"}
            {!isSubmitting && <ArrowRight size={18} />}
          </button>

        </form>

        <p className="auth-switch">
          Don't have an account?{" "}
          <button
            type="button"
            onClick={() => navigate("/register")}
          >
            Register
          </button>
        </p>
      </div>
    </main>
  );
}

export default Login;