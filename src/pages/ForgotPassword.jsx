import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Mail, ArrowRight, ArrowLeft, CheckCircle2, AlertCircle } from "lucide-react";
import { API_BASE_URL } from "../config/api.js";
import "./Auth.css";

function ForgotPassword() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");

    const trimmedEmail = email.trim().toLowerCase();
    if (!trimmedEmail) {
      setErrorMessage("Please enter your email address.");
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/forgot-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email: trimmedEmail }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.detail || "Unable to process password reset request. Please try again later.");
      }

      // Safe backend message - never displays token or link in browser
      setSuccessMessage(
        data.message || "If an account exists for this email, a password reset link has been sent."
      );
    } catch (err) {
      console.error("[AUTH] Forgot password request error:", err);
      if (err.name === "TypeError" && err.message.includes("fetch")) {
        setErrorMessage("Unable to connect to the authentication server. Please ensure the backend is running.");
      } else {
        setErrorMessage(err.message || "An unexpected error occurred. Please try again.");
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

        <h1>Forgot Password</h1>

        <p className="auth-description">
          Enter your registered email address and we'll generate a secure reset link for your account.
        </p>

        {errorMessage && (
          <div className="auth-alert auth-alert-error">
            <AlertCircle size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
            <span>{errorMessage}</span>
          </div>
        )}

        {successMessage && (
          <div className="auth-alert auth-alert-success">
            <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
            <span>{successMessage}</span>
          </div>
        )}

        {!successMessage ? (
          <form className="auth-form" onSubmit={handleSubmit}>
            <label htmlFor="forgot-email">
              Email Address
            </label>

            <div className="auth-input">
              <Mail size={18} />

              <input
                id="forgot-email"
                type="email"
                name="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={isSubmitting}
              />
            </div>

            <button type="submit" className="auth-submit" disabled={isSubmitting}>
              {isSubmitting ? "Sending Reset Link..." : "Send Reset Link"}
              {!isSubmitting && <ArrowRight size={18} />}
            </button>
          </form>
        ) : (
          <button
            type="button"
            className="auth-submit"
            onClick={() => navigate("/login")}
          >
            <ArrowLeft size={18} />
            Back to Login
          </button>
        )}

        <p className="auth-switch">
          Remember your password?{" "}
          <button
            type="button"
            onClick={() => navigate("/login")}
          >
            Back to Login
          </button>
        </p>
      </div>
    </main>
  );
}

export default ForgotPassword;
