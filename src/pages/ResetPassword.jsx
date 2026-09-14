import { useState, useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ShieldCheck, Lock, ArrowRight, ArrowLeft, CheckCircle2, AlertCircle, RefreshCw } from "lucide-react";
import { API_BASE_URL } from "../config/api.js";
import "./Auth.css";

function ResetPassword() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Read reset token from URL query string
  const token = useMemo(() => (searchParams.get("token") || "").trim(), [searchParams]);

  const [formData, setFormData] = useState({
    newPassword: "",
    confirmPassword: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage("");

    if (!token) {
      setErrorMessage("Password reset token is missing from the URL. Please request a new reset link.");
      return;
    }

    if (!formData.newPassword || formData.newPassword.length < 8 || formData.newPassword.length > 128) {
      setErrorMessage("New password must be between 8 and 128 characters long.");
      return;
    }

    if (!/[a-zA-Z]/.test(formData.newPassword)) {
      setErrorMessage("New password must contain at least one letter.");
      return;
    }

    if (!/[0-9]/.test(formData.newPassword)) {
      setErrorMessage("New password must contain at least one number.");
      return;
    }

    if (formData.newPassword !== formData.confirmPassword) {
      setErrorMessage("Passwords do not match. Please verify both password fields.");
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/reset-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          token: token,
          new_password: formData.newPassword,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        if (response.status === 400) {
          throw new Error("This password reset link is invalid, expired, or has already been used. Please request a new reset link.");
        } else if (response.status === 422) {
          let msg = "Password must be between 8 and 128 characters long and contain at least one letter and one number.";
          if (Array.isArray(data.detail) && data.detail[0]?.msg) {
            msg = data.detail[0].msg;
          } else if (typeof data.detail === "string") {
            msg = data.detail;
          }
          throw new Error(msg);
        } else {
          throw new Error(data.detail || "Unable to reset password. Please try again later.");
        }
      }

      // Password successfully updated in MySQL with Argon2
      setIsSuccess(true);
    } catch (err) {
      console.error("[AUTH] Password reset error:", err);
      if (err.name === "TypeError" && err.message.includes("fetch")) {
        setErrorMessage("Unable to connect to the authentication server. Please ensure the backend is running.");
      } else {
        setErrorMessage(err.message || "An error occurred while resetting your password.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="auth-page">
      <div className="auth-card">
        {!isSuccess ? (
          <>
            <div className="auth-logo">
              <ShieldCheck size={30} />
            </div>

            <p className="auth-label">SECURECODE AI</p>

            <h1>Reset Password</h1>

            <p className="auth-description">
              Enter your new secure password below to regain access to your account.
            </p>

            {errorMessage && (
              <div className="auth-alert auth-alert-error">
                <AlertCircle size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
                <span>{errorMessage}</span>
              </div>
            )}

            {!token ? (
              <div className="auth-alert auth-alert-error" style={{ display: "block" }}>
                <p style={{ margin: "0 0 12px 0" }}>
                  <strong>Reset Token Missing</strong>
                </p>
                <p style={{ margin: "0 0 16px 0", fontSize: "0.82rem", color: "#fca5a5" }}>
                  This password reset link does not contain a valid security token. Please initiate a new password reset request.
                </p>
                <button
                  type="button"
                  className="auth-submit"
                  onClick={() => navigate("/forgot-password")}
                >
                  <RefreshCw size={18} />
                  Request New Reset Link
                </button>
              </div>
            ) : (
              <form className="auth-form" onSubmit={handleSubmit}>
                <label htmlFor="new-password">
                  New Password (min 8 characters, 1 letter, 1 number)
                </label>

                <div className="auth-input">
                  <Lock size={18} />

                  <input
                    id="new-password"
                    type="password"
                    name="newPassword"
                    placeholder="Enter new password (min 8 chars, 1 letter, 1 number)"
                    value={formData.newPassword}
                    onChange={handleChange}
                    required
                    minLength={8}
                    disabled={isSubmitting}
                  />
                </div>

                <label htmlFor="confirm-password">
                  Confirm New Password
                </label>

                <div className="auth-input">
                  <Lock size={18} />

                  <input
                    id="confirm-password"
                    type="password"
                    name="confirmPassword"
                    placeholder="Confirm new password"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    required
                    minLength={8}
                    disabled={isSubmitting}
                  />
                </div>

                <button type="submit" className="auth-submit" disabled={isSubmitting}>
                  {isSubmitting ? "Updating Password..." : "Reset Password"}
                  {!isSubmitting && <ArrowRight size={18} />}
                </button>
              </form>
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
          </>
        ) : (
          /* SUCCESS STATE */
          <div style={{ textAlign: "center" }}>
            <div className="auth-success-icon">
              <CheckCircle2 size={36} />
            </div>

            <p className="auth-label">PASSWORD UPDATED</p>

            <h1>Password Reset Complete</h1>

            <p className="auth-description">
              Your password has been successfully updated with Argon2 encryption. You can now sign in using your new credentials.
            </p>

            <button
              type="button"
              className="auth-submit"
              onClick={() => navigate("/login")}
            >
              <ArrowLeft size={18} />
              Back to Login
            </button>
          </div>
        )}
      </div>
    </main>
  );
}

export default ResetPassword;
