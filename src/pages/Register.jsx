import { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Auth.css";
import {
  ShieldCheck,
  User,
  Mail,
  Lock,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import { API_BASE_URL } from "../config/api.js";

function Register() {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

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
    setSuccessMessage("");

    const trimmedName = formData.name.trim();
    if (!trimmedName) {
      setErrorMessage("Please enter your name.");
      return;
    }

    const normalizedEmail = formData.email.trim().toLowerCase();
    if (!normalizedEmail) {
      setErrorMessage("Please enter a valid email address.");
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setErrorMessage("Passwords do not match.");
      return;
    }

    if (formData.password.length < 8 || formData.password.length > 128) {
      setErrorMessage("Password must be between 8 and 128 characters long.");
      return;
    }

    if (!/[a-zA-Z]/.test(formData.password)) {
      setErrorMessage("Password must contain at least one letter.");
      return;
    }

    if (!/[0-9]/.test(formData.password)) {
      setErrorMessage("Password must contain at least one number.");
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: trimmedName,
          email: normalizedEmail,
          password: formData.password,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        if (response.status === 409) {
          throw new Error(data.detail || "Email already registered");
        } else if (response.status === 422) {
          let msg = "Password must be between 8 and 128 characters and contain at least one letter and one number.";
          if (Array.isArray(data.detail) && data.detail[0]?.msg) {
            msg = data.detail[0].msg;
          } else if (typeof data.detail === "string") {
            msg = data.detail;
          }
          throw new Error(msg);
        } else {
          throw new Error(data.detail || "Failed to create account. Please try again.");
        }
      }

      setSuccessMessage("Account created successfully! Redirecting to login...");
      setTimeout(() => {
        navigate("/login");
      }, 1500);
    } catch (err) {
      console.error("[AUTH] Registration error:", err);
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

        <h1>Create Account</h1>

        <p className="auth-description">
          Join SecureCode AI and start analysing your code securely.
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

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            Full Name
          </label>

          <div className="auth-input">
            <User size={18} />

            <input
              type="text"
              name="name"
              placeholder="Enter your name"
              value={formData.name}
              onChange={handleChange}
              disabled={isSubmitting}
              required
            />
          </div>

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
              placeholder="Create password (min 8 chars, 1 letter, 1 number)"
              value={formData.password}
              onChange={handleChange}
              disabled={isSubmitting}
              required
            />
          </div>

          <label>
            Confirm Password
          </label>

          <div className="auth-input">
            <Lock size={18} />

            <input
              type="password"
              name="confirmPassword"
              placeholder="Confirm password"
              value={formData.confirmPassword}
              onChange={handleChange}
              disabled={isSubmitting}
              required
            />
          </div>

          <button type="submit" className="auth-submit" disabled={isSubmitting}>
            {isSubmitting ? "Creating Account..." : "Create Account"}
            {!isSubmitting && <ArrowRight size={18} />}
          </button>
        </form>

        <p className="auth-switch">
          Already have an account?{" "}
          <button
            type="button"
            onClick={() => navigate("/login")}
          >
            Login
          </button>
        </p>
      </div>
    </main>
  );
}

export default Register;