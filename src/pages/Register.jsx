import { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Auth.css";
import {
  ShieldCheck,
  User,
  Mail,
  Lock,
  ArrowRight,
} from "lucide-react";

function Register() {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const handleChange = (event) => {
    const { name, value } = event.target;

    setFormData((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();

    if (formData.password !== formData.confirmPassword) {
      alert("Passwords do not match.");
      return;
    }

    // Backend পরে connect করব
    console.log("Register Data:", formData);

    navigate("/login");
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
              placeholder="Create password"
              value={formData.password}
              onChange={handleChange}
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
              required
            />
          </div>

          <button type="submit" className="auth-submit">
            Create Account
            <ArrowRight size={18} />
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