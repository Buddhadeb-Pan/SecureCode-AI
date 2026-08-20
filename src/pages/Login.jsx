import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Mail, Lock, ArrowRight } from "lucide-react";
import "./Auth.css";
function Login() {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    email: "",
    password: "",
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

    // Backend পরে connect করব
    console.log("Login Data:", formData);

    navigate("/home");
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
              required
            />
          </div>

          <button type="submit" className="auth-submit">
            Login
            <ArrowRight size={18} />
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