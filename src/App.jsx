import { Routes, Route } from "react-router-dom";

import Welcome from "./components/Welcome.jsx";
import Home from "./pages/Home.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import ForgotPassword from "./pages/ForgotPassword.jsx";
import ResetPassword from "./pages/ResetPassword.jsx";
import Features from "./pages/Features.jsx";
import AnalysisDashboard from "./pages/AnalysisDashboard.jsx";
import About from "./pages/About.jsx";
import HowItWorksPage from "./pages/HowItWorksPage.jsx";
import FeatureDetail from "./pages/FeatureDetail.jsx";
import Profile from "./pages/Profile.jsx";
import Settings from "./pages/Settings.jsx";
import ProtectedRoute from "./Components/ProtectedRoute.jsx";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Welcome />} />

      <Route path="/login" element={<Login />} />

      <Route path="/register" element={<Register />} />

      <Route path="/forgot-password" element={<ForgotPassword />} />

      <Route path="/reset-password" element={<ResetPassword />} />

      <Route path="/home" element={<Home />} />

      <Route path="/features" element={<Features />} />
      <Route
        path="/features/smart-code-analysis"
        element={<FeatureDetail featureKey="smart-code-analysis" />}
      />
      <Route
        path="/features/vulnerability-detection"
        element={<FeatureDetail featureKey="vulnerability-detection" />}
      />
      <Route
        path="/features/risk-severity"
        element={<FeatureDetail featureKey="risk-severity" />}
      />
      <Route
        path="/features/secure-fix-guidance"
        element={<FeatureDetail featureKey="secure-fix-guidance" />}
      />
      <Route
        path="/features/security-report"
        element={<FeatureDetail featureKey="security-report" />}
      />
      <Route
        path="/features/code-optimization"
        element={<FeatureDetail featureKey="code-optimization" />}
      />
      <Route path="/features/:slug" element={<FeatureDetail />} />

      <Route
        path="/dashboard"
        element={<AnalysisDashboard />}
      />
      <Route
        path="/about"
        element={<About />}
      />
      <Route
        path="/how-it-works"
        element={<HowItWorksPage />}
      />
      <Route
        path="/profile"
        element={
          <ProtectedRoute>
            <Profile />
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <Settings />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

export default App;