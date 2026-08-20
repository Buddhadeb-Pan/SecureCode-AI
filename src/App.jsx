import { Routes, Route } from "react-router-dom";

import Welcome from "./components/Welcome.jsx";
import Home from "./pages/Home.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import Features from "./pages/Features.jsx";
import AnalysisDashboard from "./pages/AnalysisDashboard.jsx";
import About from "./pages/About.jsx";
import HowItWorksPage from "./pages/HowItWorksPage.jsx";
function App() {
  return (
    <Routes>
      <Route path="/" element={<Welcome />} />

      <Route path="/login" element={<Login />} />

      <Route path="/register" element={<Register />} />

      <Route path="/home" element={<Home />} />
      <Route path="/features" element={<Features />} />
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
    </Routes>
  );
}

export default App;