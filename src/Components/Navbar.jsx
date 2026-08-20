import { useState } from "react";
import { Link } from "react-router-dom";

import {
  ShieldCheck,
  CircleUserRound,
  Menu,
  X,
} from "lucide-react";

function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);

  const closeMenu = () => {
    setMenuOpen(false);
  };

  return (
    <header className="main-navbar">
      <div className="main-navbar-inner">

        {/* LEFT - BRAND */}
        <a href="#home" className="main-logo" onClick={closeMenu}>
          <span className="main-logo-icon">
            <ShieldCheck size={27} strokeWidth={1.9} />
          </span>

          <span className="main-logo-text">
            SecureCode <strong>AI</strong>
          </span>
        </a>

        {/* CENTER */}
        <nav className={`main-nav-links ${menuOpen ? "open" : ""}`}>
          <a href="#home" onClick={closeMenu}>
            Home
          </a>

          <Link to="/features" onClick={closeMenu}>
  Features
</Link>

          <Link to="/how-it-works" onClick={closeMenu}>
  How It Works
</Link>

          <Link
  to="/about"
  onClick={closeMenu}
>
  About
</Link>
        </nav>

        {/* RIGHT - PROFILE */}
        <button type="button" className="profile-button">
          <span className="profile-icon">
            <CircleUserRound size={22} />
          </span>

          <span>Profile</span>
        </button>

        {/* MOBILE */}
        <button
          type="button"
          className="main-menu-button"
          onClick={() => setMenuOpen((prev) => !prev)}
          aria-label="Toggle navigation"
        >
          {menuOpen ? <X size={26} /> : <Menu size={26} />}
        </button>

      </div>
    </header>
  );
}

export default Navbar;