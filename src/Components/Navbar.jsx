import { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";

import {
  ShieldCheck,
  CircleUserRound,
  Menu,
  X,
  LogOut,
  ChevronDown,
  User,
  Settings,
} from "lucide-react";
import {
  API_BASE_URL,
  authFetch,
  getStoredToken,
  getStoredUser,
  setStoredUser,
  logoutUser,
} from "../config/api.js";
import ProfileAvatar from "./ProfileAvatar.jsx";
import LogoutConfirmModal from "./LogoutConfirmModal.jsx";
import "./Navbar.css";

function Navbar() {
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const [user, setUser] = useState(getStoredUser());
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const dropdownRef = useRef(null);

  const closeMenu = () => {
    setMenuOpen(false);
  };

  useEffect(() => {
    let isSubscribed = true;

    const syncUser = () => {
      setUser(getStoredUser());
    };

    syncUser();
    window.addEventListener("auth-changed", syncUser);

    const token = getStoredToken();
    if (token) {
      authFetch(`${API_BASE_URL}/auth/me`)
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data && isSubscribed) {
            const current = getStoredUser();
            if (
              !current ||
              current.name !== data.name ||
              current.email !== data.email ||
              current.is_active !== data.is_active
            ) {
              setStoredUser(data);
              setUser(data);
            }
          }
        })
        .catch(() => {});
    }

    return () => {
      isSubscribed = false;
      window.removeEventListener("auth-changed", syncUser);
    };
  }, []);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setProfileDropdownOpen(false);
      }
    };

    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setProfileDropdownOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  const handleProfileClick = () => {
    if (!user && !getStoredToken()) {
      navigate("/login");
    } else {
      setProfileDropdownOpen((prev) => !prev);
    }
  };

  const handleOpenLogoutModal = () => {
    setProfileDropdownOpen(false);
    setLogoutError("");
    setShowLogoutModal(true);
  };

  const handleCloseLogoutModal = () => {
    if (!isLoggingOut) {
      setShowLogoutModal(false);
      setLogoutError("");
    }
  };

  const handleConfirmLogout = async () => {
    setIsLoggingOut(true);
    setLogoutError("");
    try {
      await logoutUser();
      setUser(null);
      setShowLogoutModal(false);
      navigate("/login");
    } catch (err) {
      setLogoutError(
        err.message || "Unable to sign out securely. Please try again.",
      );
    } finally {
      setIsLoggingOut(false);
    }
  };

  return (
    <header className="main-navbar">
      <div className="main-navbar-inner">
        {/* LEFT - BRAND */}
        <Link to="/home" className="main-logo" onClick={closeMenu}>
          <span className="main-logo-icon">
            <ShieldCheck size={27} strokeWidth={1.9} />
          </span>

          <span className="main-logo-text">
            SecureCode <strong>AI</strong>
          </span>
        </Link>

        {/* CENTER */}
        <nav className={`main-nav-links ${menuOpen ? "open" : ""}`}>
          <Link to="/home" onClick={closeMenu}>
            Home
          </Link>

          <Link to="/features" onClick={closeMenu}>
            Features
          </Link>

          <Link to="/how-it-works" onClick={closeMenu}>
            How It Works
          </Link>

          <Link to="/about" onClick={closeMenu}>
            About
          </Link>
        </nav>

        {/* RIGHT - PROFILE & MOBILE CONTROLS */}
        <div className="main-navbar-actions">
          <div className="profile-button-wrapper" ref={dropdownRef}>
            {user ? (
              <button
                type="button"
                className="profile-button"
                onClick={handleProfileClick}
                aria-label="User profile menu"
                aria-expanded={profileDropdownOpen}
              >
                <ProfileAvatar
                  name={user.name}
                  imageUrl={user.profile_image_url}
                  size="small"
                />

                <span className="profile-button-name">{user.name}</span>

                <ChevronDown
                  size={14}
                  className={`profile-chevron ${
                    profileDropdownOpen ? "open" : ""
                  }`}
                />
              </button>
            ) : (
              <button
                type="button"
                className="profile-button"
                onClick={handleProfileClick}
                aria-label="Sign in"
              >
                <span className="profile-icon-guest">
                  <CircleUserRound size={20} />
                </span>

                <span className="profile-button-name">Sign In</span>
              </button>
            )}

            {profileDropdownOpen && user && (
              <div
                className="profile-dropdown-menu"
                role="menu"
                aria-label="Profile actions"
              >
                <div className="profile-dropdown-header">
                  <div className="profile-dropdown-avatar-wrap">
                    <ProfileAvatar
                      name={user.name}
                      imageUrl={user.profile_image_url}
                      size="medium"
                    />
                  </div>

                  <div className="profile-dropdown-name">{user.name}</div>
                  <div className="profile-dropdown-email">{user.email}</div>

                  <div
                    className={`profile-dropdown-status ${
                      user.is_active !== false ? "is-active" : "is-inactive"
                    }`}
                  >
                    <span className="profile-status-dot" />
                    {user.is_active !== false
                      ? "Active Account"
                      : "Inactive Account"}
                  </div>
                </div>

                <div className="profile-dropdown-items">
                  <button
                    type="button"
                    className="profile-dropdown-item"
                    role="menuitem"
                    onClick={() => {
                      setProfileDropdownOpen(false);
                      navigate("/profile");
                    }}
                  >
                    <span className="profile-dropdown-item-icon">
                      <User size={16} />
                    </span>
                    <span>My Profile</span>
                  </button>

                  <button
                    type="button"
                    className="profile-dropdown-item"
                    role="menuitem"
                    onClick={() => {
                      setProfileDropdownOpen(false);
                      navigate("/settings");
                    }}
                  >
                    <span className="profile-dropdown-item-icon">
                      <Settings size={16} />
                    </span>
                    <span>Account Settings</span>
                  </button>

                  <div className="profile-dropdown-divider" />

                  <button
                    type="button"
                    className="profile-dropdown-item logout-item"
                    role="menuitem"
                    onClick={handleOpenLogoutModal}
                  >
                    <span className="profile-dropdown-item-icon">
                      <LogOut size={16} />
                    </span>
                    <span>Logout</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* MOBILE HAMBURGER BUTTON */}
          <button
            type="button"
            className="main-menu-button"
            onClick={() => setMenuOpen((prev) => !prev)}
            aria-label="Toggle navigation"
          >
            {menuOpen ? <X size={26} /> : <Menu size={26} />}
          </button>
        </div>
      </div>

      <LogoutConfirmModal
        isOpen={showLogoutModal}
        onClose={handleCloseLogoutModal}
        onConfirm={handleConfirmLogout}
        isLoggingOut={isLoggingOut}
        errorMessage={logoutError}
      />
    </header>
  );
}

export default Navbar;