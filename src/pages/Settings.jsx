import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  CalendarDays,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
  LogOut,
  Mail,
  Pencil,
  RefreshCw,
  Shield,
  ShieldCheck,
  UserRound,
  Trash2,
} from "lucide-react";

import ProfileAvatar from "../Components/ProfileAvatar.jsx";
import {
  getStoredToken,
  getStoredUser,
  setStoredUser,
  logoutUser,
  deleteUserAccount,
} from "../config/api.js";
import {
  fetchCurrentProfile,
  updateCurrentProfileName,
  changeUserPassword,
} from "../config/profile.js";
import LogoutConfirmModal from "../Components/LogoutConfirmModal.jsx";
import DeleteAccountModal from "../Components/DeleteAccountModal.jsx";
import "./Settings.css";

function formatMemberSince(createdAt) {
  if (!createdAt) {
    return "Unavailable";
  }

  const memberSince = new Date(createdAt);
  if (Number.isNaN(memberSince.getTime())) {
    return "Unavailable";
  }

  return new Intl.DateTimeFormat("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  }).format(memberSince);
}

function Settings() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState("account"); // "account" | "security"

  // User state
  const [user, setUser] = useState(() => getStoredUser());
  const [isLoading, setIsLoading] = useState(!getStoredUser());
  const [loadError, setLoadError] = useState("");

  // Account tab state (Edit Name)
  const [isEditingName, setIsEditingName] = useState(false);
  const [nameInput, setNameInput] = useState("");
  const [isSavingName, setIsSavingName] = useState(false);
  const [nameError, setNameError] = useState("");

  // Security tab state (Change Password)
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [passwordError, setPasswordError] = useState("");

  // General feedback
  const [feedback, setFeedback] = useState(null);

  // Logout modal state
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState("");

  // Delete account modal state
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [isDeletingAccount, setIsDeletingAccount] = useState(false);
  const [deleteAccountError, setDeleteAccountError] = useState("");

  const loadSettingsData = useCallback(
    async (signal) => {
      if (!getStoredToken()) {
        navigate("/login", {
          replace: true,
          state: { from: "/settings" },
        });
        return;
      }

      try {
        const currentProfile = await fetchCurrentProfile(
          signal ? { signal } : {},
        );

        if (signal?.aborted) {
          return;
        }

        setLoadError("");
        setUser(currentProfile);
      } catch (error) {
        if (error.name === "AbortError" || signal?.aborted) {
          return;
        }

        if (error.status === 401 || !getStoredToken()) {
          navigate("/login", {
            replace: true,
            state: { from: "/settings" },
          });
          return;
        }

        if (!getStoredUser()) {
          setUser(null);
          setLoadError("Unable to load your settings.");
        }
      } finally {
        if (!signal?.aborted) {
          setIsLoading(false);
        }
      }
    },
    [navigate],
  );

  useEffect(() => {
    const controller = new AbortController();
    loadSettingsData(controller.signal);

    return () => controller.abort();
  }, [loadSettingsData]);

  // Sync when user changes anywhere in app
  useEffect(() => {
    const handleAuthChange = () => {
      const stored = getStoredUser();
      if (stored) {
        setUser(stored);
      } else if (!getStoredToken()) {
        navigate("/login", { replace: true });
      }
    };

    window.addEventListener("auth-changed", handleAuthChange);
    return () => window.removeEventListener("auth-changed", handleAuthChange);
  }, [navigate]);

  // --- ACCOUNT TAB HANDLERS ---
  const handleStartEditName = () => {
    setNameInput(user?.name || "");
    setNameError("");
    setFeedback(null);
    setIsEditingName(true);
  };

  const handleCancelEditName = () => {
    setNameInput(user?.name || "");
    setNameError("");
    setIsEditingName(false);
  };

  const handleSaveName = async (e) => {
    if (e) e.preventDefault();

    const trimmed = (nameInput || "").trim();
    if (!trimmed) {
      setNameError("Full name cannot be empty.");
      return;
    }

    if (user && trimmed === user.name) {
      setIsEditingName(false);
      return;
    }

    setIsSavingName(true);
    setNameError("");
    setFeedback(null);

    try {
      const updatedProfile = await updateCurrentProfileName(trimmed);
      setUser(updatedProfile);
      setStoredUser(updatedProfile);
      setIsEditingName(false);
      setFeedback({
        type: "success",
        message: "Account name updated successfully.",
      });
    } catch (err) {
      setFeedback({
        type: "error",
        message: err.message || "Unable to update account name. Please try again.",
      });
    } finally {
      setIsSavingName(false);
    }
  };

  // --- SECURITY TAB HANDLERS ---
  const handleChangePassword = async (e) => {
    if (e) e.preventDefault();

    setPasswordError("");
    setFeedback(null);

    if (!currentPassword) {
      setPasswordError("Current password is required.");
      return;
    }

    if (!newPassword) {
      setPasswordError("New password is required.");
      return;
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      setPasswordError("New password must be between 8 and 128 characters long.");
      return;
    }

    if (!/[a-zA-Z]/.test(newPassword)) {
      setPasswordError("New password must contain at least one letter.");
      return;
    }

    if (!/[0-9]/.test(newPassword)) {
      setPasswordError("New password must contain at least one number.");
      return;
    }

    if (!confirmPassword) {
      setPasswordError("Please confirm your new password.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords do not match.");
      return;
    }

    setIsChangingPassword(true);

    try {
      const result = await changeUserPassword({
        currentPassword,
        newPassword,
        confirmPassword,
      });

      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setFeedback({
        type: "success",
        message: result.message || "Password has been successfully updated.",
      });
    } catch (err) {
      setFeedback({
        type: "error",
        message: err.message || "Unable to change password. Please try again.",
      });
    } finally {
      setIsChangingPassword(false);
    }
  };

  // --- LOGOUT HANDLERS ---
  const handleOpenLogoutModal = () => {
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

  // --- DELETE ACCOUNT HANDLERS ---
  const handleOpenDeleteModal = () => {
    setDeleteAccountError("");
    setShowDeleteModal(true);
  };

  const handleCloseDeleteModal = () => {
    if (!isDeletingAccount) {
      setShowDeleteModal(false);
      setDeleteAccountError("");
    }
  };

  const handleConfirmDelete = async ({ currentPassword, confirmation }) => {
    setIsDeletingAccount(true);
    setDeleteAccountError("");
    try {
      await deleteUserAccount({ currentPassword, confirmation });
      setShowDeleteModal(false);
      navigate("/login");
    } catch (err) {
      setDeleteAccountError(
        err.message || "Unable to delete your account. Please try again.",
      );
    } finally {
      setIsDeletingAccount(false);
    }
  };

  return (
    <main className="settings-page">
      <header className="settings-page-header">
        <Link to="/home" className="settings-page-brand">
          <span className="settings-page-brand-icon">
            <ShieldCheck size={25} strokeWidth={1.9} />
          </span>
          <span>
            SecureCode <strong>AI</strong>
          </span>
        </Link>

        <Link to="/home" className="settings-page-back-link">
          <ArrowLeft size={17} />
          Back to Home
        </Link>
      </header>

      <section className="settings-page-content" aria-busy={isLoading}>
        <div className="settings-header-meta">
          <h1 className="settings-section-title">Settings</h1>
          <p className="settings-section-desc">
            Manage your account and security preferences
          </p>
        </div>

        {/* NAVIGATION TABS */}
        <nav className="settings-tabs" aria-label="Settings sections">
          <button
            type="button"
            className={`settings-tab-btn ${
              activeTab === "account" ? "is-active" : ""
            }`}
            onClick={() => {
              setActiveTab("account");
              setFeedback(null);
            }}
          >
            <UserRound size={17} />
            <span>Account</span>
          </button>

          <button
            type="button"
            className={`settings-tab-btn ${
              activeTab === "security" ? "is-active" : ""
            }`}
            onClick={() => {
              setActiveTab("security");
              setFeedback(null);
            }}
          >
            <Shield size={17} />
            <span>Security</span>
          </button>
        </nav>

        {/* LOADING STATE */}
        {isLoading && !user && (
          <div className="settings-state-card" role="status">
            <span className="settings-loading-spinner" aria-hidden="true" />
            <h2>Loading your settings</h2>
            <p>Confirming your SecureCode AI account details.</p>
          </div>
        )}

        {/* ERROR STATE */}
        {!isLoading && loadError && !user && (
          <div
            className="settings-state-card settings-state-card--error"
            role="alert"
          >
            <RefreshCw size={30} />
            <h2>Settings unavailable</h2>
            <p>{loadError}</p>
            <button type="button" onClick={() => loadSettingsData()}>
              Try Again
            </button>
          </div>
        )}

        {/* MAIN SETTINGS CONTENT */}
        {user && (
          <article className="settings-card">
            <div className="settings-card-accent" aria-hidden="true" />

            {/* FEEDBACK BANNER */}
            {feedback && (
              <div
                className={`settings-feedback-alert settings-feedback-alert--${feedback.type}`}
                role="status"
              >
                {feedback.type === "success" ? (
                  <CheckCircle2 size={18} className="settings-feedback-icon" />
                ) : (
                  <AlertCircle size={18} className="settings-feedback-icon" />
                )}
                <span>{feedback.message}</span>
              </div>
            )}

            {/* TAB 1: ACCOUNT SECTION */}
            {activeTab === "account" && (
              <>
                {/* HERO IDENTITY */}
                <div className="settings-account-hero">
                  <ProfileAvatar
                    name={user.name}
                    imageUrl={user.profile_image_url}
                    size="large"
                  />

                  <div className="settings-account-heading">
                    <span className="settings-eyebrow">AUTHENTICATED USER</span>
                    <h2>{user.name}</h2>
                    <p>{user.email}</p>
                  </div>

                  <span
                    className={`settings-account-badge ${
                      user.is_active !== false ? "is-active" : "is-inactive"
                    }`}
                  >
                    <CheckCircle2 size={16} />
                    {user.is_active !== false ? "Active Account" : "Inactive Account"}
                  </span>
                </div>

                <div className="settings-divider" />

                {/* ACCOUNT DETAILS */}
                <div className="settings-subcard">
                  <h3 className="settings-section-header">ACCOUNT INFORMATION</h3>

                  <dl className="settings-details-grid">
                    {/* FULL NAME */}
                    <div className="settings-detail-item">
                      <span className="settings-detail-icon">
                        <UserRound size={20} />
                      </span>

                      <div className="settings-detail-content">
                        <dt>Full Name</dt>

                        {isEditingName ? (
                          <form
                            onSubmit={handleSaveName}
                            className="settings-inline-form"
                          >
                            <input
                              type="text"
                              className={`settings-edit-input ${
                                nameError ? "has-error" : ""
                              }`}
                              value={nameInput}
                              onChange={(e) => {
                                setNameInput(e.target.value);
                                setNameError("");
                              }}
                              placeholder="Enter your full name"
                              maxLength={255}
                              disabled={isSavingName}
                              autoFocus
                              aria-label="Edit full name"
                            />

                            {nameError && (
                              <div className="settings-field-error" role="alert">
                                {nameError}
                              </div>
                            )}

                            <div className="settings-edit-buttons">
                              <button
                                type="submit"
                                className="settings-btn-save-sm"
                                disabled={isSavingName}
                              >
                                {isSavingName ? "Saving..." : "Save Changes"}
                              </button>

                              <button
                                type="button"
                                className="settings-btn-cancel-sm"
                                onClick={handleCancelEditName}
                                disabled={isSavingName}
                              >
                                Cancel
                              </button>
                            </div>
                          </form>
                        ) : (
                          <div className="settings-name-display-row">
                            <dd>{user.name}</dd>

                            <button
                              type="button"
                              className="settings-btn-edit-inline"
                              onClick={handleStartEditName}
                              aria-label="Edit full name"
                            >
                              <Pencil size={13} />
                              Edit
                            </button>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* EMAIL ADDRESS - READ ONLY */}
                    <div className="settings-detail-item">
                      <span className="settings-detail-icon">
                        <Mail size={20} />
                      </span>

                      <div className="settings-detail-content">
                        <dt>Email Address</dt>
                        <dd>{user.email}</dd>
                        <span className="settings-readonly-hint">
                          Verified account email (read-only)
                        </span>
                      </div>
                    </div>

                    {/* MEMBER SINCE */}
                    <div className="settings-detail-item">
                      <span className="settings-detail-icon">
                        <CalendarDays size={20} />
                      </span>

                      <div className="settings-detail-content">
                        <dt>Member Since</dt>
                        <dd>{formatMemberSince(user.created_at)}</dd>
                      </div>
                    </div>

                    {/* ACCOUNT STATUS */}
                    <div className="settings-detail-item">
                      <span className="settings-detail-icon">
                        <CheckCircle2 size={20} />
                      </span>

                      <div className="settings-detail-content">
                        <dt>Account Status</dt>
                        <dd>
                          {user.is_active !== false ? "Active" : "Inactive"}
                        </dd>
                      </div>
                    </div>
                  </dl>
                </div>
              </>
            )}

            {/* TAB 2: SECURITY SECTION */}
            {activeTab === "security" && (
              <>
                {/* CHANGE PASSWORD SUBCARD */}
                <div className="settings-subcard">
                  <div className="settings-subcard-header">
                    <h3>Change Password</h3>
                    <p>Update your password to keep your account secure.</p>
                  </div>

                  <form
                    onSubmit={handleChangePassword}
                    className="settings-password-form"
                  >
                    {/* CURRENT PASSWORD */}
                    <div className="settings-form-group">
                      <label
                        htmlFor="current-password"
                        className="settings-form-label"
                      >
                        Current Password
                      </label>
                      <div className="settings-input-wrapper">
                        <input
                          id="current-password"
                          type={showCurrentPassword ? "text" : "password"}
                          value={currentPassword}
                          onChange={(e) => {
                            setCurrentPassword(e.target.value);
                            setPasswordError("");
                          }}
                          className={`settings-text-input ${
                            passwordError ? "has-error" : ""
                          }`}
                          placeholder="Enter current password"
                          autoComplete="current-password"
                          disabled={isChangingPassword}
                        />
                        <button
                          type="button"
                          className="settings-pwd-toggle"
                          onClick={() =>
                            setShowCurrentPassword((prev) => !prev)
                          }
                          aria-label={
                            showCurrentPassword
                              ? "Hide current password"
                              : "Show current password"
                          }
                        >
                          {showCurrentPassword ? (
                            <EyeOff size={16} />
                          ) : (
                            <Eye size={16} />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* NEW PASSWORD */}
                    <div className="settings-form-group">
                      <label
                        htmlFor="new-password"
                        className="settings-form-label"
                      >
                        New Password
                      </label>
                      <div className="settings-input-wrapper">
                        <input
                          id="new-password"
                          type={showNewPassword ? "text" : "password"}
                          value={newPassword}
                          onChange={(e) => {
                            setNewPassword(e.target.value);
                            setPasswordError("");
                          }}
                          className={`settings-text-input ${
                            passwordError ? "has-error" : ""
                          }`}
                          placeholder="At least 8 characters (letters & numbers)"
                          autoComplete="new-password"
                          disabled={isChangingPassword}
                        />
                        <button
                          type="button"
                          className="settings-pwd-toggle"
                          onClick={() => setShowNewPassword((prev) => !prev)}
                          aria-label={
                            showNewPassword
                              ? "Hide new password"
                              : "Show new password"
                          }
                        >
                          {showNewPassword ? (
                            <EyeOff size={16} />
                          ) : (
                            <Eye size={16} />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* CONFIRM NEW PASSWORD */}
                    <div className="settings-form-group">
                      <label
                        htmlFor="confirm-password"
                        className="settings-form-label"
                      >
                        Confirm New Password
                      </label>
                      <div className="settings-input-wrapper">
                        <input
                          id="confirm-password"
                          type={showConfirmPassword ? "text" : "password"}
                          value={confirmPassword}
                          onChange={(e) => {
                            setConfirmPassword(e.target.value);
                            setPasswordError("");
                          }}
                          className={`settings-text-input ${
                            passwordError ? "has-error" : ""
                          }`}
                          placeholder="Re-enter your new password"
                          autoComplete="new-password"
                          disabled={isChangingPassword}
                        />
                        <button
                          type="button"
                          className="settings-pwd-toggle"
                          onClick={() =>
                            setShowConfirmPassword((prev) => !prev)
                          }
                          aria-label={
                            showConfirmPassword
                              ? "Hide confirm password"
                              : "Show confirm password"
                          }
                        >
                          {showConfirmPassword ? (
                            <EyeOff size={16} />
                          ) : (
                            <Eye size={16} />
                          )}
                        </button>
                      </div>
                    </div>

                    {passwordError && (
                      <div className="settings-field-error" role="alert">
                        {passwordError}
                      </div>
                    )}

                    <div className="settings-password-policy">
                      Password policy: Minimum 8 characters with at least one letter
                      and one number.
                    </div>

                    <button
                      type="submit"
                      className="settings-btn-save-main"
                      disabled={isChangingPassword}
                    >
                      {isChangingPassword ? "Updating..." : "Update Password"}
                    </button>
                  </form>
                </div>

                <div className="settings-divider" />

                {/* LOGOUT SUBCARD */}
                <div className="settings-logout-card">
                  <div className="settings-logout-info">
                    <h4>Session & Sign Out</h4>
                    <p>
                      Sign out of your active SecureCode AI session on this
                      browser.
                    </p>
                  </div>

                  <button
                    type="button"
                    className="settings-btn-logout"
                    onClick={handleOpenLogoutModal}
                  >
                    <LogOut size={16} />
                    <span>Sign Out</span>
                  </button>
                </div>
              </>
            )}

            {/* DANGER ZONE (at the bottom of Settings) */}
            <div className="settings-divider settings-divider--danger" />

            <div className="settings-danger-card">
              <div className="settings-danger-header-row">
                <span className="settings-danger-eyebrow">DANGER ZONE</span>
              </div>

              <div className="settings-danger-content-row">
                <div className="settings-danger-info">
                  <h4>Delete Account</h4>
                  <p>
                    Permanently delete your SecureCode AI account and account information.
                  </p>
                </div>

                <button
                  type="button"
                  className="settings-btn-delete-account"
                  onClick={handleOpenDeleteModal}
                >
                  <Trash2 size={16} />
                  <span>Delete Account</span>
                </button>
              </div>
            </div>
          </article>
        )}
      </section>

      <LogoutConfirmModal
        isOpen={showLogoutModal}
        onClose={handleCloseLogoutModal}
        onConfirm={handleConfirmLogout}
        isLoggingOut={isLoggingOut}
        errorMessage={logoutError}
      />

      <DeleteAccountModal
        isOpen={showDeleteModal}
        onClose={handleCloseDeleteModal}
        onConfirm={handleConfirmDelete}
        isDeleting={isDeletingAccount}
        errorMessage={deleteAccountError}
      />
    </main>
  );
}

export default Settings;
