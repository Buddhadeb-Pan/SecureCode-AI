import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  CalendarDays,
  CheckCircle2,
  AlertCircle,
  Mail,
  Pencil,
  RefreshCw,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import ProfileAvatar from "../Components/ProfileAvatar.jsx";
import { getStoredToken, getStoredUser, setStoredUser } from "../config/api.js";
import {
  fetchCurrentProfile,
  updateCurrentProfileName,
} from "../config/profile.js";
import "./Profile.css";

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

function Profile() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState(() => getStoredUser());
  const [isLoading, setIsLoading] = useState(!getStoredUser());
  const [loadError, setLoadError] = useState("");

  // Edit display name state
  const [isEditing, setIsEditing] = useState(false);
  const [editName, setEditName] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [validationError, setValidationError] = useState("");
  const [feedback, setFeedback] = useState(null);

  const loadProfile = useCallback(
    async (signal) => {
      if (!getStoredToken()) {
        navigate("/login", {
          replace: true,
          state: { from: "/profile" },
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
        setProfile(currentProfile);
      } catch (error) {
        if (error.name === "AbortError" || signal?.aborted) {
          return;
        }

        if (error.status === 401 || !getStoredToken()) {
          navigate("/login", {
            replace: true,
            state: { from: "/profile" },
          });
          return;
        }

        // If we don't have cached data, show load error
        if (!getStoredUser()) {
          setProfile(null);
          setLoadError("Unable to load your profile.");
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
    loadProfile(controller.signal);

    return () => controller.abort();
  }, [loadProfile]);

  // Sync with auth changes (e.g. from navbar or another tab)
  useEffect(() => {
    const handleAuthChange = () => {
      const stored = getStoredUser();
      if (stored) {
        setProfile(stored);
      } else if (!getStoredToken()) {
        navigate("/login", { replace: true });
      }
    };

    window.addEventListener("auth-changed", handleAuthChange);
    return () => window.removeEventListener("auth-changed", handleAuthChange);
  }, [navigate]);

  const handleStartEdit = () => {
    setEditName(profile?.name || "");
    setValidationError("");
    setFeedback(null);
    setIsEditing(true);
  };

  const handleCancelEdit = () => {
    setEditName(profile?.name || "");
    setValidationError("");
    setIsEditing(false);
  };

  const handleSaveName = async (e) => {
    if (e) {
      e.preventDefault();
    }

    const trimmed = (editName || "").trim();
    if (!trimmed) {
      setValidationError("Full name cannot be empty.");
      return;
    }

    if (profile && trimmed === profile.name) {
      setIsEditing(false);
      return;
    }

    setIsSaving(true);
    setValidationError("");
    setFeedback(null);

    try {
      const updatedProfile = await updateCurrentProfileName(trimmed);
      setProfile(updatedProfile);
      setStoredUser(updatedProfile);
      setIsEditing(false);
      setFeedback({
        type: "success",
        message: "Profile updated successfully.",
      });
    } catch (err) {
      setFeedback({
        type: "error",
        message: err.message || "Unable to update profile. Please try again.",
      });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <main className="profile-page">
      <header className="profile-page-header">
        <Link to="/home" className="profile-page-brand">
          <span className="profile-page-brand-icon">
            <ShieldCheck size={25} strokeWidth={1.9} />
          </span>
          <span>
            SecureCode <strong>AI</strong>
          </span>
        </Link>

        <Link to="/home" className="profile-page-back-link">
          <ArrowLeft size={17} />
          Back to Home
        </Link>
      </header>

      <section className="profile-page-content" aria-busy={isLoading}>
        <div className="profile-header-meta">
          <h1 className="profile-section-title">Profile</h1>
          <p className="profile-section-desc">
            Manage your personal information
          </p>
        </div>

        {isLoading && !profile && (
          <div className="profile-state-card" role="status">
            <span className="profile-loading-spinner" aria-hidden="true" />
            <h2>Loading your profile</h2>
            <p>Confirming your SecureCode AI account details.</p>
          </div>
        )}

        {!isLoading && loadError && !profile && (
          <div
            className="profile-state-card profile-state-card--error"
            role="alert"
          >
            <RefreshCw size={30} />
            <h2>Profile unavailable</h2>
            <p>{loadError}</p>
            <button type="button" onClick={() => loadProfile()}>
              Try Again
            </button>
          </div>
        )}

        {profile && (
          <article className="profile-card">
            <div className="profile-card-accent" aria-hidden="true" />

            {/* FEEDBACK BANNER */}
            {feedback && (
              <div
                className={`profile-feedback-alert profile-feedback-alert--${feedback.type}`}
                role="status"
              >
                {feedback.type === "success" ? (
                  <CheckCircle2 size={18} className="feedback-icon" />
                ) : (
                  <AlertCircle size={18} className="feedback-icon" />
                )}
                <span>{feedback.message}</span>
              </div>
            )}

            {/* HERO IDENTITY */}
            <div className="profile-card-hero">
              <ProfileAvatar
                name={profile.name}
                imageUrl={profile.profile_image_url}
                size="large"
              />

              <div className="profile-card-heading">
                <span className="profile-card-eyebrow">AUTHENTICATED PROFILE</span>
                <h2>{profile.name}</h2>
                <p>{profile.email}</p>
              </div>

              <span
                className={`profile-account-badge ${
                  profile.is_active !== false ? "is-active" : "is-inactive"
                }`}
              >
                <CheckCircle2 size={16} />
                {profile.is_active !== false
                  ? "Active Account"
                  : "Inactive Account"}
              </span>
            </div>

            <div className="profile-card-divider" />

            {/* ACCOUNT INFORMATION SECTION */}
            <div className="profile-info-section">
              <h3 className="profile-info-header">ACCOUNT INFORMATION</h3>

              <dl className="profile-details-grid">
                {/* FULL NAME - EDITABLE */}
                <div className="profile-detail-item profile-detail-item--name">
                  <span className="profile-detail-icon">
                    <UserRound size={20} />
                  </span>

                  <div className="profile-detail-content">
                    <dt>Full Name</dt>

                    {isEditing ? (
                      <form
                        onSubmit={handleSaveName}
                        className="profile-inline-form"
                      >
                        <input
                          type="text"
                          className={`profile-edit-input ${
                            validationError ? "has-error" : ""
                          }`}
                          value={editName}
                          onChange={(e) => {
                            setEditName(e.target.value);
                            setValidationError("");
                          }}
                          placeholder="Enter your full name"
                          maxLength={255}
                          disabled={isSaving}
                          autoFocus
                          aria-label="Edit full name"
                        />

                        {validationError && (
                          <div
                            className="profile-field-error"
                            role="alert"
                          >
                            {validationError}
                          </div>
                        )}

                        <div className="profile-edit-buttons">
                          <button
                            type="submit"
                            className="profile-btn-save"
                            disabled={isSaving}
                          >
                            {isSaving ? "Saving..." : "Save Changes"}
                          </button>

                          <button
                            type="button"
                            className="profile-btn-cancel"
                            onClick={handleCancelEdit}
                            disabled={isSaving}
                          >
                            Cancel
                          </button>
                        </div>
                      </form>
                    ) : (
                      <div className="profile-name-display-row">
                        <dd>{profile.name}</dd>

                        <button
                          type="button"
                          className="profile-btn-edit-inline"
                          onClick={handleStartEdit}
                          aria-label="Edit display name"
                        >
                          <Pencil size={13} />
                          Edit
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* EMAIL ADDRESS - READ ONLY */}
                <div className="profile-detail-item">
                  <span className="profile-detail-icon">
                    <Mail size={20} />
                  </span>

                  <div className="profile-detail-content">
                    <dt>Email Address</dt>
                    <dd>{profile.email}</dd>
                    <span className="profile-readonly-hint">
                      Verified account email
                    </span>
                  </div>
                </div>

                {/* MEMBER SINCE */}
                <div className="profile-detail-item">
                  <span className="profile-detail-icon">
                    <CalendarDays size={20} />
                  </span>

                  <div className="profile-detail-content">
                    <dt>Member Since</dt>
                    <dd>{formatMemberSince(profile.created_at)}</dd>
                  </div>
                </div>

                {/* ACCOUNT STATUS */}
                <div className="profile-detail-item">
                  <span className="profile-detail-icon">
                    <CheckCircle2 size={20} />
                  </span>

                  <div className="profile-detail-content">
                    <dt>Account Status</dt>
                    <dd>
                      {profile.is_active !== false ? "Active" : "Inactive"}
                    </dd>
                  </div>
                </div>
              </dl>
            </div>

            <div className="profile-card-divider" />

            {/* ACTIONS SECTION */}
            <div className="profile-actions-section">
              <div className="profile-actions-heading">
                <h4>Actions</h4>
              </div>

              {!isEditing ? (
                <button
                  type="button"
                  className="profile-btn-edit-action"
                  onClick={handleStartEdit}
                >
                  <Pencil size={15} />
                  Edit Profile
                </button>
              ) : (
                <div className="profile-editing-note">
                  You are editing your display name above. Click "Save Changes"
                  or "Cancel" to finish.
                </div>
              )}
            </div>

            <p className="profile-card-note">
              Profile information is loaded securely from your authenticated
              SecureCode AI account.
            </p>
          </article>
        )}
      </section>
    </main>
  );
}

export default Profile;
