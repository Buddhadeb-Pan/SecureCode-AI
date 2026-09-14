import { useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, Eye, EyeOff, AlertCircle } from "lucide-react";
import "./DeleteAccountModal.css";

function DeleteAccountModal({
  isOpen,
  onClose,
  onConfirm,
  isDeleting = false,
  errorMessage = "",
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [confirmationInput, setConfirmationInput] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState("");

  const handleClose = useCallback(() => {
    if (!isDeleting) {
      setCurrentPassword("");
      setConfirmationInput("");
      setShowPassword(false);
      setFormError("");
      onClose();
    }
  }, [isDeleting, onClose]);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === "Escape" && !isDeleting) {
        handleClose();
      }
    };

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, isDeleting, handleClose]);

  if (!isOpen) {
    return null;
  }

  const isConfirmed = confirmationInput.trim() === "DELETE";
  const canSubmit = isConfirmed && currentPassword.length > 0 && !isDeleting;

  const handleSubmit = (e) => {
    e.preventDefault();
    setFormError("");

    if (!currentPassword) {
      setFormError("Please enter your current password.");
      return;
    }

    if (!isConfirmed) {
      setFormError("Please type DELETE to confirm account deletion.");
      return;
    }

    onConfirm({
      currentPassword,
      confirmation: confirmationInput.trim(),
    });
  };

  const modalNode = (
    <div
      className="delete-modal-backdrop"
      onClick={handleClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-account-title"
      aria-describedby="delete-account-desc"
    >
      <div
        className="delete-modal-card"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="delete-modal-accent" aria-hidden="true" />

        <div className="delete-modal-icon-wrap" aria-hidden="true">
          <AlertTriangle size={28} strokeWidth={2.2} />
        </div>

        <h2 id="delete-account-title" className="delete-modal-title">
          Delete your account?
        </h2>

        <p id="delete-account-desc" className="delete-modal-message">
          This action is <strong>permanent</strong> and cannot be undone. All your
          account data will be permanently removed from SecureCode AI.
        </p>

        {(errorMessage || formError) && (
          <div className="delete-modal-error" role="alert">
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{formError || errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="delete-modal-form">
          <div className="delete-modal-field">
            <label htmlFor="delete-account-password">
              Confirm with your password
            </label>
            <div className="delete-modal-input-wrap">
              <input
                id="delete-account-password"
                type={showPassword ? "text" : "password"}
                placeholder="Enter your current password"
                value={currentPassword}
                onChange={(e) => {
                  setCurrentPassword(e.target.value);
                  setFormError("");
                }}
                disabled={isDeleting}
                autoComplete="current-password"
                required
              />
              <button
                type="button"
                className="delete-modal-pwd-toggle"
                onClick={() => setShowPassword((prev) => !prev)}
                aria-label={showPassword ? "Hide password" : "Show password"}
                tabIndex={-1}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <div className="delete-modal-field">
            <label htmlFor="delete-account-confirm">
              To verify, type <code>DELETE</code> below:
            </label>
            <input
              id="delete-account-confirm"
              type="text"
              placeholder="DELETE"
              value={confirmationInput}
              onChange={(e) => {
                setConfirmationInput(e.target.value);
                setFormError("");
              }}
              disabled={isDeleting}
              autoComplete="off"
              required
            />
          </div>

          <div className="delete-modal-actions">
            <button
              type="button"
              className="delete-modal-btn-cancel"
              onClick={handleClose}
              disabled={isDeleting}
            >
              Cancel
            </button>

            <button
              type="submit"
              className="delete-modal-btn-delete"
              disabled={!canSubmit}
            >
              {isDeleting ? (
                <>
                  <span className="delete-spinner" aria-hidden="true" />
                  <span>Deleting Account...</span>
                </>
              ) : (
                <span>Delete Account</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  return typeof document !== "undefined"
    ? createPortal(modalNode, document.body)
    : modalNode;
}

export default DeleteAccountModal;
