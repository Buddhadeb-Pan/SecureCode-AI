import { useEffect } from "react";
import { createPortal } from "react-dom";
import { AlertCircle, LogOut } from "lucide-react";
import "./LogoutConfirmModal.css";

function LogoutConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  isLoggingOut = false,
  errorMessage = "",
}) {
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === "Escape" && !isLoggingOut) {
        onClose();
      }
    };

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, isLoggingOut, onClose]);

  if (!isOpen) {
    return null;
  }

  const modalNode = (
    <div
      className="logout-modal-backdrop"
      onClick={() => {
        if (!isLoggingOut) {
          onClose();
        }
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="logout-dialog-title"
      aria-describedby="logout-dialog-message"
    >
      <div
        className="logout-modal-card"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="logout-modal-accent" aria-hidden="true" />

        <div className="logout-modal-icon-wrap" aria-hidden="true">
          <LogOut size={26} strokeWidth={2.2} />
        </div>

        <h2 id="logout-dialog-title" className="logout-modal-title">
          Sign out of SecureCode AI?
        </h2>

        <p id="logout-dialog-message" className="logout-modal-message">
          Are you sure you want to log out of your account?
        </p>

        {errorMessage && (
          <div className="logout-modal-error" role="alert">
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{errorMessage}</span>
          </div>
        )}

        <div className="logout-modal-actions">
          <button
            type="button"
            className="logout-modal-btn-cancel"
            onClick={onClose}
            disabled={isLoggingOut}
          >
            Cancel
          </button>

          <button
            type="button"
            className="logout-modal-btn-confirm"
            onClick={onConfirm}
            disabled={isLoggingOut}
          >
            {isLoggingOut ? (
              <>
                <span className="logout-spinner" aria-hidden="true" />
                <span>Signing out...</span>
              </>
            ) : (
              <span>Yes, Log Out</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );

  return typeof document !== "undefined"
    ? createPortal(modalNode, document.body)
    : modalNode;
}

export default LogoutConfirmModal;
