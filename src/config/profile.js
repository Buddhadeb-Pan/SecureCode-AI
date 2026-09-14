import { API_BASE_URL, authFetch, setStoredUser } from "./api.js";

export class ProfileRequestError extends Error {
  constructor(status) {
    super("Unable to load the current user profile.");
    this.name = "ProfileRequestError";
    this.status = status;
  }
}

export function selectSafeProfile(profileData) {
  const name =
    typeof profileData?.name === "string" ? profileData.name.trim() : "";
  const email =
    typeof profileData?.email === "string" ? profileData.email.trim() : "";

  if (!name || !email) {
    throw new Error("The profile response is missing required safe fields.");
  }

  return {
    name,
    email,
    is_active: profileData?.is_active === true,
    created_at:
      typeof profileData?.created_at === "string"
        ? profileData.created_at
        : null,
    profile_image_url:
      typeof profileData?.profile_image_url === "string"
        ? profileData.profile_image_url.trim()
        : "",
  };
}

export async function fetchCurrentProfile(options = {}) {
  const response = await authFetch(`${API_BASE_URL}/auth/me`, {
    ...options,
    method: "GET",
  });

  if (!response.ok) {
    throw new ProfileRequestError(response.status);
  }

  const profileData = await response.json();
  const safeProfile = selectSafeProfile(profileData);
  setStoredUser(safeProfile);
  return safeProfile;
}

export async function updateCurrentProfileName(newName) {
  const trimmed = typeof newName === "string" ? newName.trim() : "";
  if (!trimmed) {
    throw new Error("Full name cannot be empty.");
  }

  const response = await authFetch(`${API_BASE_URL}/auth/me`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name: trimmed }),
  });

  if (!response.ok) {
    let message = "Unable to update profile. Please try again.";
    try {
      const errJson = await response.json();
      if (typeof errJson?.detail === "string") {
        message = errJson.detail;
      } else if (Array.isArray(errJson?.detail) && errJson.detail[0]?.msg) {
        message = errJson.detail[0].msg.replace(/^Value error,\s*/i, "");
      }
    } catch {
      // Ignore JSON parse errors
    }

    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  const profileData = await response.json();
  const safeProfile = selectSafeProfile(profileData);
  setStoredUser(safeProfile);
  return safeProfile;
}

export async function changeUserPassword({ currentPassword, newPassword, confirmPassword }) {
  if (!currentPassword) {
    throw new Error("Current password is required.");
  }
  if (!newPassword) {
    throw new Error("New password is required.");
  }
  if (newPassword.length < 8) {
    throw new Error("New password must be at least 8 characters long.");
  }
  if (newPassword !== confirmPassword) {
    throw new Error("New passwords do not match.");
  }

  const response = await authFetch(`${API_BASE_URL}/auth/change-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });

  if (!response.ok) {
    let message = "Unable to update password. Please try again.";
    try {
      const errJson = await response.json();
      if (typeof errJson?.detail === "string") {
        message = errJson.detail;
      } else if (Array.isArray(errJson?.detail) && errJson.detail[0]?.msg) {
        message = errJson.detail[0].msg.replace(/^Value error,\s*/i, "");
      }
    } catch {
      // Ignore JSON parse errors
    }

    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return await response.json();
}


