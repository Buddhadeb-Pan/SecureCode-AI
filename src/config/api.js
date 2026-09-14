/**
 * Centralized API configuration and authenticated fetch helper for SecureCode AI.
 * Falls back to http://127.0.0.1:8000 if VITE_API_BASE_URL is not configured.
 */

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export function getStoredToken() {
  const token = localStorage.getItem("token");
  if (!token || token === "undefined" || token === "null" || !token.trim()) {
    return null;
  }
  return token.trim();
}

export function setStoredToken(token) {
  if (token) {
    localStorage.setItem("token", token);
  } else {
    localStorage.removeItem("token");
  }
  window.dispatchEvent(new Event("auth-changed"));
}

export function getStoredUser() {
  if (!getStoredToken()) {
    return null;
  }
  try {
    const u = localStorage.getItem("user");
    return u ? JSON.parse(u) : null;
  } catch {
    return null;
  }
}

export function setStoredUser(user) {
  if (user) {
    localStorage.setItem("user", JSON.stringify(user));
  } else {
    localStorage.removeItem("user");
  }
  window.dispatchEvent(new Event("auth-changed"));
}

export function clearStoredAuth() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  window.dispatchEvent(new Event("auth-changed"));
}

export async function logoutUser() {
  const response = await fetch(`${API_BASE_URL}/auth/logout`, {
    method: "POST",
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Unable to sign out securely. Please try again.");
  }

  clearStoredAuth();
  return true;
}

export async function deleteUserAccount({ currentPassword, confirmation }) {
  const response = await authFetch(`${API_BASE_URL}/auth/me`, {
    method: "DELETE",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      current_password: currentPassword,
      confirmation: confirmation,
    }),
  });

  if (!response.ok) {
    let message = "Unable to delete account. Please try again.";
    try {
      const errJson = await response.json();
      if (typeof errJson?.detail === "string") {
        message = errJson.detail;
      } else if (Array.isArray(errJson?.detail) && errJson.detail[0]?.msg) {
        message = errJson.detail[0].msg.replace(/^Value error,\s*/i, "");
      }
    } catch {
      // Ignore parse failure
    }

    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  clearStoredAuth();
  return await response.json();
}


export async function refreshAccessToken() {
  try {
    const res = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    if (res.ok) {
      const data = await res.json();
      if (data.access_token) {
        setStoredToken(data.access_token);
        return data.access_token;
      }
    }
  } catch (err) {
    console.warn("[AUTH] Refresh token failed:", err);
  }
  clearStoredAuth();
  return null;
}

export async function authFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  let token = getStoredToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  } else {
    // For unauthenticated guest requests, pass the signed guest trial token if present
    const guestTrialToken = localStorage.getItem("guest_trial_token");
    if (
      guestTrialToken &&
      guestTrialToken !== "undefined" &&
      guestTrialToken !== "null" &&
      guestTrialToken.trim() !== ""
    ) {
      headers.set("X-Guest-Trial-Token", guestTrialToken.trim());
    }
  }

  const fetchOptions = {
    ...options,
    headers,
    credentials: "include",
  };

  let response = await fetch(url, fetchOptions);

  // If server sent or refreshed guest trial token, persist it locally
  const guestHeader = response.headers.get("X-Guest-Trial-Token");
  if (guestHeader && guestHeader !== "undefined" && guestHeader !== "null" && guestHeader.trim() !== "") {
    localStorage.setItem("guest_trial_token", guestHeader.trim());
  }

  // If access token expired (401), attempt refresh once
  if (response.status === 401 && token) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      headers.set("Authorization", `Bearer ${newToken}`);
      response = await fetch(url, {
        ...options,
        headers,
        credentials: "include",
      });
      if (response.status === 401) {
        clearStoredAuth();
      }
    } else {
      clearStoredAuth();
    }
  }

  return response;
}
