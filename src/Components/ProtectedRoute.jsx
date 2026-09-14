import { Navigate, useLocation } from "react-router-dom";
import { getStoredToken } from "../config/api.js";

/**
 * Route wrapper that enforces authentication for protected views.
 * If the user is unauthenticated (no token), immediately redirects to /login,
 * saving the attempted path in location state.
 */
function ProtectedRoute({ children }) {
  const token = getStoredToken();
  const location = useLocation();

  if (!token) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return children;
}

export default ProtectedRoute;
