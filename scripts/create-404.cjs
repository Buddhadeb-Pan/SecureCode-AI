/**
 * SecureCode AI — SPA 404 Fallback Generator for GitHub Pages
 *
 * GitHub Pages serves 404.html when a user refreshes or directly navigates to
 * client-side routes (e.g., /profile, /settings, /features/..., /reset-password).
 * By copying the production dist/index.html into dist/404.html, GitHub Pages
 * will serve the React application bundle, allowing React Router to correctly
 * initialize and resolve the target route.
 */

const fs = require("fs");
const path = require("path");

const distDir = path.resolve(__dirname, "..", "dist");
const indexPath = path.join(distDir, "index.html");
const fallbackPath = path.join(distDir, "404.html");

function createFallback() {
  if (!fs.existsSync(indexPath)) {
    console.error(`[ERROR] dist/index.html not found at: ${indexPath}`);
    console.error("[ERROR] Ensure 'npm run build' has completed before generating 404.html.");
    process.exit(1);
  }

  try {
    fs.copyFileSync(indexPath, fallbackPath);
    console.log("[SUCCESS] Generated dist/404.html for GitHub Pages SPA fallback.");
  } catch (err) {
    console.error(`[ERROR] Failed to copy dist/index.html to dist/404.html: ${err.message}`);
    process.exit(1);
  }
}

createFallback();
