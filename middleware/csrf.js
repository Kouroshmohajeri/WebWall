import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";

// Generate CSRF Token
function generateToken() {
  return uuidv4() + crypto.randomBytes(64).toString("hex");
}

export function csrfMiddleware(req, res, next) {
  // Store CSRF token in session or cookie (or custom store)
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateToken();
  }

  // Add token to response (for frontend to use)
  res.locals.csrfToken = req.session.csrfToken;

  next();
}
