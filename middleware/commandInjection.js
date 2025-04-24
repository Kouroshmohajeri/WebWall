import { isBanned, trackIp } from "../firewall/ipTracker.js";
import { logSuspiciousActivity } from "../utils/logger.js";

// Very basic detection for common command injection patterns
const suspiciousPatterns = [
  /[`|&;]/, // Shell operators
  /\$\([^)]+\)/, // Subshell execution
  /`[^`]+`/, // Backtick execution
  /\b(cat|ls|rm|touch|mkdir)\b/i, // Common shell commands
  /\b(wget|curl)\b/i, // Download tools
  /\b(eval|exec|spawn|Function)\b/i, // Dangerous functions
  /\bshutdown\b/i, // System commands
  />\s*\/dev\/null/, // Output redirection
  /\\x[0-9a-fA-F]{2}/, // Hex escape sequences
  /\\u[0-9a-fA-F]{4}/, // Unicode escape sequences
  /\b(base64\s+-d|base64\s+--decode)\b/, // Base64 decoding
  /echo\s+[A-Za-z0-9+\/=]{8,}\s*\|\s*base64\s+-d\s*\|/, // Base64 exec chain
];

function looksLikeCommandInjection(input) {
  if (typeof input !== "string") return false;

  return suspiciousPatterns.some((regex) => regex.test(input));
}

function deepScan(obj) {
  if (typeof obj === "string") return looksLikeCommandInjection(obj);
  if (Array.isArray(obj)) return obj.some(deepScan);
  if (typeof obj === "object" && obj !== null) {
    return Object.values(obj).some(deepScan);
  }
  return false;
}

export default function commandInjection(options = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (isBanned(ip)) {
      return res
        .status(403)
        .json({ error: "Your IP has been temporarily banned." });
    }

    // Only check request body for risky HTTP methods
    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      if (deepScan(req.body)) {
        logSuspiciousActivity(
          "Command Injection",
          ip,
          req.originalUrl,
          req.body
        );
        const banned = trackIp(ip);
        return res.status(403).json({
          error: banned
            ? "Your IP has been temporarily banned due to repeated command injection attempts."
            : "Suspicious command detected. This action is blocked.",
        });
      }
    }

    next();
  };
}
