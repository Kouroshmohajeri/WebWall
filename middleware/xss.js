import { isBanned, trackIp } from "../firewall/ipTracker.js";
import { logSuspiciousActivity } from "../utils/logger.js";
import { sanitizeInput } from "../utils/sanitizer.js";

export default function xssMiddleware(options = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (isBanned(ip)) {
      return res
        .status(403)
        .json({ error: "Your IP has been temporarily banned." });
    }

    try {
      const sanitized = sanitizeInput(req.body, options);

      // Check if sanitization removed anything suspicious (simple heuristic)
      if (JSON.stringify(req.body) !== JSON.stringify(sanitized)) {
        logSuspiciousActivity("XSS", ip, req.originalUrl, req.body);
        const banned = trackIp(ip);
        if (banned) {
          return res
            .status(403)
            .json({
              error:
                "Your IP has been temporarily banned due to repeated suspicious input.",
            });
        }
      }

      req.body = sanitized;
    } catch (err) {
      // Fail-safe fallback
      return res.status(400).json({ error: "Invalid input" });
    }

    next();
  };
}
