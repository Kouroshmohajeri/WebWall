import { isBanned, trackIp } from "../firewall/ipTracker.js";
import { logSuspiciousActivity } from "../utils/logger.js";

const failedAttempts = new Map();
const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MAX_FAILED_ATTEMPTS = 5;

function cleanOldAttempts(ip) {
  const now = Date.now();
  const attempts = failedAttempts.get(ip) || [];
  return attempts.filter((t) => now - t < WINDOW_MS);
}

export default function bruteForceProtection() {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;

    if (isBanned(ip)) {
      return res
        .status(403)
        .json({ error: "Your IP is temporarily banned due to brute force." });
    }

    // Automatically check on every request (like XSS middleware)
    const recentAttempts = cleanOldAttempts(ip);
    if (recentAttempts.length >= MAX_FAILED_ATTEMPTS) {
      logSuspiciousActivity("Brute Force Detected", ip, req.originalUrl, {});
      const banned = trackIp(ip);
      if (banned) {
        console.warn(`🚫 ${ip} banned for brute-force attacks.`);
        return res.status(403).json({
          error:
            "Your IP has been temporarily banned for repeated failed attempts.",
        });
      }
    }

    req.registerLoginFailure = () => {
      const recent = cleanOldAttempts(ip);
      recent.push(Date.now());
      failedAttempts.set(ip, recent);

      if (recent.length >= MAX_FAILED_ATTEMPTS) {
        console.log(`[BruteForce] BANNING ${ip}`); // Debug log
        logSuspiciousActivity("Brute Force Detected", ip, req.originalUrl, {});
        const banned = trackIp(ip);
        if (banned) {
          console.warn(`🚫 ${ip} banned for brute-force attacks.`);
        }
      }
    };
    next();
  };
}
