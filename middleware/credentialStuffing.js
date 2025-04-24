// webwall/middleware/credentialStuffing.js
import { trackIp, isBanned } from "../firewall/ipTracker.js";
import { logSuspiciousActivity } from "../utils/logger.js";

const failedUsernamesByIp = new Map();
const WINDOW_MS = 10 * 60 * 1000; // 10 min
const MAX_USERNAMES_PER_IP = 3;

function cleanOldAttempts(attempts) {
  const now = Date.now();
  return attempts.filter((entry) => now - entry.time < WINDOW_MS);
}

export default function credentialStuffingProtection() {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;

    if (isBanned(ip)) {
      return res.status(403).json({
        error:
          "Your IP has been temporarily banned for suspicious login behavior.",
      });
    }

    req.registerCredentialStuffingFailure = (username) => {
      const records = failedUsernamesByIp.get(ip) || [];
      const cleaned = cleanOldAttempts(records);
      cleaned.push({ username, time: Date.now() });

      failedUsernamesByIp.set(ip, cleaned);

      const uniqueUsernames = new Set(cleaned.map((r) => r.username));
      if (uniqueUsernames.size >= MAX_USERNAMES_PER_IP) {
        logSuspiciousActivity("Credential Stuffing", ip, req.originalUrl, {
          attemptedUsernames: Array.from(uniqueUsernames),
        });

        const banned = trackIp(ip);
        if (banned) {
          console.warn(`🚫 ${ip} temporarily banned for credential stuffing.`);
        }
      }
    };

    next();
  };
}
