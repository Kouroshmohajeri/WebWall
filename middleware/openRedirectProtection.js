import { isBanned, trackIp } from "../firewall/ipTracker.js";
import { logSuspiciousActivity } from "../utils/logger.js";

// Define safe internal domains or paths
const safeDomains = ["localhost", "127.0.0.1"]; // Adjust accordingly

function isSafeRedirect(url = "") {
  try {
    // Allow relative paths that start with `/` but not `//` (which means protocol-relative)
    if (/^\/(?!\/)/.test(url)) return true;

    // Check full URL (absolute) against whitelist
    const parsed = new URL(url);
    return safeDomains.some((domain) => parsed.hostname.endsWith(domain));
  } catch {
    return false;
  }
}

export default function openRedirectProtection(options = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (isBanned(ip)) {
      return res
        .status(403)
        .json({ error: "Your IP has been temporarily banned." });
    }

    const { url, redirect, returnTo, next: nextUrl } = req.query;

    const targets = [url, redirect, returnTo, nextUrl].filter(Boolean);

    const hasOpenRedirect = targets.some((target) => !isSafeRedirect(target));

    if (hasOpenRedirect) {
      logSuspiciousActivity("Open Redirect", ip, req.originalUrl, targets);
      const banned = trackIp(ip);

      return res.status(403).json({
        error: banned
          ? "Your IP has been temporarily banned due to repeated redirect abuse."
          : "Suspicious redirect target blocked.",
      });
    }

    next();
  };
}
