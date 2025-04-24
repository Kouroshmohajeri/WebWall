import { isInjectionSafe } from "../utils/nosql-detector.js";
import he from "he";
const { decode } = he;

import { logSuspiciousActivity } from "../utils/logger.js";
import { isBanned, trackIp } from "../firewall/ipTracker.js";

export default function nosqlInjectionMiddleware() {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;

    if (isBanned(ip)) {
      return res
        .status(403)
        .json({ error: "Your IP has been temporarily banned." });
    }

    const sources = [req.body, req.query, req.params];

    for (const source of sources) {
      const decoded = deepDecode(source);
      if (!isInjectionSafe(decoded)) {
        logSuspiciousActivity("NoSQL", ip, req.originalUrl, source);

        const banned = trackIp(ip);
        if (banned) {
          return res
            .status(403)
            .json({
              error:
                "Your IP has been temporarily banned due to repeated suspicious input.",
            });
        }

        return res
          .status(400)
          .json({
            error: "Suspicious input detected (possible NoSQL injection).",
          });
      }
    }

    next();
  };
}

function deepDecode(value) {
  if (typeof value === "string") {
    try {
      const decoded = decode(decodeURIComponent(value));
      return JSON.parse(decoded);
    } catch {
      return decode(value); // fallback if not valid JSON
    }
  }

  if (Array.isArray(value)) {
    return value.map(deepDecode);
  }

  if (value !== null && typeof value === "object") {
    const decoded = {};
    for (const key in value) {
      const decodedKey = decode(decodeURIComponent(key));
      decoded[decodedKey] = deepDecode(value[key]);
    }
    return decoded;
  }

  return value;
}
