import { getSuspicion } from "../utils/ipStore.js";
import { logSuspiciousActivity } from "../utils/logger.js";

const BAN_THRESHOLD = 5;

export default function banMiddleware() {
  return (req, res, next) => {
    const ip = req.ip;

    if (getSuspicion(ip) >= BAN_THRESHOLD) {
      logSuspiciousActivity(
        "BAN",
        ip,
        req.originalUrl,
        "Too many suspicious requests"
      );
      return res.status(403).json({
        error:
          "You are temporarily banned due to repeated suspicious activity.",
      });
    }

    next();
  };
}
