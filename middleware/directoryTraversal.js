import path from "path";
import { fileURLToPath } from "url";
import he from "he";
import { isBanned, trackIp } from "../firewall/ipTracker.js";
import { logSuspiciousActivity } from "../utils/logger.js";

const { decode } = he;

function deepDecode(value) {
  try {
    let decoded = value;
    // Limit decoding to avoid unnecessary processing
    for (let i = 0; i < 3; i++) {
      const newDecoded = decode(decodeURIComponent(decoded));
      if (newDecoded === decoded) break;
      decoded = newDecoded;
    }
    return decoded;
  } catch {
    return value;
  }
}

export default function directoryTraversalProtection(options = {}) {
  const baseDir = options.baseDir || process.cwd();

  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (isBanned(ip)) {
      return res
        .status(403)
        .json({ error: "Your IP has been temporarily banned." });
    }

    // Only check the filePath or query.filePath
    const input = req.body?.filePath || req.query?.filePath;
    if (!input || input === req.path) {
      return next(); // Skip if there's no filePath or if it's the same as the request path
    }

    const decoded = deepDecode(input);
    const normalized = path.normalize(decoded);
    const resolvedPath = path.resolve(baseDir, normalized);

    // Only block if the resolved path escapes the baseDir
    if (!resolvedPath.startsWith(baseDir)) {
      logSuspiciousActivity("Directory Traversal", ip, req.originalUrl, {
        attemptedPath: resolvedPath,
        originalInput: input,
      });
      const banned = trackIp(ip);
      if (banned) {
        return res.status(403).json({
          error:
            "Your IP has been temporarily banned due to repeated suspicious activity.",
        });
      }
      return res
        .status(400)
        .json({ error: "Directory traversal attempt detected." });
    }

    next();
  };
}
