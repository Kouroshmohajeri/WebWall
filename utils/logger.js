import fs from "fs";
import path from "path";

const logDir = path.resolve("logs");
const logPath = path.join(logDir, "webwall-ip-tracker.log");

// Ensure logs directory exists
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

export function logSuspiciousActivity(type, ip, route, payload) {
  const log = {
    timestamp: new Date().toISOString(),
    type,
    ip,
    route,
    payload,
  };

  fs.appendFileSync(logPath, JSON.stringify(log) + "\n");
}
