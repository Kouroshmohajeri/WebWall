const ipAttempts = new Map();

const MAX_ATTEMPTS = 6;
const WINDOW_MS = 10 * 60 * 1000; // 10 minutes

export function trackIp(ip) {
  const now = Date.now();
  if (!ipAttempts.has(ip)) {
    ipAttempts.set(ip, []);
  }

  const attempts = ipAttempts.get(ip).filter((t) => now - t < WINDOW_MS);
  attempts.push(now);
  ipAttempts.set(ip, attempts);

  return attempts.length >= MAX_ATTEMPTS;
}

export function isBanned(ip) {
  const now = Date.now();
  const attempts = ipAttempts.get(ip) || [];
  const recent = attempts.filter((t) => now - t < WINDOW_MS);

  ipAttempts.set(ip, recent);
  return recent.length >= MAX_ATTEMPTS;
}
