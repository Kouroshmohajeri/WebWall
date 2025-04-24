const ipHits = new Map();

export default function rateLimiter({
  windowMs = 10000,
  maxRequests = 3,
} = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();

    if (!ipHits.has(ip)) {
      ipHits.set(ip, []);
    }

    const timestamps = ipHits.get(ip).filter((ts) => now - ts < windowMs);

    if (timestamps.length >= maxRequests) {
      return res.status(429).json({
        error: "Too many requests, please try again later.",
      });
    }

    timestamps.push(now);
    ipHits.set(ip, timestamps);
    next();
  };
}
