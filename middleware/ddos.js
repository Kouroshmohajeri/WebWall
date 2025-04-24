import rateLimit from "express-rate-limit";

const ddosProtection = (options = {}) => {
  const {
    windowMs = 60 * 1000, // 1 minute
    max = 100, // 100 requests per minute per IP
    message = "Too many requests. Please try again later.",
  } = options;

  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message },
    skipSuccessfulRequests: false,
  });
};

export default ddosProtection;
