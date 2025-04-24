import rateLimit from "express-rate-limit";

const otpAbuseProtection = () => {
  return rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 3, // limit each IP/phone to 3 OTPs per minute
    message: { error: "Too many OTP requests. Please wait and try again." },
    keyGenerator: (req) => {
      return req.body.phone || req.ip; // Prioritize phone for tracking abuse
    },
    skipSuccessfulRequests: false, // count all attempts
  });
};

export default otpAbuseProtection;
