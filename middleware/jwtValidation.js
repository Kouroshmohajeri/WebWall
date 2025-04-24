import jwt from "jsonwebtoken";

const jwtValidation = (options = {}) => {
  const { secret, algorithms = ["HS256"] } = options;

  if (!secret) {
    throw new Error("JWT secret must be provided for validation.");
  }

  return (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Missing token" });
    }

    try {
      const payload = jwt.verify(token, secret, { algorithms });
      req.user = payload; // attach decoded payload to request
      next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
};

export default jwtValidation;
