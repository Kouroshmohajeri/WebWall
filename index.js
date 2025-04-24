import helmet from "helmet";
import xss from "./middleware/xss.js";
import nosqlInjection from "./middleware/nosqlinjection.js";
import banMiddleware from "./middleware/ban.js";
import rateLimiter from "./middleware/ratelimiter.js";
import commandInjection from "./middleware/commandInjection.js";
import openRedirectProtection from "./middleware/openRedirectProtection.js";
import bruteForceProtection from "./middleware/bruteForce.js";
import credentialStuffingProtection from "./middleware/credentialStuffing.js";
import jwtValidation from "./middleware/jwtValidation.js";
import otpAbuseProtection from "./middleware/otpAbuse.js";
import ddosProtection from "./middleware/ddos.js";
import directoryTraversalProtection from "./middleware/directoryTraversal.js";
import exposedFileProtection from "./middleware/exposedFiles.js";
import openPortProtection from "./middleware/openPort.js";
// import { csrfMiddleware } from "./middleware/csrf.js";
// import { verifyCsrf } from "./middleware/verifyCsrf.js";

export default function webwall(options = {}) {
  const middlewares = [];

  middlewares.push(helmet());

  // Ban Suspicious IDs
  if (options.ban !== false) {
    middlewares.unshift(banMiddleware());
  }
  // Brute Force Protection (Add this block)
  if (options.bruteForce !== false) {
    middlewares.push(bruteForceProtection());
  }
  // Credential Stuffing Protection
  if (options.credentialStuffing !== false) {
    middlewares.push(credentialStuffingProtection());
  }
  // Inside the webwall function
  if (options.directoryTraversal !== false) {
    const traversalOptions =
      typeof options.directoryTraversal === "object"
        ? options.directoryTraversal
        : {};
    middlewares.push(directoryTraversalProtection(traversalOptions));
  }
  // XSS Protection
  if (options.xss !== false) {
    const xssOptions = typeof options.xss === "object" ? options.xss : {};
    middlewares.push(xss(xssOptions));
  }
  // inside the webwall(options = {}) function
  if (options.exposedFiles !== false) {
    middlewares.push(exposedFileProtection());
  }
  if (options.openPort !== false) {
    const portOptions =
      typeof options.openPort === "object" ? options.openPort : {};
    middlewares.unshift(openPortProtection(portOptions));
  }
  // if (options.otpAbuse !== false) {
  //   middlewares.push(otpAbuseProtection());
  // }
  if (options.ddos !== false) {
    middlewares.unshift(ddosProtection(options.ddos));
  }
  // NoSQL Injection Protection
  if (options.nosqlInjection !== false) {
    middlewares.push(nosqlInjection());
  }

  //Limiting User Requests
  if (options.rateLimit !== false) {
    middlewares.push(rateLimiter(options.rateLimit));
  }

  if (options.jwt !== false && options.jwtSecret) {
    const jwtOptions = typeof options.jwt === "object" ? options.jwt : {};
    jwtOptions.secret = options.jwtSecret;
    middlewares.push(jwtValidation(jwtOptions));
  }
  // CSRF Protection
  // if (options.csrfProtection !== false) {
  //   middlewares.push(csrfMiddleware); // Generate token
  //   middlewares.push(verifyCsrf); // Verify token on sensitive requests
  // }

  // Open Redirect Protection
  if (options.openRedirect !== false) {
    middlewares.push(openRedirectProtection());
  }
  // Command Injection Protection
  if (options.commandInjection !== false) {
    middlewares.push(commandInjection());
  }

  return middlewares;
}
