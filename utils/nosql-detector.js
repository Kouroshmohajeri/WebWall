/**
 * Recursively checks input for NoSQL injection patterns
 * @param {*} input
 * @returns {boolean} true if safe
 */
export function isInjectionSafe(input) {
  const blacklist = [
    "$ne",
    "$gt",
    "$lt",
    "$in",
    "$regex",
    "$where",
    "$exists",
    "$expr",
  ];

  if (typeof input === "string") {
    // Check for blacklisted patterns even inside value strings
    return !blacklist.some((keyword) => input.toLowerCase().includes(keyword));
  }

  if (Array.isArray(input)) {
    return input.every(isInjectionSafe);
  }

  if (input !== null && typeof input === "object") {
    for (const key in input) {
      if (blacklist.some((k) => key.toLowerCase().includes(k))) {
        return false;
      }
      if (!isInjectionSafe(input[key])) {
        return false;
      }
    }
  }

  return true;
}
