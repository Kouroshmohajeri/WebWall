import sanitizeHtml from "sanitize-html";
import he from "he";
const { decode } = he;

/**
 * Deep-decodes HTML entities and URI components multiple times to catch obfuscated payloads.
 * @param {string} str
 * @param {number} rounds
 * @returns {string}
 */
function deepMultiDecode(str, rounds = 5) {
  let decoded = str;
  for (let i = 0; i < rounds; i++) {
    try {
      decoded = decodeURIComponent(decoded);
    } catch {
      // skip invalid decodeURIComponent
    }
    decoded = he.decode(decoded);
  }
  return decoded;
}

/**
 * Recursively sanitizes a value or object
 * @param {*} input
 * @param {{ preserveText?: boolean }} options
 * @returns sanitized version
 */
export function sanitizeInput(input, { preserveText = false } = {}) {
  if (typeof input === "string") {
    const decoded = deepMultiDecode(input);

    const clean = sanitizeHtml(decoded, {
      allowedTags: [],
      allowedAttributes: {},
      textFilter: preserveText ? (text) => text : undefined,
    });

    // Extra heuristic detection
    const dangerousPattern =
      /<.*script.*>|javascript:|onerror=|onload=|<iframe|document\.cookie|alert\(/i;
    if (dangerousPattern.test(decoded)) {
      return "[XSS Blocked]";
    }

    return clean;
  }

  if (Array.isArray(input)) {
    return input.map((item) => sanitizeInput(item, { preserveText }));
  }

  if (input !== null && typeof input === "object") {
    const sanitized = {};
    for (const key in input) {
      sanitized[key] = sanitizeInput(input[key], { preserveText });
    }
    return sanitized;
  }

  return input;
}
