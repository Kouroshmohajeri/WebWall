// middleware/exposedFileProtection.js

const forbiddenFiles = [
  ".env",
  ".git",
  ".gitignore",
  ".htaccess",
  "docker-compose.yml",
  "Dockerfile",
  "config.php",
  "package-lock.json",
  "yarn.lock",
];

const forbiddenPatterns = forbiddenFiles.map(
  (file) => new RegExp(`(?:^|/)${file}(?:$|/)?`, "i")
);

export default function exposedFileProtection() {
  return (req, res, next) => {
    try {
      const decodedPath = decodeURIComponent(req.path.toLowerCase());

      const isForbidden = forbiddenPatterns.some((pattern) =>
        pattern.test(decodedPath)
      );

      if (isForbidden) {
        return res.status(403).json({ error: "Access denied." });
      }

      next();
    } catch (err) {
      return res.status(400).json({ error: "Bad request." });
    }
  };
}
