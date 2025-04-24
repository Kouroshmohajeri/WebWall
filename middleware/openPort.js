export default function openPortProtection(options = {}) {
  const suspiciousPorts = options.blockedPorts || [
    21, 22, 23, 3306, 5432, 6379, 11211,
  ];
  const suspiciousPaths = options.paths || [
    "/phpmyadmin",
    "/shell",
    "/admin",
    "/webdav",
    "/.git",
    "/.env",
    "/config.php",
  ];

  return (req, res, next) => {
    const port = req.socket.localPort;

    // Warn if running on unsafe port in production
    if (
      process.env.NODE_ENV === "production" &&
      suspiciousPorts.includes(port)
    ) {
      console.warn(`⚠️ App running on suspicious port ${port}`);
    }

    // Block known sensitive endpoints often targeted
    const path = decodeURIComponent(req.path.toLowerCase());
    if (suspiciousPaths.includes(path)) {
      return res.status(403).json({ error: "Access denied." });
    }

    next();
  };
}
