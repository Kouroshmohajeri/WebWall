# 🛡️ WebWall – Express.js Security Middleware

**WebWall** is a plug-and-play security middleware for Express.js that protects your backend from a wide range of common web attacks—without the bloat. It’s modular, fast, and designed for production.

> ✅ Actively blocks attacks, tracks IPs, and auto-bans repeat offenders.

---

## 🔐 What It Protects Against

- Brute Force Attacks  
- Credential Stuffing  
- Rate Limiting & DDoS Floods  
- NoSQL Injection  
- Cross-site Scripting (XSS)  
- Command Injection  
- Open Redirects  
- Directory Traversal  
- Exposed/Dotfile Access  
- File Upload Abuse   

---

## 🚀 Getting Started

### 1. Install

```bash
npm i @webgallery/webwall

```
### 2. Implementation
```bash
app.use(webwall());
```
or
```bash
app.use(
  webwall({
    xss: true,
    nosqlInjection: true,
    ban: true,
    bruteForce: true,
    credentialStuffing: true,
    rateLimit: {
      windowMs: 10000, // 10 seconds
      maxRequests: 30, // Only 3 requests allowed in that time
    },
    openRedirect: true,
    commandInjection: true,
    jwt: false,
    // jwtSecret: "your-very-strong-secret",
    ddos: {
      windowMs: 10000, // 10 seconds
      max: 5, // only allow 5 requests per IP in 10s
    },
    directoryTraversal: true,
    exposedFiles: true,
    openPort: {
      blockedPorts: [22, 3306],
      paths: ["/admin", "/shell", "/.git"],
    },
  })
);

```
### 3. Uploading files
```bash
app.post("/upload", (req, res, next) => {
  upload.single("file")(req, res, function (err) {
    if (err instanceof Error) {
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded." });
    }

    res.json({
      filename: req.file.originalname,
      size: req.file.size,
      message: "File uploaded successfully",
    });
  });
});

```