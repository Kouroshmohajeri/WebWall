import multer from "multer";
import path from "path";

// Allowed extensions and MIME types
const allowedExtensions = [".jpg", ".jpeg", ".png", ".gif", ".pdf"];
const allowedMimeTypes = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "application/pdf",
];

// 10 MB max size (change as needed)
const MAX_FILE_SIZE = 10 * 1024 * 1024;

const storage = multer.memoryStorage(); // or use diskStorage if needed

const fileFilter = (req, file, cb) => {
  const original = file.originalname.toLowerCase();

  const ext = path.extname(original);
  const baseName = path.basename(original, ext); // Remove only the final extension
  const secondExt = path.extname(baseName); // Check for hidden extension like `.php` in `.php.jpg`

  const isAllowedExt = allowedExtensions.includes(ext);
  const isAllowedMime = allowedMimeTypes.includes(file.mimetype);

  const hasDangerousDoubleExt = secondExt.match(
    /\.(php|exe|sh|bat|js|jsp|asp|aspx)$/
  );

  if (!isAllowedExt || !isAllowedMime || hasDangerousDoubleExt) {
    return cb(new Error("Invalid or potentially dangerous file type."));
  }

  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE },
});

export default upload;
