import multer from "multer";
import { config } from "../config";

// Keeps the uploaded file in memory (max 50MB) - nothing touches the disk
// until it has passed validation. Form field name must be "file".
export const upload = multer({
  storage: multer.memoryStorage(),
  preservePath: true,
  limits: { fileSize: config.maxFileSizeBytes, files: 1 },
});
