import { Request, Response, NextFunction } from "express";
import multer from "multer";
import { ZodError } from "zod";
import { AppError } from "../utils/errors";
import { config } from "../config";

// Wraps async route functions so errors reach the error handler
export const asyncHandler =
  (fn: (req: any, res: Response, next: NextFunction) => Promise<any>) =>
  (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next);
  };

export function notFound(_req: Request, res: Response) {
  res.status(404).json({ error: "Route not found" });
}

// Central error handler - never leaks stack traces to the client (SRS section 8)
export function errorHandler(err: any, _req: Request, res: Response, _next: NextFunction) {
  if (err instanceof AppError) {
    return res.status(err.status).json({ error: err.message });
  }

  if (err instanceof ZodError) {
    const fields = err.issues.map((i) => ({ field: i.path.join("."), message: i.message }));
    return res.status(400).json({ error: "Validation failed", fields });
  }

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      const mb = config.maxFileSizeBytes / (1024 * 1024);
      return res.status(413).json({ error: `File exceeds the ${mb}MB limit` });
    }
    return res.status(400).json({ error: "Invalid upload request" });
  }

  if (err?.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Malformed JSON body" });
  }

  console.error("Unexpected error:", err); // full details only in server logs
  return res.status(500).json({ error: "Something went wrong on the server" });
}
