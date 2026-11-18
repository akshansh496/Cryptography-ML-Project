import { z } from "zod";
import { AppError } from "./errors";

// ---------- Auth input (FR-1.1) ----------
export const registerSchema = z.object({
  email: z.string().trim().toLowerCase().email("Enter a valid email address").max(254),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password needs at least 1 uppercase letter")
    .regex(/[0-9]/, "Password needs at least 1 number")
    .regex(/[^A-Za-z0-9]/, "Password needs at least 1 special character"),
});

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(1),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(10),
});

// ---------- File validation (FR-2) ----------

// FR-2.5: reject path traversal / null bytes, and allow only .exe/.dll
export function validateFilename(name: string): string {
  if (!name || name.includes("\0") || name.includes("..") || name.includes("/") || name.includes("\\")) {
    throw new AppError(400, "Invalid filename");
  }
  if (name.length > 255) {
    throw new AppError(400, "Filename is too long");
  }
  const lower = name.toLowerCase();
  if (!lower.endsWith(".exe") && !lower.endsWith(".dll")) {
    throw new AppError(400, "Only .exe and .dll files are allowed");
  }
  return name;
}

// FR-2.2: real PE check -> "MZ" at start, e_lfanew at offset 0x3C, "PE\0\0" at that offset
export function isValidPE(buf: Buffer): boolean {
  if (buf.length < 64) return false;
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return false; // "MZ"
  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 4 > buf.length) return false;
  return (
    buf[peOffset] === 0x50 && // P
    buf[peOffset + 1] === 0x45 && // E
    buf[peOffset + 2] === 0x00 &&
    buf[peOffset + 3] === 0x00
  );
}

export const uuidSchema = z.string().uuid();
