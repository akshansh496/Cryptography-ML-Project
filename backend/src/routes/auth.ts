import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { prisma } from "../db";
import { config } from "../config";
import { AppError } from "../utils/errors";
import { asyncHandler } from "../middleware/errorHandler";
import { registerSchema, loginSchema, refreshSchema } from "../utils/validators";
import { issueTokens } from "../utils/tokens";
import { sha256Hex } from "../utils/hash";

const router = Router();

// SRS section 7: 5 failed login attempts per 15 min per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please try again later." },
});

// POST /api/auth/register
router.post(
  "/register",
  asyncHandler(async (req, res) => {
    const { email, password } = registerSchema.parse(req.body);

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) throw new AppError(409, "Account already exists");

    const passwordHash = await bcrypt.hash(password, 12); // cost >= 12 (FR-1.2)
    const user = await prisma.user.create({ data: { email, passwordHash } });

    res.status(201).json({ id: user.id, email: user.email });
  })
);

// POST /api/auth/login
router.post(
  "/login",
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    // same message for wrong email / wrong password (no user enumeration)
    const ok = user ? await bcrypt.compare(password, user.passwordHash) : false;
    if (!user || !ok) throw new AppError(401, "Invalid email or password");

    const tokens = await issueTokens(user);
    res.json({ ...tokens, user: { id: user.id, email: user.email, role: user.role } });
  })
);

// POST /api/auth/refresh  (rotation: old refresh token is deleted, new pair issued)
router.post(
  "/refresh",
  asyncHandler(async (req, res) => {
    const { refreshToken } = refreshSchema.parse(req.body);

    let payload: any;
    try {
      payload = jwt.verify(refreshToken, config.jwtRefreshSecret);
    } catch {
      throw new AppError(401, "Invalid or expired refresh token");
    }

    const stored = await prisma.refreshToken.findUnique({
      where: { tokenHash: sha256Hex(refreshToken) },
    });
    if (!stored || stored.expiresAt < new Date()) {
      throw new AppError(401, "Invalid or expired refresh token");
    }

    const user = await prisma.user.findUnique({ where: { id: payload.sub } });
    if (!user) throw new AppError(401, "Invalid or expired refresh token");

    await prisma.refreshToken.delete({ where: { id: stored.id } }); // rotation
    const tokens = await issueTokens(user);
    res.json(tokens);
  })
);

// POST /api/auth/logout  (revokes the refresh token)
router.post(
  "/logout",
  asyncHandler(async (req, res) => {
    const { refreshToken } = refreshSchema.parse(req.body);
    await prisma.refreshToken.deleteMany({ where: { tokenHash: sha256Hex(refreshToken) } });
    res.status(204).send();
  })
);

export default router;
