import jwt from "jsonwebtoken";
import crypto from "crypto";
import { config } from "../config";
import { prisma } from "../db";
import { sha256Hex } from "./hash";

export interface AccessPayload {
  sub: string; // user id
  role: string;
}

// Creates access (15 min) + refresh (7 days) tokens.
// Only a HASH of the refresh token is stored in the DB so it can be revoked (logout).
export async function issueTokens(user: { id: string; role: string }) {
  const accessToken = jwt.sign({ sub: user.id, role: user.role }, config.jwtAccessSecret, {
    expiresIn: config.accessTokenTtl,
  } as jwt.SignOptions);

  const refreshToken = jwt.sign(
    { sub: user.id, jti: crypto.randomUUID() },
    config.jwtRefreshSecret,
    { expiresIn: "7d" } as jwt.SignOptions
  );

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: sha256Hex(refreshToken),
      expiresAt: new Date(Date.now() + config.refreshTokenTtlMs),
    },
  });

  return { accessToken, refreshToken };
}
