import dotenv from "dotenv";
import path from "path";

dotenv.config();

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name} (check your .env file)`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT || 4000),
  nodeEnv: process.env.NODE_ENV || "development",
  jwtAccessSecret: required("JWT_ACCESS_SECRET"),
  jwtRefreshSecret: required("JWT_REFRESH_SECRET"),
  accessTokenTtl: "15m",
  refreshTokenTtlMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  frontendOrigin: process.env.FRONTEND_ORIGIN || "http://localhost:5173",
  mlMode: (process.env.ML_MODE || "mock") as "mock" | "real",
  mlServiceUrl: process.env.ML_SERVICE_URL || "http://localhost:8000",
  mlTimeoutMs: 10_000,
  storageDir: path.resolve(process.env.STORAGE_DIR || "./storage"),
  maxFileSizeBytes: 50 * 1024 * 1024, // 50 MB
  riskLowMax: Number(process.env.RISK_LOW_MAX || 30),
  riskMediumMax: Number(process.env.RISK_MEDIUM_MAX || 70),
};

// BR-3: thresholds live on the server, not in the frontend
export function riskLevel(score: number): "Low" | "Medium" | "High" {
  if (score <= config.riskLowMax) return "Low";
  if (score <= config.riskMediumMax) return "Medium";
  return "High";
}
