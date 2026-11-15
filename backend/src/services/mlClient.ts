import { config } from "../config";
import { sha256Hex } from "../utils/hash";
import { AppError } from "../utils/errors";

// Agreed response format between Member 1 (FastAPI) and Member 2 (this backend)
export interface TopFeature {
  name: string;
  description: string;
  contribution: number;
}

export interface MlResult {
  verdict: "benign" | "malicious";
  probability: number; // 0..1  (probability that file is malicious)
  riskScore: number; // 0..100
  topFeatures: TopFeature[];
  modelVersion: string;
}

// ---------- MOCK (used until Member 1's service is ready) ----------
function mockAnalyze(buffer: Buffer): MlResult {
  const hash = sha256Hex(buffer);
  const riskScore = parseInt(hash.slice(0, 4), 16) % 101; // deterministic 0..100
  return {
    verdict: riskScore > 50 ? "malicious" : "benign",
    probability: riskScore / 100,
    riskScore,
    modelVersion: "mock-v0",
    topFeatures: [
      { name: "section_entropy_text", description: "Entropy of the executable code section", contribution: 0.31 },
      { name: "imports_suspicious_api", description: "Use of suspicious imported APIs", contribution: 0.22 },
      { name: "header_timestamp", description: "Unusual compile timestamp in the PE header", contribution: 0.14 },
      { name: "byte_histogram_zeros", description: "Unusual share of zero bytes in the file", contribution: 0.09 },
      { name: "file_size", description: "File size compared with typical programs", contribution: 0.05 },
    ],
  };
}

// ---------- REAL (Member 1's FastAPI: POST /internal/analyze) ----------
async function realAnalyze(buffer: Buffer, filename: string): Promise<MlResult> {
  const form = new FormData();
  form.append("file", new Blob([new Uint8Array(buffer)]), filename);

  let response: Response;
  try {
    response = await fetch(`${config.mlServiceUrl}/internal/analyze`, {
      method: "POST",
      body: form,
      signal: AbortSignal.timeout(config.mlTimeoutMs),
    });
  } catch {
    // service down or timeout
    throw new AppError(503, "Analysis service temporarily unavailable, please retry");
  }

  if (!response.ok) {
    throw new AppError(503, "Analysis service temporarily unavailable, please retry");
  }

  const data: any = await response.json();
  if (
    (data.verdict !== "benign" && data.verdict !== "malicious") ||
    typeof data.risk_score !== "number"
  ) {
    throw new AppError(503, "Analysis service returned an invalid response");
  }

  return {
    verdict: data.verdict,
    probability: Number(data.probability ?? data.risk_score / 100),
    riskScore: Math.max(0, Math.min(100, Math.round(data.risk_score))),
    topFeatures: Array.isArray(data.top_features) ? data.top_features : [],
    modelVersion: String(data.model_version ?? "rf-ember2018"),
  };
}

export async function analyzeFile(buffer: Buffer, filename: string): Promise<MlResult> {
  if (config.mlMode === "mock") return mockAnalyze(buffer);
  return realAnalyze(buffer, filename);
}
