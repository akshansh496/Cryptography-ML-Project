import { Router, Response } from "express";
import crypto from "crypto";
import { z } from "zod";
import { prisma } from "../db";
import { riskLevel } from "../config";
import { AppError } from "../utils/errors";
import { sha256Hex } from "../utils/hash";
import { validateFilename, isValidPE, uuidSchema } from "../utils/validators";
import { requireAuth, AuthRequest } from "../middleware/auth";
import { asyncHandler } from "../middleware/errorHandler";
import { upload } from "../middleware/upload";
import { analyzeFile } from "../services/mlClient";
import { storeFile, loadFile, deleteFile } from "../services/storage";

const router = Router();
router.use(requireAuth); // every scan route needs login

// Shape sent to the frontend (agreed with Member 4). Storage path is never exposed (FR-8.3).
function formatScan(scan: any, extra: Record<string, unknown> = {}) {
  return {
    id: scan.id,
    filename: scan.originalFilename,
    fileSize: scan.fileSize,
    sha256: scan.sha256Hash,
    verdict: scan.verdict,
    probability: scan.probability,
    riskScore: scan.riskScore,
    riskLevel: riskLevel(scan.riskScore),
    explanation: scan.explanation,
    modelVersion: scan.modelVersion,
    createdAt: scan.createdAt,
    ...extra,
  };
}

// Loads a scan and enforces ownership: 404 if missing, 403 if it belongs to someone else
async function getOwnedScan(id: string, userId: string) {
  if (!uuidSchema.safeParse(id).success) throw new AppError(404, "Scan not found");
  const scan = await prisma.scan.findUnique({ where: { id }, include: { encryptedFile: true } });
  if (!scan) throw new AppError(404, "Scan not found");
  if (scan.userId !== userId) throw new AppError(403, "You do not have access to this scan");
  return scan;
}

// POST /api/scans  -> upload + validate + hash + analyze + store
router.post(
  "/",
  upload.single("file"),
  asyncHandler(async (req: AuthRequest & { file?: Express.Multer.File }, res: Response) => {
    const userId = req.user!.id;
    const file = req.file;
    if (!file) throw new AppError(400, "No file uploaded (form field name must be 'file')");

    // 1. Validate (BR-1: before anything else)
    const filename = validateFilename(file.originalname);
    if (file.size === 0) throw new AppError(400, "File is empty");
    if (!isValidPE(file.buffer)) throw new AppError(400, "File is not a valid PE executable");

    // 2. Hash + duplicate check (informational only, FR-3.3)
    const sha256 = sha256Hex(file.buffer);
    const duplicate = (await prisma.scan.count({ where: { userId, sha256Hash: sha256 } })) > 0;

    // 3. Analyze. If ML is down this throws 503 and NOTHING is saved (FR-4.6, BR-2)
    const ml = await analyzeFile(file.buffer, filename);

    // 4. Store file, then save DB records. Clean up the blob if DB fails.
    const scanId = crypto.randomUUID();
    const stored = await storeFile(scanId, file.buffer, sha256);

    try {
      const scan = await prisma.scan.create({
        data: {
          id: scanId,
          userId,
          originalFilename: filename,
          fileSize: file.size,
          sha256Hash: sha256,
          verdict: ml.verdict,
          probability: ml.probability,
          riskScore: ml.riskScore,
          explanation: ml.topFeatures as any,
          modelVersion: ml.modelVersion,
          encryptedFile: {
            create: {
              storagePath: stored.storagePath,
              wrappedAesKey: stored.wrappedAesKey,
              iv: stored.iv,
              gcmTag: stored.gcmTag,
            },
          },
        },
      });
      res.status(201).json(formatScan(scan, { duplicate }));
    } catch (err) {
      await deleteFile(stored.storagePath);
      throw err;
    }
  })
);

// GET /api/scans?page=1&limit=20&sortBy=createdAt|riskScore&order=desc|asc
const listQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sortBy: z.enum(["createdAt", "riskScore"]).default("createdAt"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

router.get(
  "/",
  asyncHandler(async (req: AuthRequest, res: Response) => {
    const { page, limit, sortBy, order } = listQuery.parse(req.query);
    const where = { userId: req.user!.id };

    const [total, scans] = await Promise.all([
      prisma.scan.count({ where }),
      prisma.scan.findMany({
        where,
        orderBy: { [sortBy]: order },
        skip: (page - 1) * limit,
        take: limit,
      }),
    ]);

    res.json({
      items: scans.map((s) => formatScan(s)),
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    });
  })
);

// GET /api/scans/:id
router.get(
  "/:id",
  asyncHandler(async (req: AuthRequest, res: Response) => {
    const scan = await getOwnedScan(req.params.id, req.user!.id);
    res.json(formatScan(scan));
  })
);

// GET /api/scans/:id/download  -> load, re-verify SHA-256, send
router.get(
  "/:id/download",
  asyncHandler(async (req: AuthRequest, res: Response) => {
    const scan = await getOwnedScan(req.params.id, req.user!.id);
    if (!scan.encryptedFile) throw new AppError(404, "Stored file not found");

    let plain: Buffer;
    try {
      plain = await loadFile(
        {
          storagePath: scan.encryptedFile.storagePath,
          wrappedAesKey: scan.encryptedFile.wrappedAesKey ?? undefined,
          iv: scan.encryptedFile.iv ?? undefined,
          gcmTag: scan.encryptedFile.gcmTag ?? undefined,
        },
        scan.sha256Hash
      );
    } catch (err) {
      console.error("SECURITY: could not load/decrypt file", { scanId: scan.id, userId: scan.userId });
      throw new AppError(409, "File integrity check failed");
    }

    // FR-9.1 / FR-9.2: hash must match what we stored at upload time
    if (sha256Hex(plain) !== scan.sha256Hash) {
      console.error("SECURITY ALERT: hash mismatch on download", { scanId: scan.id, userId: scan.userId });
      throw new AppError(409, "File integrity check failed");
    }

    console.log("AUDIT: download", { scanId: scan.id, userId: scan.userId, at: new Date().toISOString() });

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(scan.originalFilename)}"`);
    res.setHeader("Cache-Control", "no-store");
    res.send(plain);
  })
);

// DELETE /api/scans/:id  -> permanent delete (BR-5)
router.delete(
  "/:id",
  asyncHandler(async (req: AuthRequest, res: Response) => {
    const scan = await getOwnedScan(req.params.id, req.user!.id);
    if (scan.encryptedFile) await deleteFile(scan.encryptedFile.storagePath);
    await prisma.scan.delete({ where: { id: scan.id } }); // cascades to encrypted_files
    res.status(204).send();
  })
);

export default router;
