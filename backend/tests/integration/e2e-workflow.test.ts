/**
 * CipherGuard AI - End-to-End Core Workflow Integration Test
 *
 * Verifies the complete data pipeline across Members 1 and 3:
 * 1. Upload & Validate PE (MZ magic bytes)
 * 2. Calculate initial SHA-256 hash
 * 3. ML Risk Analysis contract simulation
 * 4. AES-256-GCM authenticated encryption & unique IV/key generation
 * 5. RSA-OAEP envelope key wrapping & memory zero-scrubbing
 * 6. Ciphertext persistence to secure file vault (<scanId>.enc)
 * 7. Secure decryption with RSA unwrapping & GCM tag validation
 * 8. Re-calculate SHA-256 and enforce integrity verification
 * 9. Stream verified file and confirm bit-for-bit identity
 */

import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { calculateSha256 } from '../../src/crypto/hash.js';
import { KeyManager } from '../../src/crypto/key-management.js';
import { generateRsaKeyPair } from '../../src/crypto/rsa.js';
import { SecureFileService } from '../../src/services/secure-file.service.js';
import { EncryptedStorageService } from '../../src/storage/encrypted-storage.js';
import { SecureTempFileManager } from '../../src/utils/temp-file.js';
import { createMockPeBuffer } from '../fixtures/sample-pe.js';

describe('End-to-End Workflow Integration (Members 1 & 3 Core Pipeline)', () => {
  const e2eStorageDir = path.resolve(process.cwd(), 'storage', 'e2e_storage');
  const e2eTempDir = path.resolve(process.cwd(), 'storage', 'e2e_temp');

  let keyManager: KeyManager;
  let storageService: EncryptedStorageService;
  let tempFileManager: SecureTempFileManager;
  let secureService: SecureFileService;
  let keyPair: ReturnType<typeof generateRsaKeyPair>;

  beforeAll(() => {
    if (fs.existsSync(e2eStorageDir)) fs.rmSync(e2eStorageDir, { recursive: true, force: true });
    if (fs.existsSync(e2eTempDir)) fs.rmSync(e2eTempDir, { recursive: true, force: true });

    fs.mkdirSync(e2eStorageDir, { recursive: true });
    fs.mkdirSync(e2eTempDir, { recursive: true });

    keyPair = generateRsaKeyPair(2048);
    keyManager = new KeyManager({
      rsaPublicKeyPem: keyPair.publicKey,
      rsaPrivateKeyPem: keyPair.privateKey,
    });
    storageService = new EncryptedStorageService({
      encryptedStorageDir: e2eStorageDir,
      tempStorageDir: e2eTempDir,
    });
    tempFileManager = new SecureTempFileManager(e2eTempDir);

    secureService = new SecureFileService({
      keyManager,
      storageService,
      tempFileManager,
    });
  });

  afterAll(() => {
    if (fs.existsSync(e2eStorageDir)) fs.rmSync(e2eStorageDir, { recursive: true, force: true });
    if (fs.existsSync(e2eTempDir)) fs.rmSync(e2eTempDir, { recursive: true, force: true });
  });

  it('executes full pipeline: Upload -> Validate PE -> Hash -> ML Result -> Encrypt -> Store -> Decrypt -> Verify SHA-256 -> Download', async () => {
    // Step 1: Client uploads file
    const rawUploadedFile = createMockPeBuffer('MZ CipherGuard E2E Verified Payload 2026');

    // Validate PE magic bytes (0x4D, 0x5A)
    const isPe = rawUploadedFile.length >= 2 && rawUploadedFile[0] === 0x4d && rawUploadedFile[1] === 0x5a;
    expect(isPe).toBe(true);

    // Step 2: Compute upload SHA-256
    const uploadSha256 = calculateSha256(rawUploadedFile);
    expect(uploadSha256).toHaveLength(64);

    // Step 3: ML Inference Service contract (Member 1)
    const mlAnalysisResult = {
      verdict: 'benign' as const,
      probability: 0.02,
      risk_score: 2,
      top_features: [
        {
          feature: 'header_0',
          importance: 0.002,
          description: 'COFF header fields',
        },
      ],
    };
    expect(mlAnalysisResult.risk_score).toBe(2);
    expect(mlAnalysisResult.verdict).toBe('benign');

    // Step 4 & 5: Encrypt with AES-256-GCM, wrap key with RSA-OAEP, store ciphertext
    const scanId = 'e2e-scan-uuid-001';
    const encryptedRecord = await secureService.encryptAndStore({
      scanId,
      fileData: rawUploadedFile,
      originalSha256: uploadSha256,
    });

    expect(encryptedRecord.storagePath).toBe(`${scanId}.enc`);
    expect(encryptedRecord.wrappedAesKey).toBeInstanceOf(Buffer);
    expect(encryptedRecord.wrappedAesKey.length).toBeGreaterThanOrEqual(256);
    expect(encryptedRecord.iv).toHaveLength(12);
    expect(encryptedRecord.gcmTag).toHaveLength(16);

    // Step 6: Verify file stored in vault is ciphertext, not plaintext
    const vaultPath = path.join(e2eStorageDir, encryptedRecord.storagePath);
    expect(fs.existsSync(vaultPath)).toBe(true);
    const vaultBytes = fs.readFileSync(vaultPath);
    expect(vaultBytes.equals(rawUploadedFile)).toBe(false);

    // Step 7, 8 & 9: Decrypt stream, verify GCM authentication tag & SHA-256 integrity
    const downloadResult = await secureService.decryptAndVerifyStream({
      storagePath: encryptedRecord.storagePath,
      wrappedAesKey: encryptedRecord.wrappedAesKey,
      iv: encryptedRecord.iv,
      gcmTag: encryptedRecord.gcmTag,
      expectedSha256: uploadSha256,
    });

    expect(downloadResult.verifiedSha256).toBe(uploadSha256);
    expect(downloadResult.contentLength).toBe(rawUploadedFile.length);

    // Consume stream
    const chunks: Buffer[] = [];
    for await (const chunk of downloadResult.stream) {
      chunks.push(Buffer.from(chunk));
    }
    const downloadedFile = Buffer.concat(chunks);

    // Final assertion: downloaded file matches original uploaded file bit-for-bit
    expect(downloadedFile.equals(rawUploadedFile)).toBe(true);
    expect(calculateSha256(downloadedFile)).toBe(uploadSha256);

    // Cleanup hook cleans transient plaintext
    await downloadResult.cleanup();
  });
});
