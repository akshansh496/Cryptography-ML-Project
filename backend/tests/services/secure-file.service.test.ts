import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { calculateSha256 } from '../../src/crypto/hash.js';
import { KeyManager } from '../../src/crypto/key-management.js';
import { generateRsaKeyPair } from '../../src/crypto/rsa.js';
import { DecryptionError, IntegrityVerificationError } from '../../src/errors/crypto.errors.js';
import { SecureFileService } from '../../src/services/secure-file.service.js';
import { EncryptedStorageService } from '../../src/storage/encrypted-storage.js';
import { SecureTempFileManager } from '../../src/utils/temp-file.js';
import { createMockPeBuffer } from '../fixtures/sample-pe.js';

describe('SecureFileService Orchestration & Security Tests', () => {
  const testStorageDir = path.resolve(process.cwd(), 'storage', 'test_svc_encrypted');
  const testTempDir = path.resolve(process.cwd(), 'storage', 'test_svc_temp');

  let keyManager: KeyManager;
  let storageService: EncryptedStorageService;
  let tempFileManager: SecureTempFileManager;
  let secureService: SecureFileService;
  let testKeyPair: ReturnType<typeof generateRsaKeyPair>;

  beforeEach(() => {
    if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });
    if (fs.existsSync(testTempDir)) fs.rmSync(testTempDir, { recursive: true, force: true });

    fs.mkdirSync(testStorageDir, { recursive: true });
    fs.mkdirSync(testTempDir, { recursive: true });

    testKeyPair = generateRsaKeyPair(2048);
    keyManager = new KeyManager({
      rsaPublicKeyPem: testKeyPair.publicKey,
      rsaPrivateKeyPem: testKeyPair.privateKey,
    });
    storageService = new EncryptedStorageService({
      encryptedStorageDir: testStorageDir,
      tempStorageDir: testTempDir,
    });
    tempFileManager = new SecureTempFileManager(testTempDir);

    secureService = new SecureFileService({
      keyManager,
      storageService,
      tempFileManager,
    });
  });

  afterEach(() => {
    if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });
    if (fs.existsSync(testTempDir)) fs.rmSync(testTempDir, { recursive: true, force: true });
  });

  // TEST 13: Verify RSA private key is not stored in the database / returned metadata record.
  it('TEST 13: Verify RSA private key is not stored in the database record', async () => {
    const samplePe = createMockPeBuffer('PE for DB check');
    const sha256 = calculateSha256(samplePe);
    const scanId = 'scan-db-check-13';

    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256: sha256,
    });

    // Inspect the returned record (which is what gets persisted in Prisma EncryptedFile table)
    expect(record).toBeDefined();
    expect(record.scanId).toBe(scanId);
    expect(record.storagePath).toBe(`${scanId}.enc`);
    expect(record.wrappedAesKey).toBeInstanceOf(Buffer);
    expect(record.iv).toBeInstanceOf(Buffer);
    expect(record.gcmTag).toBeInstanceOf(Buffer);

    // Verify record has NO private key field
    expect((record as Record<string, unknown>).privateKey).toBeUndefined();
    expect((record as Record<string, unknown>).rsaPrivateKey).toBeUndefined();

    // Verify none of the buffer values contain the RSA private key
    const privateKeyBuffer = Buffer.from(testKeyPair.privateKey);
    expect(record.wrappedAesKey.includes(privateKeyBuffer)).toBe(false);
    expect(record.iv.includes(privateKeyBuffer)).toBe(false);
    expect(record.gcmTag.includes(privateKeyBuffer)).toBe(false);

    // Verify JSON serialization of record does not leak private key
    const serialized = JSON.stringify(record);
    expect(serialized.includes('PRIVATE KEY')).toBe(false);
  });

  // TEST 14: Verify temporary plaintext files are removed after successful processing.
  it('TEST 14: Verify temporary plaintext files are removed after successful processing', async () => {
    const samplePe = createMockPeBuffer('PE for Temp Cleanup Test');
    const sha256 = calculateSha256(samplePe);
    const scanId = 'scan-temp-success-14';

    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256: sha256,
    });

    // Decrypt and stream with automatic cleanup
    const streamResult = await secureService.decryptAndVerifyStream({
      storagePath: record.storagePath,
      wrappedAesKey: record.wrappedAesKey,
      iv: record.iv,
      gcmTag: record.gcmTag,
      expectedSha256: sha256,
    });

    expect(streamResult.verifiedSha256).toBe(sha256);

    // Consume stream
    const chunks: Buffer[] = [];
    for await (const chunk of streamResult.stream) {
      chunks.push(chunk as Buffer);
    }
    const streamedData = Buffer.concat(chunks);
    expect(streamedData.equals(samplePe)).toBe(true);

    // Execute cleanup
    await streamResult.cleanup();
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Verify temp directory contains NO leftover files
    const tempFiles = fs.readdirSync(testTempDir).filter((f) => f !== '.gitkeep');
    expect(tempFiles).toHaveLength(0);
  });

  // TEST 15: Verify temporary plaintext files are removed after an exception/failure.
  it('TEST 15: Verify temporary plaintext files are removed after an exception/failure', async () => {
    let capturedTempPath = '';

    // withSecureTempFile guarantees cleanup even if callback throws
    await expect(
      tempFileManager.withSecureTempFile(
        { prefix: 'fail_test_', ext: '.tmp', initialData: Buffer.from('sensitive data') },
        async (tempPath) => {
          capturedTempPath = tempPath;
          expect(fs.existsSync(tempPath)).toBe(true);
          throw new Error('Simulated pipeline error');
        }
      )
    ).rejects.toThrow('Simulated pipeline error');

    // Verify temporary file was deleted despite the thrown exception
    expect(capturedTempPath).not.toBe('');
    expect(fs.existsSync(capturedTempPath)).toBe(false);

    const tempFiles = fs.readdirSync(testTempDir).filter((f) => f !== '.gitkeep');
    expect(tempFiles).toHaveLength(0);
  });

  it('performs end-to-end encryption and verified decryption', async () => {
    const samplePe = createMockPeBuffer('Full end to end test binary');
    const sha256 = calculateSha256(samplePe);
    const scanId = 'scan-e2e-01';

    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256: sha256,
    });

    const decrypted = await secureService.decryptAndVerify({
      storagePath: record.storagePath,
      wrappedAesKey: record.wrappedAesKey,
      iv: record.iv,
      gcmTag: record.gcmTag,
      expectedSha256: sha256,
    });

    expect(decrypted.isVerified).toBe(true);
    expect(decrypted.verifiedSha256).toBe(sha256);
    expect(decrypted.plaintext.equals(samplePe)).toBe(true);
  });

  it('rejects decryption when SHA-256 does not match original stored hash', async () => {
    const samplePe = createMockPeBuffer('Integrity failure simulation');
    const sha256 = calculateSha256(samplePe);
    const scanId = 'scan-tamper-hash';

    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256: sha256,
    });

    // Provide a different expected SHA-256
    const fakeExpectedSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    await expect(
      secureService.decryptAndVerify({
        storagePath: record.storagePath,
        wrappedAesKey: record.wrappedAesKey,
        iv: record.iv,
        gcmTag: record.gcmTag,
        expectedSha256: fakeExpectedSha256,
      })
    ).rejects.toThrow(IntegrityVerificationError);
  });

  it('rejects decryption when GCM auth tag has been tampered with', async () => {
    const samplePe = createMockPeBuffer('Auth tag failure simulation');
    const sha256 = calculateSha256(samplePe);
    const scanId = 'scan-tamper-tag';

    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256: sha256,
    });

    const tamperedTag = Buffer.from(record.gcmTag);
    tamperedTag[0] ^= 0x55;

    await expect(
      secureService.decryptAndVerify({
        storagePath: record.storagePath,
        wrappedAesKey: record.wrappedAesKey,
        iv: record.iv,
        gcmTag: tamperedTag,
        expectedSha256: sha256,
      })
    ).rejects.toThrow(DecryptionError);
  });

  it('deletes encrypted file cleanly from permanent storage', async () => {
    const samplePe = createMockPeBuffer('File to be deleted');
    const sha256 = calculateSha256(samplePe);
    const scanId = 'scan-delete-test';

    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256: sha256,
    });

    expect(await secureService.encryptedFileExists(record.storagePath)).toBe(true);
    await secureService.deleteEncryptedFile(record.storagePath);
    expect(await secureService.encryptedFileExists(record.storagePath)).toBe(false);
  });
});
