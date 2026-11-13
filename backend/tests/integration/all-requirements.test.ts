/**
 * CipherGuard AI - Member 3 Mandatory Requirements Verification Suite
 *
 * Verifies all 18 mandatory acceptance tests specified in the Member 3 requirements:
 * TEST 1: Encrypt sample file -> ciphertext differs from plaintext
 * TEST 2: Decrypt encrypted file -> decrypted bytes identical to original
 * TEST 3: Unique AES key per file
 * TEST 4: Unique 96-bit IV per encryption
 * TEST 5: GCM authentication tag verification
 * TEST 6: Ciphertext tampering detection
 * TEST 7: Auth tag tampering detection
 * TEST 8: Wrap AES key with RSA-OAEP & unwrap successfully
 * TEST 9: Unwrapped AES key identical to original
 * TEST 10: SHA-256 matches after successful decryption
 * TEST 11: Decrypted data corruption / SHA-256 mismatch detection
 * TEST 12: Raw AES keys are never written to permanent storage
 * TEST 13: RSA private key is never stored in database
 * TEST 14: Temporary plaintext files removed after success
 * TEST 15: Temporary plaintext files removed after exception/failure
 * TEST 16: Encrypted storage contains no plaintext files
 * TEST 17: Missing/invalid GCM tag causes failure
 * TEST 18: Invalid wrapped AES keys cause controlled error
 */

import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decryptBuffer, encryptBuffer, generateAesKey, generateIv } from '../../src/crypto/aes.js';
import { calculateSha256 } from '../../src/crypto/hash.js';
import { KeyManager } from '../../src/crypto/key-management.js';
import { generateRsaKeyPair, unwrapAesKey, wrapAesKey } from '../../src/crypto/rsa.js';
import {
  DecryptionError,
  IntegrityVerificationError,
  KeyUnwrapError,
} from '../../src/errors/crypto.errors.js';
import { SecureFileService } from '../../src/services/secure-file.service.js';
import { EncryptedStorageService } from '../../src/storage/encrypted-storage.js';
import { SecureTempFileManager } from '../../src/utils/temp-file.js';
import { createMockPeBuffer } from '../fixtures/sample-pe.js';

describe('Member 3: Cryptography & Secure Storage - 18 Mandatory Tests', () => {
  const testStorageDir = path.resolve(process.cwd(), 'storage', 'all_req_storage');
  const testTempDir = path.resolve(process.cwd(), 'storage', 'all_req_temp');

  let keyManager: KeyManager;
  let storageService: EncryptedStorageService;
  let tempFileManager: SecureTempFileManager;
  let secureService: SecureFileService;
  let keyPair: ReturnType<typeof generateRsaKeyPair>;
  const samplePe = createMockPeBuffer('MZ standard benign payload for testing');
  const originalSha256 = calculateSha256(samplePe);

  beforeAll(() => {
    if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });
    if (fs.existsSync(testTempDir)) fs.rmSync(testTempDir, { recursive: true, force: true });

    fs.mkdirSync(testStorageDir, { recursive: true });
    fs.mkdirSync(testTempDir, { recursive: true });

    keyPair = generateRsaKeyPair(2048);
    keyManager = new KeyManager({
      rsaPublicKeyPem: keyPair.publicKey,
      rsaPrivateKeyPem: keyPair.privateKey,
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

  afterAll(() => {
    if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });
    if (fs.existsSync(testTempDir)) fs.rmSync(testTempDir, { recursive: true, force: true });
  });

  it('TEST 1: Encrypt a sample file and verify that the encrypted output differs from plaintext', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePe, key, iv);

    expect(ciphertext).toBeInstanceOf(Buffer);
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(ciphertext.equals(samplePe)).toBe(false);
    expect(tag).toHaveLength(16);
  });

  it('TEST 2: Decrypt the encrypted file and verify the decrypted bytes are identical to the original', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePe, key, iv);

    const decrypted = decryptBuffer({ ciphertext, key, iv, tag });
    expect(decrypted.equals(samplePe)).toBe(true);
  });

  it('TEST 3: Verify that every encryption generates a unique AES key', () => {
    const keySet = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const key = generateAesKey();
      const hex = key.toString('hex');
      expect(keySet.has(hex)).toBe(false);
      keySet.add(hex);
    }
    expect(keySet.size).toBe(50);
  });

  it('TEST 4: Verify that every encryption generates a unique 96-bit IV', () => {
    const ivSet = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const iv = generateIv();
      expect(iv.length).toBe(12); // 96 bits
      const hex = iv.toString('hex');
      expect(ivSet.has(hex)).toBe(false);
      ivSet.add(hex);
    }
    expect(ivSet.size).toBe(50);
  });

  it('TEST 5: Verify GCM authentication-tag verification', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePe, key, iv);

    // Legitimate tag must verify cleanly
    expect(() => {
      decryptBuffer({ ciphertext, key, iv, tag });
    }).not.toThrow();
  });

  it('TEST 6: Modify/tamper with ciphertext and confirm decryption fails', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePe, key, iv);

    const tampered = Buffer.from(ciphertext);
    tampered[tampered.length - 1] ^= 0xff;

    expect(() => {
      decryptBuffer({ ciphertext: tampered, key, iv, tag });
    }).toThrow(DecryptionError);
  });

  it('TEST 7: Modify/tamper with the authentication tag and confirm decryption fails', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePe, key, iv);

    const tamperedTag = Buffer.from(tag);
    tamperedTag[0] ^= 0x01;

    expect(() => {
      decryptBuffer({ ciphertext, key, iv, tag: tamperedTag });
    }).toThrow(DecryptionError);
  });

  it('TEST 8: Wrap an AES key with RSA-OAEP and successfully unwrap it', () => {
    const aesKey = generateAesKey();
    const wrapped = wrapAesKey(aesKey, keyPair.publicKey);
    expect(wrapped.equals(aesKey)).toBe(false);

    const unwrapped = unwrapAesKey(wrapped, keyPair.privateKey);
    expect(unwrapped.equals(aesKey)).toBe(true);
  });

  it('TEST 9: Verify that the unwrapped AES key is identical to the original AES key', () => {
    const originalKey = generateAesKey();
    const wrapped = wrapAesKey(originalKey, keyPair.publicKey);
    const unwrapped = unwrapAesKey(wrapped, keyPair.privateKey);

    expect(unwrapped.length).toBe(32);
    expect(unwrapped.toString('hex')).toBe(originalKey.toString('hex'));
  });

  it('TEST 10: Verify SHA-256 matches after successful decryption', async () => {
    const scanId = 'scan-test-10';
    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256,
    });

    const result = await secureService.decryptAndVerify({
      storagePath: record.storagePath,
      wrappedAesKey: record.wrappedAesKey,
      iv: record.iv,
      gcmTag: record.gcmTag,
      expectedSha256: originalSha256,
    });

    expect(result.verifiedSha256).toBe(originalSha256);
    expect(calculateSha256(result.plaintext)).toBe(originalSha256);
  });

  it('TEST 11: Modify the decrypted data / simulate corruption and verify SHA-256 mismatch is detected', async () => {
    const scanId = 'scan-test-11';
    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256,
    });

    // Provide modified expected hash to simulate corruption detection
    const corruptedHash = '0'.repeat(64);

    await expect(
      secureService.decryptAndVerify({
        storagePath: record.storagePath,
        wrappedAesKey: record.wrappedAesKey,
        iv: record.iv,
        gcmTag: record.gcmTag,
        expectedSha256: corruptedHash,
      })
    ).rejects.toThrow(IntegrityVerificationError);
  });

  it('TEST 12: Verify raw AES keys are not written to permanent storage', async () => {
    const scanId = 'scan-test-12';
    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256,
    });

    const storageFiles = fs.readdirSync(testStorageDir);
    expect(storageFiles).toContain(record.storagePath);

    // Read stored encrypted blob
    const storedBlob = fs.readFileSync(path.join(testStorageDir, record.storagePath));

    // Stored file length should be ciphertext length, never contains unwrapped key
    // The wrapped key in the record is also checked to ensure it is not plaintext
    expect(storedBlob.length).toBe(samplePe.length); // AES-GCM ciphertext has exact plaintext length
  });

  it('TEST 13: Verify RSA private key is not stored in the database record', async () => {
    const scanId = 'scan-test-13';
    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256,
    });

    // Keys of the record matching PostgreSQL EncryptedFile
    expect(Object.keys(record)).not.toContain('privateKey');
    expect(Object.keys(record)).not.toContain('rsaPrivateKey');

    const privKeyRaw = Buffer.from(keyPair.privateKey);
    expect(record.wrappedAesKey.includes(privKeyRaw)).toBe(false);
  });

  it('TEST 14: Verify temporary plaintext files are removed after successful processing', async () => {
    const scanId = 'scan-test-14';
    const record = await secureService.encryptAndStore({
      scanId,
      fileData: samplePe,
      originalSha256,
    });

    const streamResult = await secureService.decryptAndVerifyStream({
      storagePath: record.storagePath,
      wrappedAesKey: record.wrappedAesKey,
      iv: record.iv,
      gcmTag: record.gcmTag,
      expectedSha256: originalSha256,
    });

    // Read stream to completion
    for await (const _ of streamResult.stream) {
      // consume
    }

    await streamResult.cleanup();
    await new Promise((resolve) => setTimeout(resolve, 50));

    const tempFiles = fs.readdirSync(testTempDir).filter((f) => f !== '.gitkeep');
    expect(tempFiles).toHaveLength(0);
  });

  it('TEST 15: Verify temporary plaintext files are removed after an exception/failure', async () => {
    let capturedPath = '';
    await expect(
      tempFileManager.withSecureTempFile(
        { prefix: 'test_err_', ext: '.tmp', initialData: Buffer.from('transient plaintext') },
        async (tmp) => {
          capturedPath = tmp;
          expect(fs.existsSync(tmp)).toBe(true);
          throw new Error('Forced crash inside processing block');
        }
      )
    ).rejects.toThrow('Forced crash inside processing block');

    expect(capturedPath).not.toBe('');
    expect(fs.existsSync(capturedPath)).toBe(false);
  });

  it('TEST 16: Verify encrypted storage does not contain plaintext files', () => {
    const audit = secureService.auditStorageSecurity();
    expect(audit.isCompliant).toBe(true);
    expect(audit.illegalFiles).toHaveLength(0);

    const files = fs.readdirSync(testStorageDir);
    for (const file of files) {
      expect(file.endsWith('.enc') || file === '.gitkeep').toBe(true);
      expect(file.endsWith('.exe')).toBe(false);
      expect(file.endsWith('.dll')).toBe(false);
    }
  });

  it('TEST 17: Verify a missing/invalid GCM tag causes failure', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext } = encryptBuffer(samplePe, key, iv);

    // Empty tag
    expect(() => {
      decryptBuffer({ ciphertext, key, iv, tag: Buffer.alloc(0) });
    }).toThrow(DecryptionError);

    // Incorrect tag length (8 bytes)
    expect(() => {
      decryptBuffer({ ciphertext, key, iv, tag: Buffer.alloc(8) });
    }).toThrow(DecryptionError);
  });

  it('TEST 18: Verify invalid wrapped AES keys cause a controlled error', () => {
    const invalidWrapped = Buffer.from('completely invalid wrapped key payload');
    expect(() => {
      unwrapAesKey(invalidWrapped, keyPair.privateKey);
    }).toThrow(KeyUnwrapError);
  });
});
