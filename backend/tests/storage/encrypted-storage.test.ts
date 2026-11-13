import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateAesKey } from '../../src/crypto/aes.js';
import { EncryptedStorageError } from '../../src/errors/crypto.errors.js';
import { EncryptedStorageService } from '../../src/storage/encrypted-storage.js';

describe('Encrypted Storage Service Unit Tests', () => {
  const testStorageDir = path.resolve(process.cwd(), 'storage', 'test_encrypted');
  const testTempDir = path.resolve(process.cwd(), 'storage', 'test_temp');
  let storageService: EncryptedStorageService;

  beforeEach(() => {
    if (fs.existsSync(testStorageDir)) {
      fs.rmSync(testStorageDir, { recursive: true, force: true });
    }
    fs.mkdirSync(testStorageDir, { recursive: true });
    storageService = new EncryptedStorageService({
      encryptedStorageDir: testStorageDir,
      tempStorageDir: testTempDir,
    });
  });

  afterEach(() => {
    if (fs.existsSync(testStorageDir)) {
      fs.rmSync(testStorageDir, { recursive: true, force: true });
    }
  });

  // TEST 12: Verify raw AES keys are not written to permanent storage.
  it('TEST 12: Verify raw AES keys are not written to permanent storage', async () => {
    const rawAesKey = generateAesKey();
    const fakeCiphertext = Buffer.from('encrypted-data-blob-not-raw-key');
    const scanId = 'scan-test-12';

    await storageService.storeEncryptedBlob(scanId, fakeCiphertext);

    // Read all files in storage directory
    const files = fs.readdirSync(testStorageDir);
    expect(files).toContain(`${scanId}.enc`);

    for (const file of files) {
      const content = fs.readFileSync(path.join(testStorageDir, file));
      // Verify raw AES key is NOT present in any stored file
      expect(content.includes(rawAesKey)).toBe(false);
      // Verify file does not equal raw AES key
      expect(content.equals(rawAesKey)).toBe(false);
    }
  });

  // TEST 16: Verify encrypted storage does not contain plaintext files.
  it('TEST 16: Verify encrypted storage does not contain plaintext files (.exe / .dll)', async () => {
    const scanId = 'scan-test-16';
    const fakeCiphertext = Buffer.from('aes-256-gcm-ciphertext');

    await storageService.storeEncryptedBlob(scanId, fakeCiphertext);

    // Run security audit
    const audit = storageService.auditStorageSecurity();
    expect(audit.isCompliant).toBe(true);
    expect(audit.illegalFiles).toHaveLength(0);

    const dirContents = fs.readdirSync(testStorageDir);
    for (const filename of dirContents) {
      expect(filename.endsWith('.enc') || filename === '.gitkeep').toBe(true);
      expect(filename.endsWith('.exe')).toBe(false);
      expect(filename.endsWith('.dll')).toBe(false);
      expect(filename.endsWith('.bin')).toBe(false);
    }
  });

  it('detects and flags illegal plaintext files during audit', () => {
    const illegalPath = path.join(testStorageDir, 'malicious.exe');
    fs.writeFileSync(illegalPath, 'MZ plaintext PE');

    const audit = storageService.auditStorageSecurity();
    expect(audit.isCompliant).toBe(false);
    expect(audit.illegalFiles).toContain('malicious.exe');

    fs.unlinkSync(illegalPath);
  });

  it('strictly prevents path traversal in file identifiers', async () => {
    expect(() => {
      storageService.resolveSafePath('../../etc/passwd');
    }).toThrow(EncryptedStorageError);

    expect(() => {
      storageService.resolveSafePath('..\\..\\windows\\system32\\cmd.exe');
    }).toThrow(EncryptedStorageError);

    expect(() => {
      storageService.resolveSafePath('file\0injected.enc');
    }).toThrow(EncryptedStorageError);
  });

  it('stores, reads, and deletes encrypted blobs accurately', async () => {
    const testId = 'sample-scan-123';
    const data = Buffer.from('test-ciphertext-bytes');

    const storagePath = await storageService.storeEncryptedBlob(testId, data);
    expect(storagePath).toBe(`${testId}.enc`);

    expect(await storageService.exists(testId)).toBe(true);
    const retrieved = await storageService.readEncryptedBlob(testId);
    expect(retrieved.equals(data)).toBe(true);

    await storageService.deleteEncryptedBlob(testId);
    expect(await storageService.exists(testId)).toBe(false);
  });
});
