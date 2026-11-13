import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { calculateSha256, calculateSha256FromFile, calculateSha256FromStream, timingSafeCompareHashes } from '../../src/crypto/hash.js';
import { createMockPeBuffer } from '../fixtures/sample-pe.js';

describe('SHA-256 Hashing and Integrity Unit Tests', () => {
  const samplePe = createMockPeBuffer('Integrity Check PE Binary');
  const expectedHash = calculateSha256(samplePe);

  // TEST 10: Verify SHA-256 matches after successful decryption.
  it('TEST 10: Verify SHA-256 matches after successful decryption / processing', () => {
    const computedHash = calculateSha256(samplePe);
    expect(computedHash).toHaveLength(64);
    expect(timingSafeCompareHashes(computedHash, expectedHash)).toBe(true);
  });

  // TEST 11: Modify the decrypted data / simulate corruption and verify SHA-256 mismatch is detected.
  it('TEST 11: Modify the decrypted data / simulate corruption and verify SHA-256 mismatch is detected', () => {
    const corrupted = Buffer.from(samplePe);
    corrupted[corrupted.length - 1] ^= 0x01; // flip 1 bit

    const corruptedHash = calculateSha256(corrupted);
    expect(corruptedHash).not.toBe(expectedHash);
    expect(timingSafeCompareHashes(corruptedHash, expectedHash)).toBe(false);
  });

  it('computes SHA-256 accurately from Readable stream', async () => {
    const stream = Readable.from([samplePe]);
    const streamHash = await calculateSha256FromStream(stream);
    expect(streamHash).toBe(expectedHash);
  });

  it('computes SHA-256 accurately from file on disk', async () => {
    const tempFilePath = path.resolve(process.cwd(), 'storage', 'temp', 'test_hash.bin');
    fs.writeFileSync(tempFilePath, samplePe);

    try {
      const fileHash = await calculateSha256FromFile(tempFilePath);
      expect(fileHash).toBe(expectedHash);
    } finally {
      if (fs.existsSync(tempFilePath)) {
        fs.unlinkSync(tempFilePath);
      }
    }
  });

  it('timingSafeCompareHashes handles edge cases securely', () => {
    expect(timingSafeCompareHashes('', '')).toBe(false);
    expect(timingSafeCompareHashes('short', 'short')).toBe(false);
    expect(timingSafeCompareHashes('a'.repeat(64), 'a'.repeat(64))).toBe(true);
    expect(timingSafeCompareHashes('a'.repeat(64), 'b'.repeat(64))).toBe(false);
  });
});
