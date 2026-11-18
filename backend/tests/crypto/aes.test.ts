import { describe, expect, it } from 'vitest';
import { decryptBuffer, encryptBuffer, generateAesKey, generateIv } from '../../src/crypto/aes.js';
import { DecryptionError, EncryptionError } from '../../src/errors/crypto.errors.js';
import { createMockPeBuffer } from '../fixtures/sample-pe.js';

describe('AES-256-GCM Cryptographic Unit Tests', () => {
  const samplePlaintext = createMockPeBuffer('Hello CipherGuard Security Analyst');

  // TEST 1: Encrypt a sample file and verify that the encrypted output differs from plaintext.
  it('TEST 1: Encrypt a sample file and verify that the encrypted output differs from plaintext', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePlaintext, key, iv);

    expect(ciphertext).toBeInstanceOf(Buffer);
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(ciphertext.equals(samplePlaintext)).toBe(false);
    expect(ciphertext.includes(Buffer.from('CipherGuard Security Analyst'))).toBe(false);
    expect(tag).toBeInstanceOf(Buffer);
    expect(tag.length).toBe(16); // 128-bit tag
  });

  // TEST 2: Decrypt the encrypted file and verify the decrypted bytes are identical to the original.
  it('TEST 2: Decrypt the encrypted file and verify the decrypted bytes are identical to the original', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePlaintext, key, iv);

    const decrypted = decryptBuffer({
      ciphertext,
      key,
      iv,
      tag,
    });

    expect(decrypted.equals(samplePlaintext)).toBe(true);
    expect(decrypted.toString()).toBe(samplePlaintext.toString());
  });

  // TEST 3: Verify that every encryption generates a unique AES key.
  it('TEST 3: Verify that every encryption generates a unique AES key', () => {
    const keys = new Set<string>();
    const count = 100;

    for (let i = 0; i < count; i++) {
      const key = generateAesKey();
      expect(key.length).toBe(32); // 256 bits
      const hex = key.toString('hex');
      expect(keys.has(hex)).toBe(false);
      keys.add(hex);
    }

    expect(keys.size).toBe(count);
  });

  // TEST 4: Verify that every encryption generates a unique 96-bit IV.
  it('TEST 4: Verify that every encryption generates a unique 96-bit IV', () => {
    const ivs = new Set<string>();
    const count = 100;

    for (let i = 0; i < count; i++) {
      const iv = generateIv();
      expect(iv.length).toBe(12); // 96 bits
      const hex = iv.toString('hex');
      expect(ivs.has(hex)).toBe(false);
      ivs.add(hex);
    }

    expect(ivs.size).toBe(count);
  });

  // TEST 5: Verify GCM authentication-tag verification.
  it('TEST 5: Verify GCM authentication-tag verification succeeds with valid tag', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePlaintext, key, iv);

    expect(() => {
      decryptBuffer({ ciphertext, key, iv, tag });
    }).not.toThrow();
  });

  // TEST 6: Modify/tamper with ciphertext and confirm decryption fails.
  it('TEST 6: Modify/tamper with ciphertext and confirm decryption fails', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePlaintext, key, iv);

    // Tamper with the ciphertext by flipping a single bit
    const tamperedCiphertext = Buffer.from(ciphertext);
    tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0x01;

    expect(() => {
      decryptBuffer({
        ciphertext: tamperedCiphertext,
        key,
        iv,
        tag,
      });
    }).toThrow(DecryptionError);
  });

  // TEST 7: Modify/tamper with the authentication tag and confirm decryption fails.
  it('TEST 7: Modify/tamper with the authentication tag and confirm decryption fails', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext, tag } = encryptBuffer(samplePlaintext, key, iv);

    // Tamper with the authentication tag
    const tamperedTag = Buffer.from(tag);
    tamperedTag[0] ^= 0xff;

    expect(() => {
      decryptBuffer({
        ciphertext,
        key,
        iv,
        tag: tamperedTag,
      });
    }).toThrow(DecryptionError);
  });

  // TEST 17: Verify a missing/invalid GCM tag causes failure.
  it('TEST 17: Verify a missing/invalid GCM tag causes failure', () => {
    const key = generateAesKey();
    const iv = generateIv();
    const { ciphertext } = encryptBuffer(samplePlaintext, key, iv);

    // 1. Missing tag (empty buffer)
    expect(() => {
      decryptBuffer({
        ciphertext,
        key,
        iv,
        tag: Buffer.alloc(0),
      });
    }).toThrow(DecryptionError);

    // 2. Truncated tag (e.g. 10 bytes instead of 16)
    expect(() => {
      decryptBuffer({
        ciphertext,
        key,
        iv,
        tag: Buffer.alloc(10),
      });
    }).toThrow(DecryptionError);
  });

  it('rejects invalid key length (not 32 bytes)', () => {
    const invalidKey = Buffer.alloc(16); // 128 bits
    const iv = generateIv();
    expect(() => {
      encryptBuffer(samplePlaintext, invalidKey, iv);
    }).toThrow(EncryptionError);
  });
});
