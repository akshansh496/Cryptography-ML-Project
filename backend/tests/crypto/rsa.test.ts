import { describe, expect, it } from 'vitest';
import { generateAesKey } from '../../src/crypto/aes.js';
import { generateRsaKeyPair, unwrapAesKey, validateRsaPrivateKey, validateRsaPublicKey, wrapAesKey } from '../../src/crypto/rsa.js';
import { KeyConfigurationError, KeyUnwrapError, KeyWrapError } from '../../src/errors/crypto.errors.js';

describe('RSA-OAEP Key Wrapping Unit Tests', () => {
  // Use a fast 2048-bit key for tests to keep test runs fast, plus test 4096-bit
  const testKeyPair = generateRsaKeyPair(2048);

  // TEST 8: Wrap an AES key with RSA-OAEP and successfully unwrap it.
  it('TEST 8: Wrap an AES key with RSA-OAEP and successfully unwrap it', () => {
    const aesKey = generateAesKey();
    const wrapped = wrapAesKey(aesKey, testKeyPair.publicKey);

    expect(wrapped).toBeInstanceOf(Buffer);
    expect(wrapped.length).toBeGreaterThan(0);
    expect(wrapped.equals(aesKey)).toBe(false);

    const unwrapped = unwrapAesKey(wrapped, testKeyPair.privateKey);
    expect(unwrapped).toBeInstanceOf(Buffer);
    expect(unwrapped.equals(aesKey)).toBe(true);
  });

  // TEST 9: Verify that the unwrapped AES key is identical to the original AES key.
  it('TEST 9: Verify that the unwrapped AES key is identical to the original AES key', () => {
    const aesKey = generateAesKey();
    const wrapped = wrapAesKey(aesKey, testKeyPair.publicKey);
    const unwrapped = unwrapAesKey(wrapped, testKeyPair.privateKey);

    expect(unwrapped.length).toBe(32);
    expect(unwrapped.toString('hex')).toBe(aesKey.toString('hex'));
  });

  // TEST 18: Verify invalid wrapped AES keys cause a controlled error.
  it('TEST 18: Verify invalid wrapped AES keys cause a controlled error', () => {
    // 1. Corrupted wrapped key
    const aesKey = generateAesKey();
    const wrapped = wrapAesKey(aesKey, testKeyPair.publicKey);
    const corruptedWrapped = Buffer.from(wrapped);
    corruptedWrapped[0] ^= 0xaa;

    expect(() => {
      unwrapAesKey(corruptedWrapped, testKeyPair.privateKey);
    }).toThrow(KeyUnwrapError);

    // 2. Empty wrapped key
    expect(() => {
      unwrapAesKey(Buffer.alloc(0), testKeyPair.privateKey);
    }).toThrow(KeyUnwrapError);

    // 3. Completely random invalid bytes
    expect(() => {
      unwrapAesKey(Buffer.from('not-a-valid-rsa-ciphertext'), testKeyPair.privateKey);
    }).toThrow(KeyUnwrapError);
  });

  it('validates minimum RSA modulus length of 2048 bits', () => {
    expect(() => {
      generateRsaKeyPair(1024);
    }).toThrow(KeyConfigurationError);
  });

  it('validates public key formatting', () => {
    expect(() => {
      validateRsaPublicKey('invalid-pem');
    }).toThrow(KeyConfigurationError);
  });

  it('validates private key formatting', () => {
    expect(() => {
      validateRsaPrivateKey('invalid-pem');
    }).toThrow(KeyConfigurationError);
  });

  it('rejects wrapping invalid AES key lengths', () => {
    const invalidAesKey = Buffer.alloc(16); // 128-bit instead of 256-bit
    expect(() => {
      wrapAesKey(invalidAesKey, testKeyPair.publicKey);
    }).toThrow(KeyWrapError);
  });
});
