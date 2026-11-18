/**
 * CipherGuard AI - AES-256-GCM Cryptographic Implementation
 * Member 3: Cryptography & Secure Storage
 *
 * Requirements (SRS FR-6, Architecture §3.2, §7):
 * - Generate a unique 256-bit AES key per file using crypto.randomBytes(32).
 * - Generate a unique 96-bit IV/nonce per encryption operation using crypto.randomBytes(12).
 * - NEVER reuse an IV with the same AES key.
 * - Authenticated encryption via AES-256-GCM with 128-bit (16-byte) tag.
 * - GCM tag must be preserved and strictly verified during every decryption.
 * - Ciphertext tampering or tag tampering must fail immediately.
 * - Support both in-memory buffers and streaming for up to 50MB files.
 * - Never log raw AES keys.
 */

import crypto from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { CRYPTO_CONSTANTS } from '../config/crypto.config.js';
import { DecryptionError, EncryptionError } from '../errors/crypto.errors.js';
import type { AesDecryptionOptions, AesEncryptionResult } from '../types/crypto.types.js';
import { defaultLogger } from '../utils/logger.js';

/**
 * Generates a cryptographically secure random 256-bit (32-byte) AES key.
 * Never logs or persists this key in plaintext.
 */
export function generateAesKey(): Buffer {
  return crypto.randomBytes(CRYPTO_CONSTANTS.AES_KEY_LENGTH_BYTES);
}

/**
 * Generates a cryptographically secure random 96-bit (12-byte) initialization vector (IV/nonce).
 * Per NIST SP 800-38D, a 96-bit IV is the standard for AES-GCM and avoids hash calculation overhead.
 */
export function generateIv(): Buffer {
  return crypto.randomBytes(CRYPTO_CONSTANTS.GCM_IV_LENGTH_BYTES);
}

/**
 * Validates AES-256 key and 96-bit IV lengths.
 */
function validateAesInputs(key: Buffer, iv: Buffer, expectedKeyLen = CRYPTO_CONSTANTS.AES_KEY_LENGTH_BYTES, expectedIvLen = CRYPTO_CONSTANTS.GCM_IV_LENGTH_BYTES): void {
  if (!Buffer.isBuffer(key) || key.length !== expectedKeyLen) {
    throw new EncryptionError(`Invalid AES key length: expected ${expectedKeyLen} bytes (256-bit), got ${key?.length ?? 0} bytes.`);
  }
  if (!Buffer.isBuffer(iv) || iv.length !== expectedIvLen) {
    throw new EncryptionError(`Invalid IV length: expected ${expectedIvLen} bytes (96-bit), got ${iv?.length ?? 0} bytes.`);
  }
}

/**
 * Encrypts a plaintext buffer using AES-256-GCM.
 *
 * @param plaintext - The plaintext buffer to encrypt
 * @param key - The 256-bit AES key (Buffer)
 * @param explicitIv - Optional explicit IV. If omitted, a fresh random 96-bit IV is always generated.
 * @returns AesEncryptionResult containing ciphertext, IV, and 128-bit auth tag.
 */
export function encryptBuffer(
  plaintext: Buffer,
  key: Buffer,
  explicitIv?: Buffer
): AesEncryptionResult {
  const iv = explicitIv ?? generateIv();
  validateAesInputs(key, iv);

  try {
    const cipher = crypto.createCipheriv(CRYPTO_CONSTANTS.AES_ALGORITHM, key, iv, {
      authTagLength: CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES,
    });

    const encryptedChunks = [cipher.update(plaintext), cipher.final()];
    const ciphertext = Buffer.concat(encryptedChunks);
    const tag = cipher.getAuthTag();

    if (tag.length !== CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES) {
      throw new EncryptionError('Generated authentication tag has invalid length.');
    }

    return { ciphertext, iv, tag };
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    defaultLogger.error('AES-256-GCM encryption failed', { reason: err instanceof Error ? err.message : String(err) });
    throw new EncryptionError('AES-256-GCM encryption operation failed.', err);
  }
}

/**
 * Decrypts an AES-256-GCM ciphertext buffer.
 * Authenticates the ciphertext using the supplied 128-bit authentication tag.
 *
 * @throws DecryptionError if the ciphertext or authentication tag was modified, corrupted, or invalid.
 */
export function decryptBuffer(options: AesDecryptionOptions): Buffer {
  const { ciphertext, key, iv, tag } = options;

  if (!Buffer.isBuffer(tag) || tag.length !== CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES) {
    throw new DecryptionError(
      `Invalid GCM authentication tag: expected ${CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES} bytes (128-bit), got ${tag?.length ?? 0} bytes.`
    );
  }

  validateAesInputs(key, iv);

  try {
    const decipher = crypto.createDecipheriv(CRYPTO_CONSTANTS.AES_ALGORITHM, key, iv, {
      authTagLength: CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES,
    });

    decipher.setAuthTag(tag);

    const decryptedChunks = [decipher.update(ciphertext), decipher.final()];
    return Buffer.concat(decryptedChunks);
  } catch (err) {
    defaultLogger.securityAlert('AES-256-GCM decryption failed: authentication tag verification failed or ciphertext tampered.', {
      error: err instanceof Error ? err.message : String(err),
    });
    throw new DecryptionError('Decryption failed: corrupted ciphertext or authentication tag mismatch.', err);
  }
}

/**
 * Encrypts a Readable stream to a Writable stream using AES-256-GCM.
 * Extracts and returns the 128-bit authentication tag upon stream completion.
 */
export async function encryptStream(
  inputStream: Readable,
  outputStream: Writable,
  key: Buffer,
  iv: Buffer
): Promise<{ tag: Buffer; totalBytesWritten: number }> {
  validateAesInputs(key, iv);

  const cipher = crypto.createCipheriv(CRYPTO_CONSTANTS.AES_ALGORITHM, key, iv, {
    authTagLength: CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES,
  });

  let totalBytesWritten = 0;
  cipher.on('data', (chunk: Buffer) => {
    totalBytesWritten += chunk.length;
  });

  try {
    await pipeline(inputStream, cipher, outputStream);
    const tag = cipher.getAuthTag();
    return { tag, totalBytesWritten };
  } catch (err) {
    defaultLogger.error('AES-256-GCM streaming encryption failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    throw new EncryptionError('Streaming AES-256-GCM encryption failed.', err);
  }
}

/**
 * Decrypts a Readable stream to a Writable stream using AES-256-GCM.
 * Verifies the 128-bit GCM authentication tag.
 *
 * @throws DecryptionError if tag or ciphertext does not authenticate.
 */
export async function decryptStream(
  inputStream: Readable,
  outputStream: Writable,
  key: Buffer,
  iv: Buffer,
  tag: Buffer
): Promise<void> {
  if (!Buffer.isBuffer(tag) || tag.length !== CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES) {
    throw new DecryptionError(`Invalid authentication tag length: expected ${CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES} bytes.`);
  }

  validateAesInputs(key, iv);

  const decipher = crypto.createDecipheriv(CRYPTO_CONSTANTS.AES_ALGORITHM, key, iv, {
    authTagLength: CRYPTO_CONSTANTS.GCM_AUTH_TAG_LENGTH_BYTES,
  });

  decipher.setAuthTag(tag);

  try {
    await pipeline(inputStream, decipher, outputStream);
  } catch (err) {
    defaultLogger.securityAlert('AES-256-GCM streaming decryption failed: authentication tag verification failed.', {
      error: err instanceof Error ? err.message : String(err),
    });
    throw new DecryptionError('Streaming decryption failed: corrupted ciphertext or authentication tag mismatch.', err);
  }
}
