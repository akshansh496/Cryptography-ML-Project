/**
 * CipherGuard AI - Cryptographic Hashing Utilities
 * Member 3: Cryptography & Secure Storage
 *
 * Implements SHA-256 hashing and timing-safe verification per:
 * - SRS FR-3.1 (Compute SHA-256 of raw uploaded file)
 * - SRS FR-9.1 / FR-9.2 (Re-compute and verify SHA-256 post-decryption)
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { CRYPTO_CONSTANTS } from '../config/crypto.config.js';
import { CryptoError } from '../errors/crypto.errors.js';

/**
 * Calculates a SHA-256 hash of a Buffer or UTF-8 string.
 * Returns lowercase hex-encoded string (64 characters).
 */
export function calculateSha256(data: Buffer | string): string {
  try {
    return crypto.createHash(CRYPTO_CONSTANTS.HASH_ALGORITHM).update(data).digest('hex').toLowerCase();
  } catch (err) {
    throw new CryptoError('Failed to compute SHA-256 hash.', 'CIPHERGUARD_HASH_ERROR', 500);
  }
}

/**
 * Computes SHA-256 hash from a Readable stream efficiently without buffering entire contents into RAM.
 */
export async function calculateSha256FromStream(readable: Readable): Promise<string> {
  try {
    const hash = crypto.createHash(CRYPTO_CONSTANTS.HASH_ALGORITHM);
    await pipeline(readable, hash);
    return hash.digest('hex').toLowerCase();
  } catch (err) {
    throw new CryptoError('Failed to compute SHA-256 hash from stream.', 'CIPHERGUARD_HASH_ERROR', 500);
  }
}

/**
 * Computes SHA-256 hash directly from a file path using a streaming file read.
 */
export async function calculateSha256FromFile(filePath: string): Promise<string> {
  if (!fs.existsSync(filePath)) {
    throw new CryptoError(`Cannot hash file: path does not exist.`, 'CIPHERGUARD_FILE_NOT_FOUND', 404);
  }
  const stream = fs.createReadStream(filePath);
  return calculateSha256FromStream(stream);
}

/**
 * Compares two SHA-256 hex strings in constant time to prevent timing attacks.
 *
 * @param actual - The newly calculated hash
 * @param expected - The original recorded hash
 * @returns true if hashes match exactly, false otherwise
 */
export function timingSafeCompareHashes(actual: string, expected: string): boolean {
  if (typeof actual !== 'string' || typeof expected !== 'string') {
    return false;
  }
  const normActual = actual.trim().toLowerCase();
  const normExpected = expected.trim().toLowerCase();

  if (normActual.length !== 64 || normExpected.length !== 64) {
    return false;
  }

  const bufActual = Buffer.from(normActual, 'hex');
  const bufExpected = Buffer.from(normExpected, 'hex');

  if (bufActual.length !== bufExpected.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufActual, bufExpected);
}
