/**
 * CipherGuard AI - Cryptography & Storage Configuration
 * Member 3: Cryptography & Secure Storage
 *
 * Implements constants and environment loading per:
 * - SRS FR-6 (AES-256-GCM: 256-bit key, 96-bit IV, 128-bit GCM tag)
 * - SRS FR-7 (RSA-OAEP: 2048-bit minimum or 4096-bit RSA, SHA-256 OAEP hash)
 * - SRS FR-2.3 (50 MB maximum file size)
 */

import path from 'node:path';

export const CRYPTO_CONSTANTS = {
  /** AES algorithm identifier */
  AES_ALGORITHM: 'aes-256-gcm' as const,
  /** AES key length in bytes: 32 bytes = 256 bits */
  AES_KEY_LENGTH_BYTES: 32,
  /** GCM IV/nonce length in bytes: 12 bytes = 96 bits (standard NIST recommended length) */
  GCM_IV_LENGTH_BYTES: 12,
  /** GCM authentication tag length in bytes: 16 bytes = 128 bits */
  GCM_AUTH_TAG_LENGTH_BYTES: 16,
  /** Minimum allowed RSA modulus size in bits */
  MIN_RSA_MODULUS_BITS: 2048,
  /** Default RSA modulus size for new keys */
  DEFAULT_RSA_MODULUS_BITS: 4096,
  /** OAEP hashing algorithm */
  RSA_OAEP_HASH: 'sha256' as const,
  /** Hash algorithm used for file integrity */
  HASH_ALGORITHM: 'sha256' as const,
  /** Max file size (50MB) */
  MAX_FILE_SIZE_BYTES: 50 * 1024 * 1024,
} as const;

export interface CryptoEnvironmentConfig {
  encryptedStorageDir: string;
  tempStorageDir: string;
  rsaPublicKeyPem?: string;
  rsaPrivateKeyPem?: string;
  rsaPublicKeyPath?: string;
  rsaPrivateKeyPath?: string;
  allowEphemeralDevKeys: boolean;
}

/**
 * Loads crypto and storage configuration from environment variables with safe defaults.
 */
export function loadCryptoConfig(): CryptoEnvironmentConfig {
  const baseStorageDir = process.env.CIPHERGUARD_STORAGE_ROOT || path.resolve(process.cwd(), 'storage');

  return {
    encryptedStorageDir:
      process.env.CIPHERGUARD_ENCRYPTED_STORAGE_DIR || path.join(baseStorageDir, 'encrypted'),
    tempStorageDir:
      process.env.CIPHERGUARD_TEMP_STORAGE_DIR || path.join(baseStorageDir, 'temp'),
    rsaPublicKeyPem: process.env.CIPHERGUARD_RSA_PUBLIC_KEY,
    rsaPrivateKeyPem: process.env.CIPHERGUARD_RSA_PRIVATE_KEY,
    rsaPublicKeyPath: process.env.CIPHERGUARD_RSA_PUBLIC_KEY_PATH,
    rsaPrivateKeyPath: process.env.CIPHERGUARD_RSA_PRIVATE_KEY_PATH,
    allowEphemeralDevKeys: process.env.NODE_ENV !== 'production' || process.env.CIPHERGUARD_ALLOW_DEV_KEYS === 'true',
  };
}
