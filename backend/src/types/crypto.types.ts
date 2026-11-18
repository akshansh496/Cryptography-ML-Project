/**
 * CipherGuard AI - Cryptography & Secure Storage Types
 * Member 3: Cryptography & Secure Storage
 *
 * All types adhere to the specifications in:
 * - CipherGuard AI PRD v1.0
 * - CipherGuard AI SRS v1.0 (Section 6 & FR-6, FR-7, FR-8, FR-9)
 * - CipherGuard AI System Architecture Document v1.0 (Section 3.2, 3.6, 4)
 */

import { Readable } from 'node:stream';

/**
 * Result of in-memory or streamed AES-256-GCM encryption.
 */
export interface AesEncryptionResult {
  /** The AES-256-GCM ciphertext bytes */
  ciphertext: Buffer;
  /** 96-bit (12-byte) initialization vector / nonce */
  iv: Buffer;
  /** 128-bit (16-byte) GCM authentication tag */
  tag: Buffer;
}

/**
 * Options required to decrypt an AES-256-GCM ciphertext buffer.
 */
export interface AesDecryptionOptions {
  /** The encrypted ciphertext bytes */
  ciphertext: Buffer;
  /** The 256-bit (32-byte) raw AES key */
  key: Buffer;
  /** The 96-bit (12-byte) initialization vector / nonce used during encryption */
  iv: Buffer;
  /** The 128-bit (16-byte) GCM authentication tag produced during encryption */
  tag: Buffer;
}

/**
 * Streaming AES-256-GCM encryption result.
 */
export interface StreamEncryptionResult {
  /** 96-bit (12-byte) initialization vector / nonce */
  iv: Buffer;
  /** 128-bit (16-byte) GCM authentication tag */
  tag: Buffer;
  /** Length of the written ciphertext in bytes */
  ciphertextBytes: number;
}

/**
 * RSA key pair in PEM format.
 */
export interface RsaKeyPair {
  /** RSA Public Key in SPKI (SubjectPublicKeyInfo) PEM format */
  publicKey: string;
  /** RSA Private Key in PKCS#8 PEM format */
  privateKey: string;
}

/**
 * Cryptographic metadata corresponding to PostgreSQL `encrypted_files` table.
 * Exactly matches SRS §6:
 * EncryptedFile - id (UUID, PK), scan_id (FK, 1:1), storage_path, wrapped_aes_key (bytes), iv (bytes), gcm_tag (bytes), encrypted_at
 */
export interface EncryptedFileRecord {
  /** Unique ID of the encrypted file record (UUID v4) */
  id: string;
  /** Foreign key to Scan table (1:1 relation) */
  scanId: string;
  /** Relative storage path or unique filename of the encrypted blob (e.g. "<scanId>.enc") */
  storagePath: string;
  /** AES-256 key wrapped with RSA-OAEP 2048/4096-bit public key */
  wrappedAesKey: Buffer;
  /** 96-bit (12-byte) initialization vector / nonce */
  iv: Buffer;
  /** 128-bit (16-byte) GCM authentication tag */
  gcmTag: Buffer;
  /** Timestamp when encryption occurred */
  encryptedAt: Date;
}

/**
 * Complete file metadata per SRS §4 FR-8.2.
 */
export interface FileMetadata {
  fileId: string;
  scanId: string;
  userId?: string;
  originalFilename?: string;
  sha256Hash: string;
  verdict?: 'BENIGN' | 'MALICIOUS';
  riskScore?: number;
  explanation?: Record<string, unknown>;
  wrappedAesKey: Buffer;
  iv: Buffer;
  gcmTag: Buffer;
  storagePath: string;
  uploadTimestamp?: Date;
  encryptedAt: Date;
}

/**
 * Input parameters for encryptAndStore orchestration.
 */
export interface EncryptAndStoreInput {
  /** Unique scan ID corresponding to an already analyzed file (per SRS BR-2) */
  scanId: string;
  /** File buffer or absolute path to the validated, analyzed file */
  fileData: Buffer | string;
  /** Expected SHA-256 hash computed upon initial upload validation (SRS FR-3.1) */
  originalSha256: string;
  /** Optional custom file identifier; defaults to scanId */
  fileId?: string;
}

/**
 * Options for decryptAndVerify orchestration.
 */
export interface DecryptAndVerifyOptions {
  /** Storage path or blob identifier in encrypted storage */
  storagePath: string;
  /** RSA-OAEP wrapped AES-256 key from `encrypted_files` table */
  wrappedAesKey: Buffer;
  /** 96-bit IV from `encrypted_files` table */
  iv: Buffer;
  /** 128-bit GCM authentication tag from `encrypted_files` table */
  gcmTag: Buffer;
  /** Original SHA-256 hash from `scans` table to verify against post-decryption */
  expectedSha256: string;
}

/**
 * Result of decryptAndVerify returning an in-memory buffer.
 */
export interface DecryptedBufferResult {
  /** Decrypted plaintext buffer */
  plaintext: Buffer;
  /** Verified SHA-256 hash */
  verifiedSha256: string;
  /** Explicit verification confirmation */
  isVerified: true;
}

/**
 * Result of decryptAndVerify returning a streaming payload with automatic cleanup.
 */
export interface DecryptedStreamResult {
  /** Readable stream of decrypted, integrity-verified plaintext */
  stream: Readable;
  /** Verified SHA-256 hash matching the original stored hash */
  verifiedSha256: string;
  /** Total byte length of plaintext */
  contentLength: number;
  /** Cleanup hook to remove any temporary files or zero memory buffers */
  cleanup: () => Promise<void>;
}

/**
 * Key manager configuration.
 */
export interface KeyManagerConfig {
  /** RSA Public Key in PEM format (used for wrapping AES keys) */
  rsaPublicKeyPem?: string;
  /** RSA Private Key in PEM format (used for unwrapping AES keys during download) */
  rsaPrivateKeyPem?: string;
  /** Path to RSA Public Key PEM file */
  rsaPublicKeyPath?: string;
  /** Path to RSA Private Key PEM file */
  rsaPrivateKeyPath?: string;
  /** Minimum allowed RSA modulus length in bits (default: 2048) */
  minRsaModulusBits?: number;
  /** Allow generating ephemeral in-memory RSA key pair if none configured (dev/test only) */
  allowEphemeralDevKeys?: boolean;
}

/**
 * Storage configuration options.
 */
export interface StorageConfig {
  /** Absolute or relative base directory for permanent encrypted files */
  encryptedStorageDir: string;
  /** Absolute or relative base directory for temporary processing files */
  tempStorageDir: string;
  /** Maximum allowable file size in bytes (default: 50MB per SRS FR-2.3) */
  maxFileSizeBytes?: number;
}
