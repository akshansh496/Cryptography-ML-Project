/**
 * CipherGuard AI - Secure File Service
 * Member 3: Cryptography & Secure Storage
 *
 * Primary Orchestrator for:
 * - Envelope encryption (AES-256-GCM + RSA-OAEP)
 * - Secure permanent encrypted storage (<scanId>.enc)
 * - Post-decryption SHA-256 integrity verification
 * - Secure temporary file management with zero-wiping
 * - Clear integration contract for Member 2 (API/Auth/DB)
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import { CRYPTO_CONSTANTS, loadCryptoConfig } from '../config/crypto.config.js';
import { decryptBuffer, encryptBuffer, generateAesKey, generateIv } from '../crypto/aes.js';
import { calculateSha256, timingSafeCompareHashes } from '../crypto/hash.js';
import { KeyManager } from '../crypto/key-management.js';
import { generateRsaKeyPair } from '../crypto/rsa.js';
import { CryptoError, IntegrityVerificationError } from '../errors/crypto.errors.js';
import { EncryptedStorageService } from '../storage/encrypted-storage.js';
import type {
  DecryptedBufferResult,
  DecryptedStreamResult,
  DecryptAndVerifyOptions,
  EncryptAndStoreInput,
  EncryptedFileRecord,
  KeyManagerConfig,
  RsaKeyPair,
  StorageConfig,
} from '../types/crypto.types.js';
import { defaultLogger } from '../utils/logger.js';
import { SecureTempFileManager } from '../utils/temp-file.js';

export interface SecureFileServiceOptions {
  keyManager?: KeyManager;
  keyConfig?: KeyManagerConfig;
  storageService?: EncryptedStorageService;
  storageConfig?: StorageConfig;
  tempFileManager?: SecureTempFileManager;
}

export class SecureFileService {
  private readonly keyManager: KeyManager;
  private readonly storageService: EncryptedStorageService;
  private readonly tempFileManager: SecureTempFileManager;

  constructor(options?: SecureFileServiceOptions) {
    const envConfig = loadCryptoConfig();

    this.keyManager =
      options?.keyManager ??
      new KeyManager(
        options?.keyConfig ?? {
          rsaPublicKeyPem: envConfig.rsaPublicKeyPem,
          rsaPrivateKeyPem: envConfig.rsaPrivateKeyPem,
          rsaPublicKeyPath: envConfig.rsaPublicKeyPath,
          rsaPrivateKeyPath: envConfig.rsaPrivateKeyPath,
          allowEphemeralDevKeys: envConfig.allowEphemeralDevKeys,
        }
      );

    this.storageService =
      options?.storageService ??
      new EncryptedStorageService(
        options?.storageConfig ?? {
          encryptedStorageDir: envConfig.encryptedStorageDir,
          tempStorageDir: envConfig.tempStorageDir,
        }
      );

    this.tempFileManager =
      options?.tempFileManager ??
      new SecureTempFileManager(options?.storageConfig?.tempStorageDir ?? envConfig.tempStorageDir);
  }

  // ==========================================
  // Cryptographic Primitives (Exported for Member 2)
  // ==========================================

  /**
   * Generates a unique 256-bit AES key.
   */
  public generateAesKey(): Buffer {
    return generateAesKey();
  }

  /**
   * Generates a unique 96-bit IV.
   */
  public generateIv(): Buffer {
    return generateIv();
  }

  /**
   * Generates an RSA key pair (4096-bit or 2048-bit).
   */
  public generateKeys(modulusBits = CRYPTO_CONSTANTS.DEFAULT_RSA_MODULUS_BITS): RsaKeyPair {
    return generateRsaKeyPair(modulusBits);
  }

  /**
   * Wraps an AES key using the RSA public key.
   */
  public wrapKey(aesKey: Buffer): Buffer {
    return this.keyManager.wrapKey(aesKey);
  }

  /**
   * Unwraps an AES key using the RSA private key.
   */
  public unwrapKey(wrappedAesKey: Buffer): Buffer {
    return this.keyManager.unwrapKey(wrappedAesKey);
  }

  /**
   * Computes SHA-256 hash of a buffer or string.
   */
  public calculateSha256(data: Buffer | string): string {
    return calculateSha256(data);
  }

  /**
   * Timing-safe verification of two SHA-256 hashes.
   */
  public verifyIntegrity(actualHash: string, expectedHash: string): boolean {
    return timingSafeCompareHashes(actualHash, expectedHash);
  }

  // ==========================================
  // Core Workflow: Encrypt & Store
  // ==========================================

  /**
   * Encrypts a validated file and stores it in encrypted permanent storage.
   *
   * Workflow:
   * 1. Validates file data and enforces 50MB limit.
   * 2. Re-verifies upload SHA-256 integrity before encryption.
   * 3. Generates a fresh cryptographically random 256-bit AES key.
   * 4. Generates a fresh unique 96-bit IV/nonce.
   * 5. Encrypts file using AES-256-GCM.
   * 6. Extracts 128-bit authentication tag.
   * 7. Wraps AES key with RSA-OAEP public key.
   * 8. Writes encrypted blob to storage (<scanId>.enc).
   * 9. Returns EncryptedFileRecord matching PostgreSQL schema.
   *
   * @throws CryptoError if validation, encryption, or storage fails.
   */
  public async encryptAndStore(input: EncryptAndStoreInput): Promise<EncryptedFileRecord> {
    const { scanId, fileData, originalSha256 } = input;

    if (!scanId || typeof scanId !== 'string') {
      throw new CryptoError('Invalid scanId provided for encryption.', 'CIPHERGUARD_INVALID_INPUT', 400);
    }
    if (!originalSha256 || originalSha256.length !== 64) {
      throw new CryptoError('Invalid originalSha256 provided.', 'CIPHERGUARD_INVALID_INPUT', 400);
    }

    // 1. Resolve file buffer and enforce size limits
    let plaintextBuffer: Buffer;
    if (typeof fileData === 'string') {
      if (!fs.existsSync(fileData)) {
        throw new CryptoError(`Source file not found at path: ${fileData}`, 'CIPHERGUARD_FILE_NOT_FOUND', 404);
      }
      const stat = await fs.promises.stat(fileData);
      if (stat.size === 0) {
        throw new CryptoError('Cannot encrypt empty (0-byte) file.', 'CIPHERGUARD_EMPTY_FILE', 400);
      }
      if (stat.size > CRYPTO_CONSTANTS.MAX_FILE_SIZE_BYTES) {
        throw new CryptoError('File exceeds maximum allowable size (50MB).', 'CIPHERGUARD_FILE_TOO_LARGE', 413);
      }
      plaintextBuffer = await fs.promises.readFile(fileData);
    } else if (Buffer.isBuffer(fileData)) {
      if (fileData.length === 0) {
        throw new CryptoError('Cannot encrypt empty (0-byte) file.', 'CIPHERGUARD_EMPTY_FILE', 400);
      }
      if (fileData.length > CRYPTO_CONSTANTS.MAX_FILE_SIZE_BYTES) {
        throw new CryptoError('File exceeds maximum allowable size (50MB).', 'CIPHERGUARD_FILE_TOO_LARGE', 413);
      }
      plaintextBuffer = fileData;
    } else {
      throw new CryptoError('Invalid fileData: must be a Buffer or filePath string.', 'CIPHERGUARD_INVALID_INPUT', 400);
    }

    // 2. Verify plaintext SHA-256 before encryption to ensure data wasn't modified in transit
    const preEncryptionHash = calculateSha256(plaintextBuffer);
    if (!timingSafeCompareHashes(preEncryptionHash, originalSha256)) {
      defaultLogger.securityAlert('Pre-encryption integrity check failed: file data differs from original hash', {
        scanId,
      });
      throw new IntegrityVerificationError(originalSha256, preEncryptionHash, 'Pre-encryption integrity check failed.');
    }

    // 3. Generate unique AES-256 key & 96-bit IV
    const aesKey = this.generateAesKey();
    const iv = this.generateIv();

    let wrappedAesKey: Buffer;
    let ciphertext: Buffer;
    let tag: Buffer;

    try {
      // 4. Encrypt with AES-256-GCM
      const encResult = encryptBuffer(plaintextBuffer, aesKey, iv);
      ciphertext = encResult.ciphertext;
      tag = encResult.tag;

      // 5. Wrap AES key with RSA-OAEP
      wrappedAesKey = this.keyManager.wrapKey(aesKey);
    } finally {
      // 6. Security scrub: zero out raw AES key from memory immediately
      aesKey.fill(0);
    }

    // 7. Store encrypted blob (only ciphertext is persisted to disk)
    const storagePath = await this.storageService.storeEncryptedBlob(scanId, ciphertext);

    const record: EncryptedFileRecord = {
      id: input.fileId ?? crypto.randomUUID(),
      scanId,
      storagePath,
      wrappedAesKey,
      iv,
      gcmTag: tag,
      encryptedAt: new Date(),
    };

    defaultLogger.info('File encrypted and stored successfully', {
      scanId,
      storagePath,
      ciphertextBytes: ciphertext.length,
    });

    return record;
  }

  // ==========================================
  // Core Workflow: Decrypt & Verify
  // ==========================================

  /**
   * Decrypts an encrypted file and strictly verifies SHA-256 integrity.
   *
   * Workflow:
   * 1. Reads encrypted blob from storage.
   * 2. Unwraps AES key with RSA-OAEP private key.
   * 3. Decrypts ciphertext using AES-256-GCM (authenticating with GCM tag).
   * 4. Recalculates SHA-256 of decrypted plaintext.
   * 5. Compares against stored original hash using constant-time comparison.
   * 6. Throws IntegrityVerificationError (HTTP 409) if mismatch.
   * 7. Returns DecryptedBufferResult.
   *
   * @throws DecryptionError if GCM authentication tag verification fails.
   * @throws IntegrityVerificationError if decrypted SHA-256 does not match original hash.
   */
  public async decryptAndVerify(options: DecryptAndVerifyOptions): Promise<DecryptedBufferResult> {
    const { storagePath, wrappedAesKey, iv, gcmTag, expectedSha256 } = options;

    if (!expectedSha256 || expectedSha256.length !== 64) {
      throw new CryptoError('Invalid expectedSha256 provided for verification.', 'CIPHERGUARD_INVALID_INPUT', 400);
    }

    // 1. Read encrypted blob
    const ciphertext = await this.storageService.readEncryptedBlob(storagePath);

    // 2. Unwrap AES key using RSA private key
    const rawAesKey = this.keyManager.unwrapKey(wrappedAesKey);

    let decryptedPlaintext: Buffer;
    try {
      // 3. Decrypt using AES-256-GCM (this verifies GCM auth tag)
      decryptedPlaintext = decryptBuffer({
        ciphertext,
        key: rawAesKey,
        iv,
        tag: gcmTag,
      });
    } finally {
      // Security scrub: zero out raw AES key from memory immediately
      rawAesKey.fill(0);
    }

    // 4. Recalculate SHA-256 hash of decrypted bytes
    const recalculatedHash = calculateSha256(decryptedPlaintext);

    // 5. Verify against original stored hash in constant time
    if (!timingSafeCompareHashes(recalculatedHash, expectedSha256)) {
      defaultLogger.securityAlert('Integrity verification failed post-decryption: SHA-256 mismatch detected!', {
        storagePath,
        expectedHash: expectedSha256,
        actualHash: recalculatedHash,
      });
      // Zero out decrypted plaintext before throwing
      decryptedPlaintext.fill(0);
      throw new IntegrityVerificationError(expectedSha256, recalculatedHash);
    }

    defaultLogger.info('Decryption and SHA-256 integrity verification succeeded', {
      storagePath,
      verifiedHash: recalculatedHash,
      bytes: decryptedPlaintext.length,
    });

    return {
      plaintext: decryptedPlaintext,
      verifiedSha256: recalculatedHash,
      isVerified: true,
    };
  }

  /**
   * Decrypts, verifies integrity, and provides a stream with guaranteed temporary-file cleanup.
   * Useful for Member 2 to stream the decrypted file to the HTTP response without holding 50MB in RAM.
   */
  public async decryptAndVerifyStream(options: DecryptAndVerifyOptions): Promise<DecryptedStreamResult> {
    // Perform standard verified decryption
    const result = await this.decryptAndVerify(options);

    // Store in secure temporary file for streaming with guaranteed cleanup
    const trackedTemp = await this.tempFileManager.createTrackedTempFile({
      prefix: 'cg_dl_',
      ext: '.dec',
      initialData: result.plaintext,
    });

    const stream = fs.createReadStream(trackedTemp.path);

    // Auto-cleanup on stream close, end, or error
    let cleaned = false;
    const safeCleanup = async (): Promise<void> => {
      if (cleaned) return;
      cleaned = true;
      if (!stream.destroyed) {
        stream.destroy();
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
      await trackedTemp.cleanup();
    };

    stream.on('close', () => {
      void safeCleanup();
    });
    stream.on('error', () => {
      void safeCleanup();
    });

    return {
      stream,
      verifiedSha256: result.verifiedSha256,
      contentLength: result.plaintext.length,
      cleanup: safeCleanup,
    };
  }

  // ==========================================
  // Storage Management
  // ==========================================

  /**
   * Permanently deletes an encrypted file from storage.
   * Per SRS BR-5: Deleting a scan record permanently deletes the encrypted blob.
   */
  public async deleteEncryptedFile(storagePathOrFileId: string): Promise<void> {
    await this.storageService.deleteEncryptedBlob(storagePathOrFileId);
  }

  /**
   * Checks if an encrypted file exists in storage.
   */
  public async encryptedFileExists(storagePathOrFileId: string): Promise<boolean> {
    return this.storageService.exists(storagePathOrFileId);
  }

  /**
   * Retrieves raw encrypted blob (e.g. for backup or migration).
   */
  public async getEncryptedFile(storagePathOrFileId: string): Promise<Buffer> {
    return this.storageService.readEncryptedBlob(storagePathOrFileId);
  }

  /**
   * Audits storage security to confirm no plaintext files exist in permanent storage.
   */
  public auditStorageSecurity(): { isCompliant: boolean; illegalFiles: string[] } {
    return this.storageService.auditStorageSecurity();
  }

  /**
   * Cleans up orphaned temporary files in the temporary directory.
   */
  public async sweepTempDirectory(): Promise<number> {
    return this.tempFileManager.sweepTempDirectory();
  }
}
