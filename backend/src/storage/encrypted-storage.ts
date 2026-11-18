/**
 * CipherGuard AI - Dedicated Encrypted Storage Service
 * Member 3: Cryptography & Secure Storage
 *
 * Requirements (SRS FR-8, Architecture §3.5):
 * - Permanent storage contains ONLY encrypted blobs (<id>.enc).
 * - Never store plaintext files (.exe, .dll) in permanent storage.
 * - Strict path-traversal prevention (reject .., null bytes, slashes in identifiers).
 * - Storage path abstraction (never leak internal physical paths to clients).
 * - Provide clean async operations: store, read, stream, delete, check existence.
 */

import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { EncryptedStorageError } from '../errors/crypto.errors.js';
import type { StorageConfig } from '../types/crypto.types.js';
import { defaultLogger } from '../utils/logger.js';

export class EncryptedStorageService {
  private readonly storageDir: string;
  private readonly maxFileSizeBytes: number;

  constructor(config: StorageConfig) {
    this.storageDir = path.resolve(config.encryptedStorageDir);
    this.maxFileSizeBytes = config.maxFileSizeBytes ?? 50 * 1024 * 1024;
    this.ensureStorageDirectory();
  }

  private ensureStorageDirectory(): void {
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Sanitizes and validates a storage identifier/path to strictly prevent path traversal.
   *
   * @param fileIdOrPath - Raw identifier or relative path (e.g. "scan-12345.enc")
   * @returns Absolute safe path inside the encrypted storage directory
   */
  public resolveSafePath(fileIdOrPath: string): string {
    if (!fileIdOrPath || typeof fileIdOrPath !== 'string') {
      throw new EncryptedStorageError('Invalid file identifier: identifier must be a non-empty string.', 400);
    }

    // Reject null bytes
    if (fileIdOrPath.includes('\0')) {
      throw new EncryptedStorageError('Invalid file identifier: null bytes detected.', 400);
    }

    // Strip any directory traversal or path separators to force basename inside storageDir
    const baseName = path.basename(fileIdOrPath.trim());
    if (baseName !== fileIdOrPath.trim() && !fileIdOrPath.endsWith('.enc')) {
      // If someone passed /etc/passwd or ../../foo, path.basename extracts 'passwd',
      // but we should strictly reject directory traversal attempts!
      if (fileIdOrPath.includes('..') || fileIdOrPath.includes('/') || fileIdOrPath.includes('\\')) {
        defaultLogger.securityAlert('Path traversal attempt detected in encrypted storage', {
          input: fileIdOrPath.substring(0, 50),
        });
        throw new EncryptedStorageError('Invalid file identifier: directory traversal detected.', 400);
      }
    }

    // Ensure valid safe filename characters (alphanumeric, dashes, underscores, dots)
    const safeFilenameRegex = /^[a-zA-Z0-9_-]+(\.enc)?$/;
    if (!safeFilenameRegex.test(baseName)) {
      throw new EncryptedStorageError(
        'Invalid file identifier: must only contain alphanumeric characters, hyphens, and underscores.',
        400
      );
    }

    const filename = baseName.endsWith('.enc') ? baseName : `${baseName}.enc`;
    const resolvedPath = path.resolve(this.storageDir, filename);

    // Verify resolved path is strictly within storageDir
    if (!resolvedPath.startsWith(this.storageDir + path.sep) && resolvedPath !== this.storageDir) {
      throw new EncryptedStorageError('Path traversal violation: target lies outside encrypted storage directory.', 403);
    }

    return resolvedPath;
  }

  /**
   * Stores an encrypted ciphertext buffer into the dedicated encrypted directory.
   *
   * @param fileId - Unique identifier (UUID or scanId)
   * @param ciphertext - The encrypted bytes
   * @returns The relative storage path (e.g. "<fileId>.enc")
   */
  public async storeEncryptedBlob(fileId: string, ciphertext: Buffer): Promise<string> {
    const fullPath = this.resolveSafePath(fileId);
    const relativeStoragePath = path.basename(fullPath);

    if (ciphertext.length > this.maxFileSizeBytes) {
      throw new EncryptedStorageError(
        `Encrypted file size (${ciphertext.length} bytes) exceeds maximum limit (${this.maxFileSizeBytes} bytes).`,
        413
      );
    }

    try {
      await fs.promises.writeFile(fullPath, ciphertext, { mode: 0o600 });
      defaultLogger.debug('Encrypted blob written to storage', { storagePath: relativeStoragePath });
      return relativeStoragePath;
    } catch (err) {
      defaultLogger.error('Failed to write encrypted blob to storage', {
        error: err instanceof Error ? err.message : String(err),
      });
      throw new EncryptedStorageError('Failed to store encrypted file on disk.', 500, err);
    }
  }

  /**
   * Stores an encrypted ciphertext stream into the dedicated encrypted directory.
   *
   * @param fileId - Unique identifier
   * @param cipherStream - Readable stream of ciphertext
   * @returns The relative storage path
   */
  public async storeEncryptedStream(fileId: string, cipherStream: Readable): Promise<string> {
    const fullPath = this.resolveSafePath(fileId);
    const relativeStoragePath = path.basename(fullPath);
    const writeStream = fs.createWriteStream(fullPath, { mode: 0o600 });

    try {
      await pipeline(cipherStream, writeStream);
      return relativeStoragePath;
    } catch (err) {
      // Cleanup broken partial file on failure
      if (fs.existsSync(fullPath)) {
        try {
          await fs.promises.unlink(fullPath);
        } catch {
          // ignore unlink error
        }
      }
      throw new EncryptedStorageError('Failed to stream encrypted file to storage.', 500, err);
    }
  }

  /**
   * Reads an encrypted blob into memory as a Buffer.
   *
   * @param fileIdOrPath - Storage identifier or path
   */
  public async readEncryptedBlob(fileIdOrPath: string): Promise<Buffer> {
    const fullPath = this.resolveSafePath(fileIdOrPath);

    if (!fs.existsSync(fullPath)) {
      throw new EncryptedStorageError('Encrypted file not found in storage.', 404);
    }

    try {
      return await fs.promises.readFile(fullPath);
    } catch (err) {
      throw new EncryptedStorageError('Failed to read encrypted file from storage.', 500, err);
    }
  }

  /**
   * Returns a readable stream of the encrypted blob.
   *
   * @param fileIdOrPath - Storage identifier or path
   */
  public getEncryptedBlobReadStream(fileIdOrPath: string): fs.ReadStream {
    const fullPath = this.resolveSafePath(fileIdOrPath);

    if (!fs.existsSync(fullPath)) {
      throw new EncryptedStorageError('Encrypted file not found in storage.', 404);
    }

    return fs.createReadStream(fullPath);
  }

  /**
   * Deletes an encrypted file from permanent storage.
   * Per SRS BR-5: Deleting a scan record permanently deletes the encrypted blob.
   */
  public async deleteEncryptedBlob(fileIdOrPath: string): Promise<void> {
    const fullPath = this.resolveSafePath(fileIdOrPath);

    if (!fs.existsSync(fullPath)) {
      // Already absent; idempotent operation
      return;
    }

    try {
      await fs.promises.unlink(fullPath);
      defaultLogger.info('Encrypted blob deleted from storage', { storagePath: path.basename(fullPath) });
    } catch (err) {
      throw new EncryptedStorageError('Failed to delete encrypted file from storage.', 500, err);
    }
  }

  /**
   * Checks if an encrypted blob exists.
   */
  public async exists(fileIdOrPath: string): Promise<boolean> {
    try {
      const fullPath = this.resolveSafePath(fileIdOrPath);
      return fs.existsSync(fullPath);
    } catch {
      return false;
    }
  }

  /**
   * Gets the byte size of an encrypted file.
   */
  public async getEncryptedFileSize(fileIdOrPath: string): Promise<number> {
    const fullPath = this.resolveSafePath(fileIdOrPath);
    try {
      const stat = await fs.promises.stat(fullPath);
      return stat.size;
    } catch (err) {
      throw new EncryptedStorageError('Failed to stat encrypted file.', 404, err);
    }
  }

  /**
   * Audits storage directory to verify no plaintext executable files are present.
   * Returns true if valid (all files end in .enc or .gitkeep).
   */
  public auditStorageSecurity(): { isCompliant: boolean; illegalFiles: string[] } {
    const entries = fs.readdirSync(this.storageDir);
    const illegalFiles = entries.filter(
      (entry) => !entry.endsWith('.enc') && entry !== '.gitkeep' && !entry.startsWith('.')
    );

    return {
      isCompliant: illegalFiles.length === 0,
      illegalFiles,
    };
  }
}
