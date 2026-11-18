/**
 * CipherGuard AI - Secure Temporary File Manager
 * Member 3: Cryptography & Secure Storage
 *
 * Requirements (Prompt Section 6, Architecture §7):
 * - Decrypted files must NEVER remain permanently on disk.
 * - Store temporary files only in dedicated, non-public directory (storage/temp/).
 * - Generate unpredictable cryptographically random filenames.
 * - Guarantee cleanup on both success and error paths (try/finally).
 * - Secure zero-wiping before unlinking to eliminate sensitive remnants.
 * - Never log sensitive temporary file paths or contents.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { TemporaryFileError } from '../errors/crypto.errors.js';
import { defaultLogger } from './logger.js';

export interface SecureTempFileOptions {
  prefix?: string;
  ext?: string;
  initialData?: Buffer;
  tempDir?: string;
}

export interface TrackedTempFile {
  path: string;
  cleanup: () => Promise<void>;
}

export class SecureTempFileManager {
  private readonly tempDir: string;

  constructor(tempDir = path.resolve(process.cwd(), 'storage', 'temp')) {
    this.tempDir = path.resolve(tempDir);
    this.ensureTempDir();
  }

  private ensureTempDir(): void {
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Generates a cryptographically random, unpredictable temporary filename.
   */
  public generateTempPath(prefix = 'cg_tmp_', ext = '.tmp'): string {
    const randomHex = crypto.randomBytes(16).toString('hex');
    const filename = `${prefix}${randomHex}${ext}`;
    return path.join(this.tempDir, filename);
  }

  /**
   * Securely overwrites a temporary file with zeroes before unlinking.
   */
  public async secureDelete(filePath: string): Promise<void> {
    if (!fs.existsSync(filePath)) {
      return;
    }

    try {
      const stats = await fs.promises.stat(filePath);
      if (stats.isFile() && stats.size > 0) {
        // Zero-fill file to prevent forensic data recovery
        const zeroBuf = Buffer.alloc(Math.min(stats.size, 64 * 1024), 0);
        let bytesRemaining = stats.size;
        const handle = await fs.promises.open(filePath, 'r+');
        try {
          let position = 0;
          while (bytesRemaining > 0) {
            const toWrite = Math.min(bytesRemaining, zeroBuf.length);
            await handle.write(zeroBuf, 0, toWrite, position);
            position += toWrite;
            bytesRemaining -= toWrite;
          }
          await handle.sync();
        } finally {
          await handle.close();
        }
      }
    } catch {
      // If wiping fails due to handle locking, proceed to unlink attempt
    }

    // Unlink with retry for Windows file handle release
    let retries = 5;
    while (retries > 0) {
      try {
        await fs.promises.unlink(filePath);
        return;
      } catch (err: unknown) {
        const nodeErr = err as { code?: string };
        if (nodeErr.code === 'ENOENT') {
          // File already unlinked
          return;
        }
        if ((nodeErr.code === 'EBUSY' || nodeErr.code === 'EPERM') && retries > 1) {
          retries--;
          await new Promise((resolve) => setTimeout(resolve, 30));
          continue;
        }
        defaultLogger.error('Failed to unlink temporary file', {
          error: err instanceof Error ? err.message : String(err),
        });
        throw new TemporaryFileError('Failed to remove temporary file.', err);
      }
    }
  }

  /**
   * Creates a tracked temporary file with an explicit cleanup closure.
   */
  public async createTrackedTempFile(options?: SecureTempFileOptions): Promise<TrackedTempFile> {
    const tempPath = this.generateTempPath(options?.prefix, options?.ext);

    if (options?.initialData) {
      await fs.promises.writeFile(tempPath, options.initialData, { mode: 0o600 });
    } else {
      await fs.promises.writeFile(tempPath, Buffer.alloc(0), { mode: 0o600 });
    }

    let isCleanedUp = false;
    let cleaningPromise: Promise<void> | null = null;

    const cleanup = async (): Promise<void> => {
      if (isCleanedUp) return;
      if (cleaningPromise) return cleaningPromise;

      cleaningPromise = (async () => {
        try {
          await this.secureDelete(tempPath);
        } finally {
          isCleanedUp = true;
          cleaningPromise = null;
        }
      })();

      return cleaningPromise;
    };

    return {
      path: tempPath,
      cleanup,
    };
  }

  /**
   * Higher-order execution block guaranteeing cleanup regardless of success or throw.
   */
  public async withSecureTempFile<T>(
    options: SecureTempFileOptions,
    callback: (tempPath: string) => Promise<T>
  ): Promise<T> {
    const tracked = await this.createTrackedTempFile(options);
    try {
      return await callback(tracked.path);
    } finally {
      await tracked.cleanup();
    }
  }

  /**
   * Cleans up all orphaned temporary files in the temp directory.
   */
  public async sweepTempDirectory(): Promise<number> {
    if (!fs.existsSync(this.tempDir)) return 0;

    const entries = await fs.promises.readdir(this.tempDir);
    let count = 0;

    for (const entry of entries) {
      if (entry === '.gitkeep') continue;
      const fullPath = path.join(this.tempDir, entry);
      try {
        await this.secureDelete(fullPath);
        count++;
      } catch {
        // Continue sweeping remaining files
      }
    }

    return count;
  }
}
