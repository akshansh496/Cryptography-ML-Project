import fs from "fs/promises";
import path from "path";
import { config } from "../config";
import { SecureFileService } from "./secure-file.service.js";
import { calculateSha256 } from "../crypto/hash.js";
import { decryptBuffer } from "../crypto/aes.js";

export interface StoredFileInfo {
  storagePath: string; // internal only, never sent to the client
  wrappedAesKey?: Buffer;
  iv?: Buffer;
  gcmTag?: Buffer;
}

let secureFileServiceInstance: SecureFileService | null = null;

export function getSecureFileService(): SecureFileService {
  if (!secureFileServiceInstance) {
    secureFileServiceInstance = new SecureFileService();
  }
  return secureFileServiceInstance;
}

/**
 * Encrypts raw file using AES-256-GCM, wraps the unique AES key with RSA-OAEP,
 * security-scrubs raw keys from memory, and persists ciphertext to secure vault.
 */
export async function storeFile(
  scanId: string,
  plain: Buffer,
  originalSha256?: string
): Promise<StoredFileInfo> {
  const service = getSecureFileService();
  const hash = originalSha256 ?? calculateSha256(plain);
  const record = await service.encryptAndStore({
    scanId,
    fileData: plain,
    originalSha256: hash,
  });

  return {
    storagePath: record.storagePath,
    wrappedAesKey: record.wrappedAesKey,
    iv: record.iv,
    gcmTag: record.gcmTag,
  };
}

/**
 * Decrypts file from secure vault using RSA-OAEP unwrap and AES-256-GCM authenticated
 * decryption, then re-verifies SHA-256 integrity against the expected hash.
 */
export async function loadFile(info: StoredFileInfo, expectedSha256?: string): Promise<Buffer> {
  if (info.wrappedAesKey && info.iv && info.gcmTag) {
    const service = getSecureFileService();
    if (expectedSha256) {
      const result = await service.decryptAndVerify({
        storagePath: info.storagePath,
        wrappedAesKey: info.wrappedAesKey,
        iv: info.iv,
        gcmTag: info.gcmTag,
        expectedSha256,
      });
      return result.plaintext;
    }

    // Decrypt without verification if no expected hash was provided
    const ciphertext = await service.getEncryptedFile(info.storagePath);
    const key = service.unwrapKey(info.wrappedAesKey);
    try {
      return decryptBuffer({
        ciphertext,
        key,
        iv: info.iv,
        tag: info.gcmTag,
      });
    } finally {
      key.fill(0);
    }
  }

  // Fallback for unencrypted legacy/test files if any exist without crypto metadata
  const fullPath = path.isAbsolute(info.storagePath)
    ? info.storagePath
    : path.join(config.storageDir, info.storagePath);
  return fs.readFile(fullPath);
}

/**
 * Deletes encrypted file blob from storage vault.
 */
export async function deleteFile(storagePath: string): Promise<void> {
  const service = getSecureFileService();
  try {
    await service.deleteEncryptedFile(storagePath);
  } catch {
    const fullPath = path.isAbsolute(storagePath)
      ? storagePath
      : path.join(config.storageDir, storagePath);
    await fs.rm(fullPath, { force: true });
  }
}
