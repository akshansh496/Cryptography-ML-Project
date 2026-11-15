import fs from "fs/promises";
import path from "path";
import { config } from "../config";

/*
 * ============================================================
 *  TEMPORARY STORAGE  --  Member 3 replaces the inside of this file
 * ============================================================
 * Member 2 (backend) only calls these three functions.
 * Member 3 will make them do:
 *    storeFile  -> AES-256-GCM encrypt -> RSA-OAEP wrap key -> write ciphertext
 *    loadFile   -> unwrap key -> decrypt -> return plaintext Buffer
 *    deleteFile -> remove ciphertext
 * and fill wrappedAesKey / iv / gcmTag.
 *
 * !!! Right now (before Member 3 merges) files are saved WITHOUT encryption. !!!
 * Keep the function signatures the same and nothing else in the backend changes.
 */

export interface StoredFileInfo {
  storagePath: string; // internal only, never sent to the client
  wrappedAesKey?: Buffer;
  iv?: Buffer;
  gcmTag?: Buffer;
}

// Path is built only from the scan UUID -> no user input in the path (no traversal)
function pathFor(scanId: string): string {
  return path.join(config.storageDir, `${scanId}.bin`);
}

export async function storeFile(scanId: string, plain: Buffer): Promise<StoredFileInfo> {
  await fs.mkdir(config.storageDir, { recursive: true });
  const storagePath = pathFor(scanId);
  await fs.writeFile(storagePath, plain, { mode: 0o600 });
  return { storagePath };
}

export async function loadFile(info: StoredFileInfo): Promise<Buffer> {
  return fs.readFile(info.storagePath);
}

export async function deleteFile(storagePath: string): Promise<void> {
  await fs.rm(storagePath, { force: true });
}
