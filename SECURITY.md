# CipherGuard AI - Cryptographic Security Policy

**Scope:** Cryptography, Key Management & Secure File Storage  
**Author:** Member 3 (Cryptography & Secure Storage)

---

## 1. Security Foundations

CipherGuard AI uses defense-in-depth principles to protect analyzed binaries:

1. **AES-256-GCM (Galois/Counter Mode):**
   - Provides **confidentiality** and **authenticated encryption** (AEAD).
   - Generates a **unique cryptographically secure 256-bit AES key** per file (`crypto.randomBytes(32)`).
   - Generates a **unique 96-bit IV/nonce** per encryption operation (`crypto.randomBytes(12)`).
   - **Zero IV reuse:** An IV is never reused with the same AES key.
   - Extracts and strictly validates a **128-bit (16-byte) GCM authentication tag** on every decryption attempt.

2. **RSA-OAEP (Optimal Asymmetric Encryption Padding):**
   - Implements **envelope encryption** to protect the ephemeral per-file AES keys.
   - Minimum key length: **2048-bit**; Recommended production standard: **4096-bit**.
   - Hashing algorithm: **SHA-256**.
   - The **RSA Public Key** is used exclusively to wrap symmetric keys.
   - The **RSA Private Key** is used exclusively for authorized decryption during downloads.
   - **CRITICAL RULE:** The RSA private key **MUST remain outside the database and source control**. It must be injected via a secrets manager (AWS Secrets Manager, HashiCorp Vault) or local gitignored secrets files.

3. **SHA-256 Integrity Verification:**
   - Provides cryptographic integrity verification against the original uploaded file.
   - Computed immediately upon upload and stored in PostgreSQL (`scans.sha256_hash`).
   - Recalculated immediately post-decryption during authorized downloads.
   - Compared in **constant time** (`crypto.timingSafeEqual`) to eliminate side-channel timing attacks.
   - Any hash mismatch halts processing immediately, raises a security alert, and returns **HTTP 409 Conflict**. Tampered or corrupted files are never returned.

---

## 2. Secure Storage & Isolation

- **Encrypted Storage:**
  - Located in `storage/encrypted/`.
  - Stores **ONLY** AES-256-GCM ciphertext blobs (`<scanId>.enc`).
  - No plaintext files (`.exe`, `.dll`) are ever stored in permanent storage.
  - Path traversal characters (`..`, null bytes, slashes) are strictly rejected.
  - Storage is never exposed via Express static route handlers.

- **Temporary Plaintext Handling:**
  - Decrypted files never remain permanently on disk.
  - Stored only in non-public `storage/temp/` with unpredictable random names (`crypto.randomBytes(16)`).
  - Cleaned up automatically on both success and error paths using `try / finally` guarantees.
  - Overwritten with zero-buffers before file deletion to thwart forensic recovery.

---

## 3. Secret Scrubbing & Audit Logging

- **Memory Scrubbing:**
  - Raw AES key buffers and plaintext buffers are actively zero-filled (`buf.fill(0)`) immediately after encryption/decryption operations complete.
- **Log Hygiene (SRS SEC-2):**
  - Passwords, raw AES keys, RSA private keys, and file contents are strictly filtered and redacted from all log streams.
- **Audit Alerting (Architecture §9):**
  - GCM authentication failures, decryption tampering, and SHA-256 hash mismatches trigger high-severity `security_alert` structured log events.

---

## 4. Key Rotation Procedure (SRS SEC-5)

1. Generate a new RSA-4096 key pair using `npm run generate-keys`.
2. Update the environment variables `CIPHERGUARD_RSA_PUBLIC_KEY` in the backend service.
3. Keep the previous RSA private key available in key management for existing historical scans (re-wrap migration script can be run if full re-keying is desired).
4. Verify key operation with automated test suite (`npm test`).

---

## 5. Vulnerability Disclosure

To report a cryptographic or security concern in CipherGuard AI, please contact the security response team at `security@cipherguard.ai`.
