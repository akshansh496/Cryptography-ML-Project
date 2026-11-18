/**
 * CipherGuard AI - Cryptographic & Secure Storage Error Hierarchy
 * Member 3: Cryptography & Secure Storage
 *
 * Security Requirements:
 * - Never expose internal crypto details, private filesystem paths, or key material in error messages.
 * - Provide clear typed errors for Member 2's Express error-handling middleware.
 * - Include HTTP status code mappings (e.g. 409 Conflict for integrity mismatches).
 */

/**
 * Base error for all CipherGuard cryptographic operations.
 */
export class CryptoError extends Error {
  public readonly statusCode: number;
  public readonly errorCode: string;
  public readonly isSecurityAlert: boolean;

  constructor(
    message: string,
    errorCode = 'CIPHERGUARD_CRYPTO_ERROR',
    statusCode = 500,
    isSecurityAlert = false
  ) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.isSecurityAlert = isSecurityAlert;

    // Maintain proper stack trace in V8
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Safe serialization for client response (never leaks internal stack or keys).
   */
  public toClientResponse(): { error: string; code: string } {
    return {
      error: this.message,
      code: this.errorCode
    };
  }
}

/**
 * Thrown when AES-256-GCM encryption fails.
 */
export class EncryptionError extends CryptoError {
  constructor(message = 'Failed to encrypt file data.', cause?: unknown) {
    super(message, 'CIPHERGUARD_ENCRYPTION_FAILED', 500, false);
    if (cause) {
      this.cause = cause;
    }
  }
}

/**
 * Thrown when AES-256-GCM decryption fails, including authentication tag mismatch.
 */
export class DecryptionError extends CryptoError {
  constructor(
    message = 'Decryption failed: corrupted ciphertext or authentication tag mismatch.',
    cause?: unknown
  ) {
    super(message, 'CIPHERGUARD_DECRYPTION_FAILED', 400, true);
    if (cause) {
      this.cause = cause;
    }
  }
}

/**
 * Thrown when RSA-OAEP wrapping of an AES key fails.
 */
export class KeyWrapError extends CryptoError {
  constructor(message = 'Failed to wrap symmetric AES key with RSA public key.', cause?: unknown) {
    super(message, 'CIPHERGUARD_KEY_WRAP_FAILED', 500, false);
    if (cause) {
      this.cause = cause;
    }
  }
}

/**
 * Thrown when RSA-OAEP unwrapping of an AES key fails.
 */
export class KeyUnwrapError extends CryptoError {
  constructor(
    message = 'Failed to unwrap symmetric AES key. Invalid key or unauthorized access.',
    cause?: unknown
  ) {
    super(message, 'CIPHERGUARD_KEY_UNWRAP_FAILED', 400, true);
    if (cause) {
      this.cause = cause;
    }
  }
}

/**
 * Thrown when SHA-256 hash recalculation does not match the original hash stored in PostgreSQL.
 * Per SRS FR-9.2 and SRS §8:
 * Scenario: Hash mismatch on download -> HTTP Status: 409 -> Behavior: "File integrity check failed" + security log entry.
 */
export class IntegrityVerificationError extends CryptoError {
  public readonly expectedHash: string;
  public readonly actualHash: string;

  constructor(
    expectedHash: string,
    actualHash: string,
    message = 'File integrity check failed: decrypted data does not match the original recorded SHA-256 hash.'
  ) {
    super(message, 'CIPHERGUARD_INTEGRITY_MISMATCH', 409, true);
    this.expectedHash = expectedHash;
    this.actualHash = actualHash;
  }
}

/**
 * Thrown when encrypted storage operations (save, read, delete, path validation) fail.
 */
export class EncryptedStorageError extends CryptoError {
  constructor(message: string, statusCode = 500, cause?: unknown) {
    super(message, 'CIPHERGUARD_STORAGE_ERROR', statusCode, false);
    if (cause) {
      this.cause = cause;
    }
  }
}

/**
 * Thrown when secure temporary file creation, writing, or cleanup fails.
 */
export class TemporaryFileError extends CryptoError {
  constructor(message: string, cause?: unknown) {
    super(message, 'CIPHERGUARD_TEMP_FILE_ERROR', 500, false);
    if (cause) {
      this.cause = cause;
    }
  }
}

/**
 * Thrown when RSA key configuration (public or private key) is missing, corrupt, or insufficient length.
 */
export class KeyConfigurationError extends CryptoError {
  constructor(message: string) {
    super(message, 'CIPHERGUARD_KEY_CONFIG_ERROR', 500, false);
  }
}
