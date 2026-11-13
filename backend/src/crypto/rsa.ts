/**
 * CipherGuard AI - RSA-OAEP Key Wrapping & Key Pair Utilities
 * Member 3: Cryptography & Secure Storage
 *
 * Requirements (SRS FR-7, Architecture §3.6, §7):
 * - Wrap (encrypt) per-file AES-256 keys using RSA-OAEP with SHA-256 digest.
 * - Support 2048-bit minimum or 4096-bit RSA (default: 4096-bit).
 * - Generate RSA key pairs using Node.js native crypto.
 * - Public key used to wrap AES keys (can be in app config/env).
 * - Private key used ONLY for unwrapping during authorized download.
 * - NEVER log the private key or raw AES key.
 * - NEVER persist the private key in PostgreSQL.
 * - Controlled errors on unwrap failure (KeyUnwrapError, KeyWrapError).
 */

import crypto from 'node:crypto';
import { CRYPTO_CONSTANTS } from '../config/crypto.config.js';
import { KeyConfigurationError, KeyUnwrapError, KeyWrapError } from '../errors/crypto.errors.js';
import type { RsaKeyPair } from '../types/crypto.types.js';
import { defaultLogger } from '../utils/logger.js';

/**
 * Generates an RSA key pair in PEM format using Node.js native crypto.
 *
 * @param modulusLength - Key size in bits (default: 4096-bit, min: 2048-bit).
 * @returns RsaKeyPair containing SPKI public key and PKCS#8 private key PEMs.
 */
export function generateRsaKeyPair(modulusLength: number = CRYPTO_CONSTANTS.DEFAULT_RSA_MODULUS_BITS): RsaKeyPair {
  if (modulusLength < CRYPTO_CONSTANTS.MIN_RSA_MODULUS_BITS) {
    throw new KeyConfigurationError(
      `RSA modulus length must be at least ${CRYPTO_CONSTANTS.MIN_RSA_MODULUS_BITS} bits. Requested: ${modulusLength} bits.`
    );
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
}

/**
 * Validates that an RSA public key PEM string is well-formed and meets the minimum bit length.
 */
export function validateRsaPublicKey(publicKeyPem: string, minBits: number = CRYPTO_CONSTANTS.MIN_RSA_MODULUS_BITS): void {
  try {
    const keyObject = crypto.createPublicKey(publicKeyPem);
    if (keyObject.asymmetricKeyType !== 'rsa') {
      throw new KeyConfigurationError(`Invalid key type: expected RSA, got ${keyObject.asymmetricKeyType}.`);
    }
    const details = keyObject.asymmetricKeyDetails;
    if (details?.modulusLength && details.modulusLength < minBits) {
      throw new KeyConfigurationError(
        `RSA public key modulus is too short: ${details.modulusLength} bits (minimum required: ${minBits} bits).`
      );
    }
  } catch (err) {
    if (err instanceof KeyConfigurationError) throw err;
    throw new KeyConfigurationError(`Failed to parse RSA public key PEM: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Validates that an RSA private key PEM string is well-formed and meets the minimum bit length.
 */
export function validateRsaPrivateKey(privateKeyPem: string, minBits: number = CRYPTO_CONSTANTS.MIN_RSA_MODULUS_BITS): void {
  try {
    const keyObject = crypto.createPrivateKey(privateKeyPem);
    if (keyObject.asymmetricKeyType !== 'rsa') {
      throw new KeyConfigurationError(`Invalid key type: expected RSA, got ${keyObject.asymmetricKeyType}.`);
    }
    const details = keyObject.asymmetricKeyDetails;
    if (details?.modulusLength && details.modulusLength < minBits) {
      throw new KeyConfigurationError(
        `RSA private key modulus is too short: ${details.modulusLength} bits (minimum required: ${minBits} bits).`
      );
    }
  } catch (err) {
    if (err instanceof KeyConfigurationError) throw err;
    throw new KeyConfigurationError(`Failed to parse RSA private key PEM: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Wraps (encrypts) a symmetric AES-256 key using RSA-OAEP with SHA-256.
 *
 * @param aesKey - 256-bit AES key Buffer (32 bytes)
 * @param publicKeyPem - RSA public key in PEM format
 * @returns Wrapped AES key as a Buffer
 */
export function wrapAesKey(aesKey: Buffer, publicKeyPem: string): Buffer {
  if (!Buffer.isBuffer(aesKey) || aesKey.length !== CRYPTO_CONSTANTS.AES_KEY_LENGTH_BYTES) {
    throw new KeyWrapError(
      `Invalid AES key size for wrapping: expected ${CRYPTO_CONSTANTS.AES_KEY_LENGTH_BYTES} bytes, got ${aesKey?.length ?? 0} bytes.`
    );
  }

  validateRsaPublicKey(publicKeyPem);

  try {
    const wrappedKey = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: CRYPTO_CONSTANTS.RSA_OAEP_HASH,
      },
      aesKey
    );

    return wrappedKey;
  } catch (err) {
    defaultLogger.error('RSA-OAEP key wrapping failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    throw new KeyWrapError('Failed to wrap AES key using RSA-OAEP.', err);
  }
}

/**
 * Unwraps (decrypts) an RSA-OAEP wrapped AES-256 key using the RSA private key.
 *
 * @param wrappedAesKey - The wrapped AES key Buffer
 * @param privateKeyPem - RSA private key in PEM format
 * @returns Unwrapped 256-bit AES key Buffer (32 bytes)
 */
export function unwrapAesKey(wrappedAesKey: Buffer, privateKeyPem: string): Buffer {
  if (!Buffer.isBuffer(wrappedAesKey) || wrappedAesKey.length === 0) {
    throw new KeyUnwrapError('Wrapped AES key is missing or empty.');
  }

  validateRsaPrivateKey(privateKeyPem);

  try {
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: CRYPTO_CONSTANTS.RSA_OAEP_HASH,
      },
      wrappedAesKey
    );

    if (aesKey.length !== CRYPTO_CONSTANTS.AES_KEY_LENGTH_BYTES) {
      // Securely scrub key buffer before throwing
      aesKey.fill(0);
      throw new KeyUnwrapError(
        `Unwrapped AES key length mismatch: expected ${CRYPTO_CONSTANTS.AES_KEY_LENGTH_BYTES} bytes, got ${aesKey.length} bytes.`
      );
    }

    return aesKey;
  } catch (err) {
    defaultLogger.securityAlert('RSA-OAEP key unwrapping failed: unauthorized key or corrupted wrapped key payload.', {
      error: err instanceof Error ? err.message : String(err),
    });
    if (err instanceof KeyUnwrapError) throw err;
    throw new KeyUnwrapError('Failed to unwrap AES key: invalid key or corrupted wrapped data.', err);
  }
}
