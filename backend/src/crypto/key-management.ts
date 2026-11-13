/**
 * CipherGuard AI - Key Management Service
 * Member 3: Cryptography & Secure Storage
 *
 * Requirements (SRS FR-7, Architecture §3.6, §7):
 * - Key envelope manager: handles loading, caching, and accessing RSA keys.
 * - Public key used for wrapping AES keys on upload.
 * - Private key used ONLY for unwrapping AES keys on authorized download.
 * - NEVER log private keys or raw AES keys.
 * - NEVER store private key in PostgreSQL database.
 * - In production: keys must be provided via environment / secrets manager.
 * - In development / testing: supports loading from gitignored paths or ephemeral key pairs.
 */

import fs from 'node:fs';
import { CRYPTO_CONSTANTS, loadCryptoConfig } from '../config/crypto.config.js';
import { KeyConfigurationError } from '../errors/crypto.errors.js';
import type { KeyManagerConfig, RsaKeyPair } from '../types/crypto.types.js';
import { defaultLogger } from '../utils/logger.js';
import { generateRsaKeyPair, unwrapAesKey, validateRsaPrivateKey, validateRsaPublicKey, wrapAesKey } from './rsa.js';

export class KeyManager {
  private publicKeyPem: string | null = null;
  private privateKeyPem: string | null = null;
  private readonly config: KeyManagerConfig;

  constructor(config?: KeyManagerConfig) {
    this.config = config ?? {};
    this.initializeKeys();
  }

  private initializeKeys(): void {
    const envConfig = loadCryptoConfig();

    // 1. Resolve Public Key
    if (this.config.rsaPublicKeyPem) {
      this.publicKeyPem = this.config.rsaPublicKeyPem.trim();
    } else if (this.config.rsaPublicKeyPath && fs.existsSync(this.config.rsaPublicKeyPath)) {
      this.publicKeyPem = fs.readFileSync(this.config.rsaPublicKeyPath, 'utf8').trim();
    } else if (envConfig.rsaPublicKeyPem) {
      this.publicKeyPem = envConfig.rsaPublicKeyPem.trim();
    } else if (envConfig.rsaPublicKeyPath && fs.existsSync(envConfig.rsaPublicKeyPath)) {
      this.publicKeyPem = fs.readFileSync(envConfig.rsaPublicKeyPath, 'utf8').trim();
    }

    // 2. Resolve Private Key
    if (this.config.rsaPrivateKeyPem) {
      this.privateKeyPem = this.config.rsaPrivateKeyPem.trim();
    } else if (this.config.rsaPrivateKeyPath && fs.existsSync(this.config.rsaPrivateKeyPath)) {
      this.privateKeyPem = fs.readFileSync(this.config.rsaPrivateKeyPath, 'utf8').trim();
    } else if (envConfig.rsaPrivateKeyPem) {
      this.privateKeyPem = envConfig.rsaPrivateKeyPem.trim();
    } else if (envConfig.rsaPrivateKeyPath && fs.existsSync(envConfig.rsaPrivateKeyPath)) {
      this.privateKeyPem = fs.readFileSync(envConfig.rsaPrivateKeyPath, 'utf8').trim();
    }

    // 3. Fallback for Dev/Test if allowed
    const allowDevFallback = this.config.allowEphemeralDevKeys ?? envConfig.allowEphemeralDevKeys;

    if ((!this.publicKeyPem || !this.privateKeyPem) && allowDevFallback) {
      defaultLogger.warn(
        'No RSA key pair configured via environment. Generating ephemeral RSA-4096 development key pair.'
      );
      const generated = generateRsaKeyPair(CRYPTO_CONSTANTS.DEFAULT_RSA_MODULUS_BITS);
      this.publicKeyPem = generated.publicKey;
      this.privateKeyPem = generated.privateKey;
    }

    // 4. Validate Public Key if present
    if (this.publicKeyPem) {
      validateRsaPublicKey(this.publicKeyPem, this.config.minRsaModulusBits ?? CRYPTO_CONSTANTS.MIN_RSA_MODULUS_BITS);
    } else {
      throw new KeyConfigurationError(
        'RSA Public Key is not configured. Set CIPHERGUARD_RSA_PUBLIC_KEY or CIPHERGUARD_RSA_PUBLIC_KEY_PATH.'
      );
    }

    // 5. Validate Private Key if present
    if (this.privateKeyPem) {
      validateRsaPrivateKey(this.privateKeyPem, this.config.minRsaModulusBits ?? CRYPTO_CONSTANTS.MIN_RSA_MODULUS_BITS);
    }
  }

  /**
   * Retrieves the configured RSA public key (SPKI PEM format).
   */
  public getPublicKey(): string {
    if (!this.publicKeyPem) {
      throw new KeyConfigurationError('RSA public key is not available.');
    }
    return this.publicKeyPem;
  }

  /**
   * Retrieves the configured RSA private key (PKCS#8 PEM format).
   * Throws if private key is not configured (e.g. on an encryption-only worker).
   */
  public getPrivateKey(): string {
    if (!this.privateKeyPem) {
      throw new KeyConfigurationError(
        'RSA private key is not configured on this node. Unwrapping AES keys is not permitted.'
      );
    }
    return this.privateKeyPem;
  }

  /**
   * Checks whether the private key is configured on this instance.
   */
  public hasPrivateKey(): boolean {
    return this.privateKeyPem !== null;
  }

  /**
   * Wraps an AES-256 key using the loaded RSA public key.
   */
  public wrapKey(aesKey: Buffer): Buffer {
    return wrapAesKey(aesKey, this.getPublicKey());
  }

  /**
   * Unwraps an AES-256 key using the loaded RSA private key.
   */
  public unwrapKey(wrappedAesKey: Buffer): Buffer {
    return unwrapAesKey(wrappedAesKey, this.getPrivateKey());
  }

  /**
   * Updates key pair (e.g. for testing key rotation per SRS SEC-5).
   */
  public setKeyPair(keyPair: RsaKeyPair): void {
    validateRsaPublicKey(keyPair.publicKey);
    validateRsaPrivateKey(keyPair.privateKey);
    this.publicKeyPem = keyPair.publicKey;
    this.privateKeyPem = keyPair.privateKey;
    defaultLogger.info('KeyManager key pair rotated successfully.');
  }
}
