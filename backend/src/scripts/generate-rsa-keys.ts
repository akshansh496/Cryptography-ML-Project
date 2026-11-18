/**
 * CipherGuard AI - RSA Key Pair Generator Utility
 * Member 3: Cryptography & Secure Storage
 *
 * Generates production-ready 4096-bit (or 2048-bit) RSA key pairs.
 * Used for development setup and secret provisioning.
 *
 * Security Warning:
 * - NEVER commit the generated private key to git.
 * - Store the private key in AWS Secrets Manager, HashiCorp Vault, or gitignored .env.
 */

import fs from 'node:fs';
import path from 'node:path';
import { generateRsaKeyPair } from '../crypto/rsa.js';

function run(): void {
  const bits = process.argv.includes('--2048') ? 2048 : 4096;
  console.log(`Generating ${bits}-bit RSA key pair for CipherGuard AI envelope encryption...`);

  const { publicKey, privateKey } = generateRsaKeyPair(bits);

  const secretsDir = path.resolve(process.cwd(), 'secrets');
  if (!fs.existsSync(secretsDir)) {
    fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  }

  const pubPath = path.join(secretsDir, 'rsa_public.pem');
  const privPath = path.join(secretsDir, 'rsa_private.pem');

  fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });
  fs.writeFileSync(privPath, privateKey, { mode: 0o600 });

  console.log('✅ RSA key pair generated successfully!');
  console.log(`Public Key saved to:  ${pubPath}`);
  console.log(`Private Key saved to: ${privPath}`);
  console.log('\nAdd these paths to your .env:');
  console.log(`CIPHERGUARD_RSA_PUBLIC_KEY_PATH=${pubPath}`);
  console.log(`CIPHERGUARD_RSA_PRIVATE_KEY_PATH=${privPath}`);
  console.log('\n⚠️ SECURITY REMINDER: Ensure secrets/ directory is listed in .gitignore.');
}

run();
