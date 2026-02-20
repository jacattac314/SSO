/**
 * Cryptographic utilities – AES-256-GCM encryption for tenant secrets,
 * SHA-256 hashing, and secure random generation.
 */
import crypto from 'crypto';
import { config } from '../config';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;  // 96-bit IV for GCM
const TAG_LENGTH = 16; // 128-bit auth tag
const KEY_LENGTH = 32; // 256-bit key

function getEncryptionKey(): Buffer {
  const hex = config.TENANT_SECRET_ENCRYPTION_KEY;
  if (hex.length !== 64) {
    throw new Error('TENANT_SECRET_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypts plaintext using AES-256-GCM.
 * Returns base64-encoded `iv:tag:ciphertext`.
 */
export function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

/**
 * Decrypts a base64-encoded `iv:tag:ciphertext` produced by `encrypt`.
 */
export function decrypt(ciphertext: string): string {
  const key = getEncryptionKey();
  const buf = Buffer.from(ciphertext, 'base64');
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = buf.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

/** Returns hex-encoded SHA-256 hash. */
export function sha256(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/** Constant-time string comparison (prevents timing attacks). */
export function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still do comparison to prevent timing leak on length
    crypto.timingSafeEqual(Buffer.alloc(1), Buffer.alloc(1));
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Generates a cryptographically secure random token (hex). */
export function generateToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

/** Generates a cryptographically secure random token (base64url). */
export function generateBase64Token(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Generates a PKCE code verifier (base64url, 43-128 chars per RFC 7636). */
export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/** Generates a PKCE code challenge (S256 method). */
export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

/** Returns fingerprint of a PEM certificate (SHA-256, colon-separated hex). */
export function certFingerprint(pemCert: string): string {
  // Strip PEM headers and decode base64
  const b64 = pemCert
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s/g, '');
  const der = Buffer.from(b64, 'base64');
  return crypto
    .createHash('sha256')
    .update(der)
    .digest('hex')
    .match(/.{2}/g)!
    .join(':')
    .toUpperCase();
}

/** Parses certificate expiry date from PEM (requires node-forge in caller for full parsing). */
export function parseCertExpiry(pemCert: string): Date | null {
  try {
    // Basic extraction from ASN.1 – for production use node-forge
    const forge = require('node-forge') as typeof import('node-forge');
    const cert = forge.pki.certificateFromPem(pemCert);
    return cert.validity.notAfter;
  } catch {
    return null;
  }
}

/** Generates a self-signed certificate for testing/development. */
export function generateSelfSignedCert(
  commonName: string,
  days = 365
): { cert: string; privateKey: string } {
  const forge = require('node-forge') as typeof import('node-forge');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  const attrs = [{ name: 'commonName', value: commonName }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    cert: forge.pki.certificateToPem(cert),
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
  };
}
