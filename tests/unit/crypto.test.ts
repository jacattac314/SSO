/**
 * Unit tests for cryptographic utilities.
 */
import { encrypt, decrypt, sha256, safeCompare, generateToken, generateCodeVerifier, generateCodeChallenge, certFingerprint } from '../../src/utils/crypto';

// Set a valid 64-char hex encryption key for tests
process.env.TENANT_SECRET_ENCRYPTION_KEY = 'a'.repeat(64);

describe('Crypto utilities', () => {
  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt a string', () => {
      const plaintext = 'my-secret-client-secret';
      const ciphertext = encrypt(plaintext);
      expect(ciphertext).not.toBe(plaintext);
      expect(decrypt(ciphertext)).toBe(plaintext);
    });

    it('should produce different ciphertexts for same input (IV randomness)', () => {
      const plaintext = 'same-input';
      const ct1 = encrypt(plaintext);
      const ct2 = encrypt(plaintext);
      expect(ct1).not.toBe(ct2);
      expect(decrypt(ct1)).toBe(plaintext);
      expect(decrypt(ct2)).toBe(plaintext);
    });

    it('should fail to decrypt tampered ciphertext', () => {
      const ciphertext = encrypt('test');
      const tampered = ciphertext.slice(0, -4) + 'XXXX';
      expect(() => decrypt(tampered)).toThrow();
    });

    it('should handle empty string', () => {
      expect(decrypt(encrypt(''))).toBe('');
    });

    it('should handle unicode', () => {
      const text = '🔐 secret with émojis 🎉';
      expect(decrypt(encrypt(text))).toBe(text);
    });
  });

  describe('sha256', () => {
    it('should produce consistent hex output', () => {
      const hash = sha256('hello');
      expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });

    it('should produce different hashes for different inputs', () => {
      expect(sha256('a')).not.toBe(sha256('b'));
    });
  });

  describe('safeCompare', () => {
    it('should return true for identical strings', () => {
      expect(safeCompare('abc', 'abc')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(safeCompare('abc', 'xyz')).toBe(false);
    });

    it('should return false for different lengths', () => {
      expect(safeCompare('short', 'longer_string')).toBe(false);
    });
  });

  describe('generateToken', () => {
    it('should produce hex strings of expected length', () => {
      const token = generateToken(32);
      expect(token).toHaveLength(64); // 32 bytes = 64 hex chars
    });

    it('should produce unique tokens', () => {
      const t1 = generateToken();
      const t2 = generateToken();
      expect(t1).not.toBe(t2);
    });
  });

  describe('PKCE', () => {
    it('should generate valid code verifier (base64url)', () => {
      const verifier = generateCodeVerifier();
      expect(verifier.length).toBeGreaterThanOrEqual(43);
      expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate SHA-256 code challenge from verifier', () => {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier);
      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(challenge.length).toBeGreaterThan(0);
    });
  });
});
