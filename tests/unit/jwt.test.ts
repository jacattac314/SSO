/**
 * Unit tests for JWT utilities.
 */
import { issueAccessToken, issueRefreshToken, verifyAccessToken, verifyRefreshToken, decodeToken, isTokenExpired } from '../../src/utils/jwt';
import { v4 as uuidv4 } from 'uuid';

// NOTE: env vars are set in tests/setup.ts (BASE_URL=http://localhost:3001)

describe('JWT utilities', () => {
  const userId = uuidv4();
  const tenantId = uuidv4();
  const familyId = uuidv4();
  const jti = uuidv4();

  describe('Access token', () => {
    it('should issue and verify an access token', () => {
      const token = issueAccessToken(userId, tenantId, 'user@example.com', ['user'], jti);
      const payload = verifyAccessToken(token);
      expect(payload.sub).toBe(userId);
      expect(payload.tid).toBe(tenantId);
      expect(payload.email).toBe('user@example.com');
      expect(payload.roles).toEqual(['user']);
      expect(payload.jti).toBe(jti);
    });

    it('should fail verification with wrong secret', () => {
      const token = issueAccessToken(userId, tenantId, 'user@example.com', ['admin'], jti);
      // Tamper with the token
      const parts = token.split('.');
      parts[2] = 'invalid_signature';
      expect(() => verifyAccessToken(parts.join('.'))).toThrow();
    });

    it('should include iss and aud claims', () => {
      const token = issueAccessToken(userId, tenantId, 'user@example.com', [], jti);
      const payload = decodeToken(token);
      expect(payload?.iss).toBe('http://localhost:3001');
      expect(payload?.aud).toContain('http://localhost:3001/api');
    });
  });

  describe('Refresh token', () => {
    it('should issue and verify a refresh token', () => {
      const token = issueRefreshToken(userId, tenantId, familyId, jti);
      const payload = verifyRefreshToken(token);
      expect(payload.sub).toBe(userId);
      expect(payload.tid).toBe(tenantId);
      expect(payload.fid).toBe(familyId);
      expect(payload.jti).toBe(jti);
    });

    it('should not verify refresh token as access token', () => {
      const refreshToken = issueRefreshToken(userId, tenantId, familyId, jti);
      // Access token verifier checks different audience
      expect(() => verifyAccessToken(refreshToken)).toThrow();
    });
  });

  describe('decodeToken', () => {
    it('should decode without verification', () => {
      const token = issueAccessToken(userId, tenantId, 'test@example.com', [], jti);
      const payload = decodeToken(token);
      expect(payload?.email).toBe('test@example.com');
    });

    it('should return null for invalid token', () => {
      expect(decodeToken('not.a.jwt')).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for a fresh token', () => {
      const token = issueAccessToken(userId, tenantId, 'u@e.com', [], jti);
      expect(isTokenExpired(token)).toBe(false);
    });
  });
});
