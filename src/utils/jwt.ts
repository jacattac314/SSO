/**
 * JWT utilities for issuing and verifying Legora internal tokens.
 * Uses RS256 for access tokens and HS256 for short-lived internal tokens.
 */
import jwt, { SignOptions, VerifyOptions, JwtPayload } from 'jsonwebtoken';
import { config } from '../config';

export interface AccessTokenPayload extends JwtPayload {
  sub: string;         // user ID
  tid: string;         // tenant ID
  email: string;
  roles: string[];
  iss: string;
  aud: string | string[];
  jti: string;
}

export interface RefreshTokenPayload extends JwtPayload {
  sub: string;
  tid: string;
  fid: string;         // token family ID
  jti: string;
}

/**
 * Issues a short-lived access token for a Legora user.
 */
export function issueAccessToken(
  userId: string,
  tenantId: string,
  email: string,
  roles: string[],
  jwtId: string
): string {
  const payload: Omit<AccessTokenPayload, keyof JwtPayload> & Record<string, unknown> = {
    tid: tenantId,
    email,
    roles,
    jti: jwtId,
  };
  const options: SignOptions = {
    subject: userId,
    issuer: config.JWT_ISSUER,
    audience: `${config.BASE_URL}/api`,
    expiresIn: config.JWT_ACCESS_TOKEN_TTL,
    algorithm: 'HS256',
  };
  return jwt.sign(payload, config.JWT_SECRET, options);
}

/**
 * Issues a refresh token tied to a token family (for rotation).
 */
export function issueRefreshToken(
  userId: string,
  tenantId: string,
  familyId: string,
  jwtId: string
): string {
  const payload: Record<string, unknown> = {
    tid: tenantId,
    fid: familyId,
    jti: jwtId,
  };
  const options: SignOptions = {
    subject: userId,
    issuer: config.JWT_ISSUER,
    audience: `${config.BASE_URL}/auth/token`,
    expiresIn: config.JWT_REFRESH_TOKEN_TTL,
    algorithm: 'HS256',
  };
  return jwt.sign(payload, config.JWT_SECRET, options);
}

/**
 * Verifies and decodes an access token.
 */
export function verifyAccessToken(token: string): AccessTokenPayload {
  const options: VerifyOptions = {
    issuer: config.JWT_ISSUER,
    audience: `${config.BASE_URL}/api`,
    algorithms: ['HS256'],
  };
  return jwt.verify(token, config.JWT_SECRET, options) as AccessTokenPayload;
}

/**
 * Verifies and decodes a refresh token.
 */
export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const options: VerifyOptions = {
    issuer: config.JWT_ISSUER,
    audience: `${config.BASE_URL}/auth/token`,
    algorithms: ['HS256'],
  };
  return jwt.verify(token, config.JWT_SECRET, options) as RefreshTokenPayload;
}

/**
 * Decodes a JWT without verification (for inspection only).
 */
export function decodeToken(token: string): JwtPayload | null {
  const decoded = jwt.decode(token);
  if (typeof decoded === 'object' && decoded !== null) {
    return decoded;
  }
  return null;
}

/**
 * Checks if a JWT is expired without throwing (returns true if expired).
 */
export function isTokenExpired(token: string): boolean {
  const decoded = decodeToken(token);
  if (!decoded?.exp) return true;
  return Date.now() >= decoded.exp * 1000;
}
