/**
 * Authentication middleware.
 * Validates session tokens from cookies or Authorization header.
 */
import { Request, Response, NextFunction } from 'express';
import { sessionService } from '../services/session.service';
import { tenantService } from '../services/tenant.service';
import { config } from '../config';

export interface AuthenticatedRequest extends Request {
  session_data?: {
    id: string;
    tenantId: string;
    userId: string;
    idpConfigId: string | null;
    mfaVerified: boolean;
    mfaMethod: string | null;
  };
  tenantId?: string;
}

/**
 * Validates the session token (from cookie or Authorization header).
 * Attaches session info to request.
 */
export async function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const token = extractSessionToken(req);
    if (!token) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const tenantId = req.tenantId;
    if (!tenantId) {
      res.status(400).json({ error: 'Tenant not identified' });
      return;
    }

    // Fetch tenant-specific timeout overrides
    const tenant = await tenantService.getTenant(tenantId) as {
      idle_timeout_seconds: number | null;
    } | null;

    const session = await sessionService.validate(
      token,
      tenant?.idle_timeout_seconds ?? config.SESSION_IDLE_TIMEOUT
    );

    if (!session) {
      res.clearCookie('legora_session');
      res.status(401).json({ error: 'Session expired or invalid' });
      return;
    }

    req.session_data = {
      id: session.id,
      tenantId: session.tenantId,
      userId: session.userId,
      idpConfigId: session.idpConfigId,
      mfaVerified: session.mfaVerified,
      mfaMethod: session.mfaMethod,
    };

    next();
  } catch {
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
}

/**
 * Requires MFA to have been completed for the current session.
 */
export function requireMfa(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  if (!req.session_data?.mfaVerified) {
    res.status(403).json({
      error: 'MFA required',
      code: 'mfa_required',
    });
    return;
  }
  next();
}

/**
 * SCIM bearer token authentication.
 */
export async function requireScimAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: 401,
      detail: 'Bearer token required',
    });
    return;
  }

  const token = authHeader.slice(7);

  // Validate token against the tenant's SCIM token
  // In production, use bcrypt.compare against scim_token_hash
  const tenantId = (req as AuthenticatedRequest).tenantId;
  if (!tenantId) {
    res.status(400).json({ error: 'Tenant not identified' });
    return;
  }

  const result = await (async () => {
    try {
      const { query } = await import('../config/database');
      const { safeCompare } = await import('../utils/crypto');
      const dbResult = await query<{ scim_token_hash: string }>(
        'SELECT scim_token_hash FROM tenants WHERE id = $1 AND scim_enabled = true',
        [tenantId]
      );
      if (dbResult.rows.length === 0) return false;

      const bcrypt = await import('bcrypt');
      return bcrypt.compare(token, dbResult.rows[0].scim_token_hash);
    } catch {
      return false;
    }
  })();

  if (!result) {
    res.status(401).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: 401,
      detail: 'Invalid bearer token',
    });
    return;
  }

  next();
}

function extractSessionToken(req: Request): string | null {
  // Cookie (preferred for browser-based flows)
  const cookieToken = req.cookies?.['legora_session'] as string | undefined;
  if (cookieToken) return cookieToken;

  // Authorization header (for API/programmatic access)
  const authHeader = req.headers['authorization'];
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  return null;
}
