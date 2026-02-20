/**
 * Session management service.
 * Handles creation, validation, idle/absolute timeout enforcement, and termination.
 * Implements RFC-compliant session security (HttpOnly, Secure, SameSite cookies).
 */
import { query } from '../config/database';
import { generateToken, sha256 } from '../utils/crypto';
import { sessionLogger } from '../utils/logger';
import { auditService, AuditEventType } from './audit.service';
import { config } from '../config';

export interface Session {
  id: string;
  tenantId: string;
  userId: string;
  idpConfigId: string | null;
  sessionToken: string;
  samlNameId: string | null;
  samlSessionIndex: string | null;
  samlNameIdFormat: string | null;
  oidcIdToken: string | null;
  oidcAccessToken: string | null;
  oidcRefreshToken: string | null;
  oidcTokenExp: Date | null;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
  mfaVerified: boolean;
  mfaMethod: string | null;
}

export interface CreateSessionParams {
  tenantId: string;
  userId: string;
  idpConfigId?: string;
  samlNameId?: string;
  samlSessionIndex?: string;
  samlNameIdFormat?: string;
  oidcIdToken?: string;
  oidcAccessToken?: string;
  oidcRefreshToken?: string;
  oidcTokenExp?: Date;
  ipAddress?: string;
  userAgent?: string;
  mfaVerified?: boolean;
  mfaMethod?: string;
  /** Override idle timeout (seconds) for this session's tenant. */
  idleTimeoutSeconds?: number;
  /** Override absolute timeout (seconds) for this session's tenant. */
  absoluteTimeoutSeconds?: number;
}

class SessionService {
  /**
   * Creates a new SSO session and returns the opaque session token.
   */
  async create(params: CreateSessionParams): Promise<string> {
    const token = generateToken(32); // 256-bit random token
    const absoluteTimeout = params.absoluteTimeoutSeconds ?? config.SESSION_ABSOLUTE_TIMEOUT;
    const expiresAt = new Date(Date.now() + absoluteTimeout * 1000);

    await query(
      `INSERT INTO sso_sessions (
        tenant_id, user_id, idp_config_id, session_token,
        saml_name_id, saml_session_index, saml_name_id_format,
        oidc_id_token, oidc_access_token, oidc_refresh_token, oidc_token_exp,
        expires_at, ip_address, user_agent, mfa_verified, mfa_method
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::inet, $14, $15, $16)`,
      [
        params.tenantId,
        params.userId,
        params.idpConfigId ?? null,
        token,
        params.samlNameId ?? null,
        params.samlSessionIndex ?? null,
        params.samlNameIdFormat ?? null,
        params.oidcIdToken ?? null,
        params.oidcAccessToken ?? null,
        params.oidcRefreshToken ?? null,
        params.oidcTokenExp ?? null,
        expiresAt,
        params.ipAddress ?? null,
        params.userAgent ?? null,
        params.mfaVerified ?? false,
        params.mfaMethod ?? null,
      ]
    );

    await auditService.log({
      tenantId: params.tenantId,
      userId: params.userId,
      idpConfigId: params.idpConfigId,
      eventType: AuditEventType.SESSION_CREATED,
      outcome: 'success',
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: { mfaVerified: params.mfaVerified, mfaMethod: params.mfaMethod },
    });

    sessionLogger.info('Session created', {
      tenantId: params.tenantId,
      userId: params.userId,
      expiresAt,
    });

    return token;
  }

  /**
   * Validates a session token.
   * Enforces idle timeout and absolute timeout.
   * Updates last_activity_at on success.
   * Returns null if session is invalid/expired.
   */
  async validate(
    token: string,
    idleTimeoutSeconds: number = config.SESSION_IDLE_TIMEOUT
  ): Promise<Session | null> {
    const result = await query<Session & {
      last_activity_at: Date;
      expires_at: Date;
      created_at: Date;
    }>(
      `SELECT * FROM sso_sessions WHERE session_token = $1`,
      [token]
    );

    if (result.rows.length === 0) return null;

    const session = result.rows[0];
    const now = new Date();

    // Check absolute expiry
    if (session.expiresAt < now) {
      await this.terminate(token, 'absolute_timeout');
      return null;
    }

    // Check idle timeout
    const idleDeadline = new Date(
      (session.lastActivityAt as unknown as Date).getTime() + idleTimeoutSeconds * 1000
    );
    if (idleDeadline < now) {
      await this.terminate(token, 'idle_timeout');
      return null;
    }

    // Update last activity
    await query(
      'UPDATE sso_sessions SET last_activity_at = NOW() WHERE session_token = $1',
      [token]
    );

    return {
      ...session,
      lastActivityAt: now,
    };
  }

  /**
   * Terminates a session by token.
   */
  async terminate(token: string, reason?: string): Promise<void> {
    const result = await query<{ tenant_id: string; user_id: string }>(
      'DELETE FROM sso_sessions WHERE session_token = $1 RETURNING tenant_id, user_id',
      [token]
    );

    if (result.rows.length > 0) {
      const { tenant_id, user_id } = result.rows[0];
      const eventType =
        reason === 'idle_timeout'
          ? AuditEventType.SESSION_EXPIRED_IDLE
          : reason === 'absolute_timeout'
            ? AuditEventType.SESSION_EXPIRED_ABSOLUTE
            : AuditEventType.SESSION_TERMINATED;

      await auditService.log({
        tenantId: tenant_id,
        userId: user_id,
        eventType,
        outcome: 'success',
        details: { reason },
      });

      sessionLogger.info('Session terminated', { reason, tenantId: tenant_id, userId: user_id });
    }
  }

  /**
   * Terminates ALL sessions for a user (e.g. SCIM deactivation, forced logout).
   */
  async terminateAllForUser(userId: string, reason = 'forced_logout'): Promise<number> {
    const result = await query<{ tenant_id: string }>(
      'DELETE FROM sso_sessions WHERE user_id = $1 RETURNING tenant_id',
      [userId]
    );

    if (result.rows.length > 0) {
      await auditService.log({
        tenantId: result.rows[0].tenant_id,
        userId,
        eventType: AuditEventType.SESSION_TERMINATED,
        outcome: 'success',
        details: { reason, sessionsTerminated: result.rows.length },
      });
    }

    return result.rows.length;
  }

  /**
   * Finds sessions for a SAML NameID + SessionIndex (for SLO).
   */
  async findBySamlSession(
    tenantId: string,
    nameId: string,
    sessionIndex?: string
  ): Promise<Session[]> {
    const conditions = ['tenant_id = $1', 'saml_name_id = $2'];
    const values: unknown[] = [tenantId, nameId];
    if (sessionIndex) {
      conditions.push(`saml_session_index = $3`);
      values.push(sessionIndex);
    }
    const result = await query<Session>(
      `SELECT * FROM sso_sessions WHERE ${conditions.join(' AND ')}`,
      values
    );
    return result.rows;
  }

  /**
   * Removes expired sessions (for background cleanup job).
   */
  async purgeExpired(): Promise<number> {
    const result = await query(
      'DELETE FROM sso_sessions WHERE expires_at < NOW()'
    );
    return result.rowCount ?? 0;
  }
}

export const sessionService = new SessionService();
