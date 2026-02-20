/**
 * Audit logging service.
 * Records every SSO/SCIM/session event with full context for SOC2/GDPR compliance.
 * All events are persisted to the DB and also emitted to the structured logger.
 */
import { query } from '../config/database';
import { auditLogger } from '../utils/logger';

export type AuditOutcome = 'success' | 'failure' | 'error';

export interface AuditEvent {
  tenantId?: string;
  userId?: string;
  actorEmail?: string;
  eventType: string;
  outcome: AuditOutcome;
  ipAddress?: string;
  userAgent?: string;
  idpConfigId?: string;
  details?: Record<string, unknown>;
}

// Well-known event type constants
export const AuditEventType = {
  // Authentication
  SSO_LOGIN_INITIATED: 'sso.login.initiated',
  SSO_LOGIN_SUCCESS: 'sso.login.success',
  SSO_LOGIN_FAILURE: 'sso.login.failure',
  SSO_LOGOUT_INITIATED: 'sso.logout.initiated',
  SSO_LOGOUT_SUCCESS: 'sso.logout.success',
  SSO_SLO_REQUEST_SENT: 'sso.slo.request_sent',
  SSO_SLO_REQUEST_RECEIVED: 'sso.slo.request_received',

  // Tokens
  TOKEN_ISSUED: 'token.issued',
  TOKEN_REFRESHED: 'token.refreshed',
  TOKEN_REVOKED: 'token.revoked',
  TOKEN_EXPIRED: 'token.expired',
  TOKEN_INVALID: 'token.invalid',

  // WebAuthn
  WEBAUTHN_REGISTER_STARTED: 'webauthn.register.started',
  WEBAUTHN_REGISTER_SUCCESS: 'webauthn.register.success',
  WEBAUTHN_REGISTER_FAILURE: 'webauthn.register.failure',
  WEBAUTHN_VERIFY_SUCCESS: 'webauthn.verify.success',
  WEBAUTHN_VERIFY_FAILURE: 'webauthn.verify.failure',

  // SCIM
  SCIM_USER_CREATED: 'scim.user.created',
  SCIM_USER_UPDATED: 'scim.user.updated',
  SCIM_USER_DELETED: 'scim.user.deleted',
  SCIM_USER_DEACTIVATED: 'scim.user.deactivated',
  SCIM_GROUP_CREATED: 'scim.group.created',
  SCIM_GROUP_UPDATED: 'scim.group.updated',
  SCIM_GROUP_DELETED: 'scim.group.deleted',

  // Session
  SESSION_CREATED: 'session.created',
  SESSION_EXPIRED_IDLE: 'session.expired.idle',
  SESSION_EXPIRED_ABSOLUTE: 'session.expired.absolute',
  SESSION_TERMINATED: 'session.terminated',

  // Certificate
  CERT_EXPIRY_WARNING: 'cert.expiry.warning',
  CERT_ROTATED: 'cert.rotated',

  // Tenant config
  TENANT_CONFIG_CREATED: 'tenant.config.created',
  TENANT_CONFIG_UPDATED: 'tenant.config.updated',
  IDP_CONFIG_CREATED: 'idp.config.created',
  IDP_CONFIG_UPDATED: 'idp.config.updated',
  IDP_CONFIG_DELETED: 'idp.config.deleted',
  ROLE_MAPPING_UPDATED: 'role.mapping.updated',
} as const;

class AuditService {
  async log(event: AuditEvent): Promise<void> {
    const { tenantId, userId, actorEmail, eventType, outcome, ipAddress, userAgent, idpConfigId, details } = event;

    // Always emit to structured log
    auditLogger.info('audit_event', {
      tenant_id: tenantId,
      user_id: userId,
      actor_email: actorEmail,
      event_type: eventType,
      outcome,
      ip_address: ipAddress,
      idp_config_id: idpConfigId,
      details,
    });

    // Persist to DB asynchronously (don't block request)
    try {
      await query(
        `INSERT INTO audit_logs
          (tenant_id, user_id, actor_email, event_type, outcome, ip_address, user_agent, idp_config_id, details)
         VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9)`,
        [
          tenantId ?? null,
          userId ?? null,
          actorEmail ?? null,
          eventType,
          outcome,
          ipAddress ?? null,
          userAgent ?? null,
          idpConfigId ?? null,
          JSON.stringify(details ?? {}),
        ]
      );
    } catch (err) {
      // Audit log failure must not break auth flows – log the error but continue
      auditLogger.error('Failed to persist audit log to database', { err, eventType });
    }
  }

  /** Query audit logs for a tenant (used by admin API / compliance exports). */
  async queryLogs(params: {
    tenantId: string;
    userId?: string;
    eventType?: string;
    outcome?: AuditOutcome;
    from?: Date;
    to?: Date;
    limit?: number;
    offset?: number;
  }): Promise<{ rows: Record<string, unknown>[]; total: number }> {
    const conditions: string[] = ['tenant_id = $1'];
    const values: unknown[] = [params.tenantId];
    let idx = 2;

    if (params.userId) {
      conditions.push(`user_id = $${idx++}`);
      values.push(params.userId);
    }
    if (params.eventType) {
      conditions.push(`event_type = $${idx++}`);
      values.push(params.eventType);
    }
    if (params.outcome) {
      conditions.push(`outcome = $${idx++}`);
      values.push(params.outcome);
    }
    if (params.from) {
      conditions.push(`created_at >= $${idx++}`);
      values.push(params.from);
    }
    if (params.to) {
      conditions.push(`created_at <= $${idx++}`);
      values.push(params.to);
    }

    const where = conditions.join(' AND ');
    const limit = params.limit ?? 100;
    const offset = params.offset ?? 0;

    const [countResult, dataResult] = await Promise.all([
      query<{ count: string }>(
        `SELECT COUNT(*) AS count FROM audit_logs WHERE ${where}`,
        values
      ),
      query<Record<string, unknown>>(
        `SELECT * FROM audit_logs WHERE ${where} ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
        [...values, limit, offset]
      ),
    ]);

    return {
      rows: dataResult.rows,
      total: parseInt(countResult.rows[0]?.count ?? '0', 10),
    };
  }

  /** Purge logs older than retention period. */
  async purgeOldLogs(retentionDays: number): Promise<number> {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    const result = await query(
      'DELETE FROM audit_logs WHERE created_at < $1',
      [cutoff]
    );
    return result.rowCount ?? 0;
  }
}

export const auditService = new AuditService();
