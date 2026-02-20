/**
 * User service – creates/updates/deactivates users in the Legora user store.
 * Used by SSO (just-in-time provisioning) and SCIM provisioning.
 */
import { query, withTransaction } from '../config/database';
import { auditService, AuditEventType } from './audit.service';
import { sessionService } from './session.service';

export interface User {
  id: string;
  tenantId: string;
  externalId: string | null;
  username: string | null;
  email: string;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  isActive: boolean;
  roles: string[];
  groups: string[];
  scimId: string | null;
  scimVersion: number;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface UpsertUserParams {
  tenantId: string;
  externalId?: string;
  email: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  roles?: string[];
  groups?: string[];
  isActive?: boolean;
}

class UserService {
  async findById(tenantId: string, userId: string): Promise<User | null> {
    const result = await query<User>(
      'SELECT * FROM users WHERE id = $1 AND tenant_id = $2',
      [userId, tenantId]
    );
    return result.rows[0] ?? null;
  }

  async findByEmail(tenantId: string, email: string): Promise<User | null> {
    const result = await query<User>(
      'SELECT * FROM users WHERE tenant_id = $1 AND email = $2',
      [tenantId, email.toLowerCase()]
    );
    return result.rows[0] ?? null;
  }

  async findByExternalId(tenantId: string, externalId: string): Promise<User | null> {
    const result = await query<User>(
      'SELECT * FROM users WHERE tenant_id = $1 AND external_id = $2',
      [tenantId, externalId]
    );
    return result.rows[0] ?? null;
  }

  async findByScimId(scimId: string): Promise<User | null> {
    const result = await query<User>(
      'SELECT * FROM users WHERE scim_id = $1',
      [scimId]
    );
    return result.rows[0] ?? null;
  }

  /**
   * Creates or updates a user via JIT (just-in-time) provisioning on SSO login.
   * First tries to match by externalId, then email.
   */
  async upsertFromSso(params: UpsertUserParams): Promise<User> {
    return withTransaction(async (client) => {
      let existing: User | null = null;

      // Try to find by external ID first
      if (params.externalId) {
        const r = await client.query<User>(
          'SELECT * FROM users WHERE tenant_id = $1 AND external_id = $2',
          [params.tenantId, params.externalId]
        );
        existing = r.rows[0] ?? null;
      }

      // Fall back to email
      if (!existing) {
        const r = await client.query<User>(
          'SELECT * FROM users WHERE tenant_id = $1 AND email = $2',
          [params.tenantId, params.email.toLowerCase()]
        );
        existing = r.rows[0] ?? null;
      }

      if (existing) {
        // Update existing user (JIT attribute sync)
        const r = await client.query<User>(
          `UPDATE users SET
            external_id   = COALESCE($3, external_id),
            username      = COALESCE($4, username),
            first_name    = COALESCE($5, first_name),
            last_name     = COALESCE($6, last_name),
            display_name  = COALESCE($7, display_name),
            roles         = $8,
            groups        = $9,
            is_active     = $10,
            last_login_at = NOW(),
            updated_at    = NOW()
           WHERE id = $1 AND tenant_id = $2
           RETURNING *`,
          [
            existing.id,
            params.tenantId,
            params.externalId ?? null,
            params.username ?? null,
            params.firstName ?? null,
            params.lastName ?? null,
            params.displayName ?? null,
            params.roles ?? existing.roles,
            params.groups ?? existing.groups,
            params.isActive ?? true,
          ]
        );
        return r.rows[0];
      } else {
        // Create new user
        const r = await client.query<User>(
          `INSERT INTO users (
            tenant_id, external_id, username, email,
            first_name, last_name, display_name,
            roles, groups, is_active, last_login_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
          RETURNING *`,
          [
            params.tenantId,
            params.externalId ?? null,
            params.username ?? null,
            params.email.toLowerCase(),
            params.firstName ?? null,
            params.lastName ?? null,
            params.displayName ?? null,
            params.roles ?? ['user'],
            params.groups ?? [],
            params.isActive ?? true,
          ]
        );

        await auditService.log({
          tenantId: params.tenantId,
          userId: r.rows[0].id,
          actorEmail: params.email,
          eventType: AuditEventType.SCIM_USER_CREATED,
          outcome: 'success',
          details: { source: 'jit_provisioning' },
        });

        return r.rows[0];
      }
    });
  }

  /**
   * Deactivates a user and terminates all their sessions immediately.
   * Called by SCIM DELETE/PATCH active=false.
   */
  async deactivate(tenantId: string, userId: string): Promise<void> {
    await query(
      'UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1 AND tenant_id = $2',
      [userId, tenantId]
    );

    // Immediately terminate all sessions per security requirements
    const terminated = await sessionService.terminateAllForUser(userId, 'user_deactivated');

    await auditService.log({
      tenantId,
      userId,
      eventType: AuditEventType.SCIM_USER_DEACTIVATED,
      outcome: 'success',
      details: { sessionsTerminated: terminated },
    });
  }

  async list(
    tenantId: string,
    opts: { filter?: string; limit?: number; offset?: number }
  ): Promise<{ users: User[]; total: number }> {
    const limit = opts.limit ?? 100;
    const offset = opts.offset ?? 0;
    let filterClause = '';
    const values: unknown[] = [tenantId];

    // Simple SCIM filter support (userName eq "x" or email eq "x")
    if (opts.filter) {
      const match = opts.filter.match(/^(userName|email)\s+eq\s+"(.+)"$/i);
      if (match) {
        const field = match[1].toLowerCase() === 'username' ? 'username' : 'email';
        filterClause = ` AND ${field} = $2`;
        values.push(match[2].toLowerCase());
      }
    }

    const [countResult, dataResult] = await Promise.all([
      query<{ count: string }>(
        `SELECT COUNT(*) as count FROM users WHERE tenant_id = $1${filterClause}`,
        values
      ),
      query<User>(
        `SELECT * FROM users WHERE tenant_id = $1${filterClause} ORDER BY created_at LIMIT ${limit} OFFSET ${offset}`,
        values
      ),
    ]);

    return {
      users: dataResult.rows,
      total: parseInt(countResult.rows[0]?.count ?? '0', 10),
    };
  }
}

export const userService = new UserService();
