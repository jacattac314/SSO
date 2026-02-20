/**
 * SCIM 2.0 service.
 * Implements RFC 7644 (SCIM Protocol) endpoints for automated user provisioning.
 * Supports: Users (CRUD), Groups (CRUD), filtering, and pagination.
 */
import { query, withTransaction } from '../config/database';
import { userService, User } from './user.service';
import { sessionService } from './session.service';
import { auditService, AuditEventType } from './audit.service';
import { scimLogger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

// SCIM 2.0 schema URNs
const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const SCIM_LIST_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

export interface ScimUser {
  id: string;
  externalId?: string;
  userName: string;
  name?: {
    givenName?: string;
    familyName?: string;
    formatted?: string;
  };
  emails: Array<{ value: string; primary?: boolean; type?: string }>;
  groups?: Array<{ value: string; display?: string }>;
  active: boolean;
  meta: {
    resourceType: 'User';
    created: string;
    lastModified: string;
    location: string;
    version: string;
  };
  schemas: string[];
}

export interface ScimGroup {
  id: string;
  externalId?: string;
  displayName: string;
  members: Array<{ value: string; display?: string }>;
  meta: {
    resourceType: 'Group';
    created: string;
    lastModified: string;
    location: string;
    version: string;
  };
  schemas: string[];
}

export class ScimError extends Error {
  constructor(
    public readonly status: number,
    public readonly scimType: string,
    message: string
  ) {
    super(message);
    this.name = 'ScimError';
  }

  toResponse(): Record<string, unknown> {
    return {
      schemas: [SCIM_ERROR_SCHEMA],
      status: this.status,
      scimType: this.scimType,
      detail: this.message,
    };
  }
}

class ScimService {
  private readonly baseUrl: string;

  constructor() {
    this.baseUrl = process.env.SCIM_BASE_URL ?? 'http://localhost:3000/scim/v2';
  }

  // ─── USERS ────────────────────────────────────────────────────────────────

  async getUser(tenantId: string, userId: string): Promise<ScimUser> {
    const user = await userService.findByScimId(userId);
    if (!user || user.tenantId !== tenantId) {
      throw new ScimError(404, 'notFound', `User ${userId} not found`);
    }
    return this.toScimUser(user);
  }

  async listUsers(
    tenantId: string,
    opts: { filter?: string; startIndex?: number; count?: number }
  ): Promise<{ schemas: string[]; totalResults: number; startIndex: number; itemsPerPage: number; Resources: ScimUser[] }> {
    const limit = opts.count ?? 100;
    const offset = (opts.startIndex ?? 1) - 1; // SCIM is 1-indexed

    const { users, total } = await userService.list(tenantId, {
      filter: opts.filter,
      limit,
      offset,
    });

    return {
      schemas: [SCIM_LIST_RESPONSE_SCHEMA],
      totalResults: total,
      startIndex: opts.startIndex ?? 1,
      itemsPerPage: users.length,
      Resources: users.map((u) => this.toScimUser(u)),
    };
  }

  async createUser(
    tenantId: string,
    body: Partial<ScimUser>,
    actorInfo?: { ipAddress?: string }
  ): Promise<ScimUser> {
    const email =
      body.emails?.find((e) => e.primary)?.value ??
      body.emails?.[0]?.value;

    if (!email) {
      throw new ScimError(400, 'invalidValue', 'Email is required');
    }
    if (!body.userName) {
      throw new ScimError(400, 'invalidValue', 'userName is required');
    }

    // Check for duplicate
    const existing = await userService.findByEmail(tenantId, email);
    if (existing) {
      throw new ScimError(409, 'uniqueness', `User with email ${email} already exists`);
    }

    const scimId = uuidv4();
    const now = new Date();

    const result = await query<User>(
      `INSERT INTO users (
        tenant_id, username, email, first_name, last_name, display_name,
        is_active, scim_id, roles, groups, last_login_at, external_id
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11)
      RETURNING *`,
      [
        tenantId,
        body.userName,
        email.toLowerCase(),
        body.name?.givenName ?? null,
        body.name?.familyName ?? null,
        body.name?.formatted ?? null,
        body.active ?? true,
        scimId,
        ['user'],
        [],
        body.externalId ?? null,
      ]
    );

    const user = result.rows[0];

    await auditService.log({
      tenantId,
      userId: user.id,
      actorEmail: email,
      eventType: AuditEventType.SCIM_USER_CREATED,
      outcome: 'success',
      ipAddress: actorInfo?.ipAddress,
      details: { scimId, userName: body.userName },
    });

    scimLogger.info('SCIM user created', { tenantId, scimId, email });
    return this.toScimUser(user);
  }

  async updateUser(
    tenantId: string,
    userId: string,
    body: Partial<ScimUser>,
    actorInfo?: { ipAddress?: string }
  ): Promise<ScimUser> {
    const existing = await userService.findByScimId(userId);
    if (!existing || existing.tenantId !== tenantId) {
      throw new ScimError(404, 'notFound', `User ${userId} not found`);
    }

    const wasActive = existing.isActive;
    const isNowActive = body.active ?? wasActive;

    const email =
      body.emails?.find((e) => e.primary)?.value ??
      body.emails?.[0]?.value ??
      existing.email;

    await query(
      `UPDATE users SET
        username     = COALESCE($3, username),
        email        = $4,
        first_name   = COALESCE($5, first_name),
        last_name    = COALESCE($6, last_name),
        display_name = COALESCE($7, display_name),
        is_active    = $8,
        external_id  = COALESCE($9, external_id),
        updated_at   = NOW()
       WHERE id = $1 AND tenant_id = $2`,
      [
        existing.id,
        tenantId,
        body.userName ?? null,
        email.toLowerCase(),
        body.name?.givenName ?? null,
        body.name?.familyName ?? null,
        body.name?.formatted ?? null,
        isNowActive,
        body.externalId ?? null,
      ]
    );

    // If user is being deactivated, terminate sessions immediately
    if (wasActive && !isNowActive) {
      await userService.deactivate(tenantId, existing.id);
    }

    const updated = await userService.findById(tenantId, existing.id);
    if (!updated) throw new ScimError(500, 'internalError', 'Failed to retrieve updated user');

    await auditService.log({
      tenantId,
      userId: existing.id,
      eventType: AuditEventType.SCIM_USER_UPDATED,
      outcome: 'success',
      ipAddress: actorInfo?.ipAddress,
      details: {
        wasActive,
        isNowActive,
        changes: { userName: body.userName, email, firstName: body.name?.givenName },
      },
    });

    return this.toScimUser(updated);
  }

  async patchUser(
    tenantId: string,
    userId: string,
    operations: Array<{ op: string; path?: string; value?: unknown }>,
    actorInfo?: { ipAddress?: string }
  ): Promise<ScimUser> {
    const existing = await userService.findByScimId(userId);
    if (!existing || existing.tenantId !== tenantId) {
      throw new ScimError(404, 'notFound', `User ${userId} not found`);
    }

    // Build a partial update from PATCH operations
    const updates: Partial<ScimUser> = {};
    for (const op of operations) {
      if (op.op.toLowerCase() === 'replace' || op.op.toLowerCase() === 'add') {
        if (op.path === 'active' || op.path === 'Active') {
          updates.active = op.value as boolean;
        }
        if (op.path === 'userName') {
          updates.userName = op.value as string;
        }
        // Handle complex value updates
        if (!op.path && typeof op.value === 'object' && op.value !== null) {
          Object.assign(updates, op.value);
        }
      }
    }

    return this.updateUser(tenantId, userId, updates, actorInfo);
  }

  async deleteUser(
    tenantId: string,
    userId: string,
    actorInfo?: { ipAddress?: string }
  ): Promise<void> {
    const existing = await userService.findByScimId(userId);
    if (!existing || existing.tenantId !== tenantId) {
      throw new ScimError(404, 'notFound', `User ${userId} not found`);
    }

    // Terminate sessions before deleting
    await sessionService.terminateAllForUser(existing.id, 'scim_delete');

    await query(
      'DELETE FROM users WHERE id = $1 AND tenant_id = $2',
      [existing.id, tenantId]
    );

    await auditService.log({
      tenantId,
      userId: existing.id,
      actorEmail: existing.email,
      eventType: AuditEventType.SCIM_USER_DELETED,
      outcome: 'success',
      ipAddress: actorInfo?.ipAddress,
    });

    scimLogger.info('SCIM user deleted', { tenantId, scimId: userId });
  }

  // ─── GROUPS ───────────────────────────────────────────────────────────────

  async getGroup(tenantId: string, groupId: string): Promise<ScimGroup> {
    const result = await query<{
      id: string;
      display_name: string;
      external_id: string | null;
      members: string[];
      scim_version: number;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM scim_groups WHERE id = $1 AND tenant_id = $2',
      [groupId, tenantId]
    );
    if (result.rows.length === 0) {
      throw new ScimError(404, 'notFound', `Group ${groupId} not found`);
    }
    return this.toScimGroup(result.rows[0], tenantId);
  }

  async createGroup(
    tenantId: string,
    body: Partial<ScimGroup>,
    actorInfo?: { ipAddress?: string }
  ): Promise<ScimGroup> {
    if (!body.displayName) {
      throw new ScimError(400, 'invalidValue', 'displayName is required');
    }

    const memberIds = (body.members ?? []).map((m) => m.value);

    const result = await query<{ id: string }>(
      `INSERT INTO scim_groups (tenant_id, display_name, external_id, members)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [tenantId, body.displayName, body.externalId ?? null, memberIds]
    );

    await auditService.log({
      tenantId,
      eventType: AuditEventType.SCIM_GROUP_CREATED,
      outcome: 'success',
      ipAddress: actorInfo?.ipAddress,
      details: { groupId: result.rows[0].id, displayName: body.displayName },
    });

    return this.getGroup(tenantId, result.rows[0].id);
  }

  async deleteGroup(
    tenantId: string,
    groupId: string,
    actorInfo?: { ipAddress?: string }
  ): Promise<void> {
    const result = await query(
      'DELETE FROM scim_groups WHERE id = $1 AND tenant_id = $2 RETURNING id',
      [groupId, tenantId]
    );
    if ((result.rowCount ?? 0) === 0) {
      throw new ScimError(404, 'notFound', `Group ${groupId} not found`);
    }

    await auditService.log({
      tenantId,
      eventType: AuditEventType.SCIM_GROUP_DELETED,
      outcome: 'success',
      ipAddress: actorInfo?.ipAddress,
      details: { groupId },
    });
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private toScimUser(user: User): ScimUser {
    return {
      schemas: [SCIM_USER_SCHEMA],
      id: user.scimId ?? user.id,
      externalId: user.externalId ?? undefined,
      userName: user.username ?? user.email,
      name: {
        givenName: user.firstName ?? undefined,
        familyName: user.lastName ?? undefined,
        formatted: user.displayName ?? undefined,
      },
      emails: [{ value: user.email, primary: true, type: 'work' }],
      active: user.isActive,
      meta: {
        resourceType: 'User',
        created: user.createdAt.toISOString(),
        lastModified: user.updatedAt.toISOString(),
        location: `${this.baseUrl}/Users/${user.scimId ?? user.id}`,
        version: `W/"${user.scimVersion}"`,
      },
    };
  }

  private toScimGroup(
    row: {
      id: string;
      display_name: string;
      external_id: string | null;
      members: string[];
      scim_version: number;
      created_at: Date;
      updated_at: Date;
    },
    tenantId: string
  ): ScimGroup {
    return {
      schemas: [SCIM_GROUP_SCHEMA],
      id: row.id,
      externalId: row.external_id ?? undefined,
      displayName: row.display_name,
      members: (row.members ?? []).map((m) => ({ value: m })),
      meta: {
        resourceType: 'Group',
        created: row.created_at.toISOString(),
        lastModified: row.updated_at.toISOString(),
        location: `${this.baseUrl}/Groups/${row.id}`,
        version: `W/"${row.scim_version}"`,
      },
    };
  }
}

export const scimService = new ScimService();
