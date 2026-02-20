/**
 * Tenant service – manages tenant records, IdP configurations, and role mappings.
 */
import { query, withTransaction } from '../config/database';
import { encrypt, decrypt, parseCertExpiry } from '../utils/crypto';
import { auditService, AuditEventType } from './audit.service';
import { certificateService } from './certificate.service';
import { z } from 'zod';

// ─── Validation schemas ──────────────────────────────────────────────────────

export const OidcConfigSchema = z.object({
  issuer: z.string().url(),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  discoveryUrl: z.string().url().optional(),
  authorizationEndpoint: z.string().url().optional(),
  tokenEndpoint: z.string().url().optional(),
  jwksUri: z.string().url().optional(),
  userinfoEndpoint: z.string().url().optional(),
  logoutEndpoint: z.string().url().optional(),
  scopes: z.array(z.string()).default(['openid', 'profile', 'email']),
});

export const SamlConfigSchema = z.object({
  idpEntityId: z.string().min(1),
  idpSsoUrl: z.string().url(),
  idpSloUrl: z.string().url().optional(),
  idpCertificate: z.string().min(1),
  spEntityId: z.string().optional(),
  spAcsUrl: z.string().url().optional(),
  spSloUrl: z.string().url().optional(),
  spCertificate: z.string().optional(),
  spPrivateKey: z.string().optional(),
  signRequests: z.boolean().default(true),
  wantAssertionsSigned: z.boolean().default(true),
  nameIdFormat: z
    .string()
    .default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
});

export const IdpConfigCreateSchema = z.discriminatedUnion('protocol', [
  z.object({
    protocol: z.literal('oidc'),
    name: z.string().min(1),
    isDefault: z.boolean().default(false),
    attributeMapping: z.record(z.string()).default({}),
    oidc: OidcConfigSchema,
  }),
  z.object({
    protocol: z.literal('saml'),
    name: z.string().min(1),
    isDefault: z.boolean().default(false),
    attributeMapping: z.record(z.string()).default({}),
    saml: SamlConfigSchema,
  }),
]);

export type IdpConfigCreate = z.infer<typeof IdpConfigCreateSchema>;

export interface IdpConfigRow {
  id: string;
  tenant_id: string;
  name: string;
  protocol: 'oidc' | 'saml';
  is_active: boolean;
  is_default: boolean;
  attribute_mapping: Record<string, string>;
  // OIDC
  oidc_issuer: string | null;
  oidc_client_id: string | null;
  oidc_discovery_url: string | null;
  oidc_authorization_endpoint: string | null;
  oidc_token_endpoint: string | null;
  oidc_jwks_uri: string | null;
  oidc_userinfo_endpoint: string | null;
  oidc_logout_endpoint: string | null;
  oidc_scopes: string[];
  // SAML
  saml_idp_entity_id: string | null;
  saml_idp_sso_url: string | null;
  saml_idp_slo_url: string | null;
  saml_idp_certificate: string | null;
  saml_sp_entity_id: string | null;
  saml_sp_acs_url: string | null;
  saml_sp_slo_url: string | null;
  saml_sp_certificate: string | null;
  saml_sign_requests: boolean;
  saml_want_assertions_signed: boolean;
  saml_name_id_format: string;
  // Expiry
  idp_cert_expires_at: Date | null;
  sp_cert_expires_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

class TenantService {
  // ─── Tenant CRUD ──────────────────────────────────────────────────────────

  async getTenant(tenantId: string): Promise<Record<string, unknown> | null> {
    const result = await query<Record<string, unknown>>(
      'SELECT * FROM tenants WHERE id = $1',
      [tenantId]
    );
    return result.rows[0] ?? null;
  }

  async getTenantByDomain(domain: string): Promise<Record<string, unknown> | null> {
    const result = await query<Record<string, unknown>>(
      'SELECT * FROM tenants WHERE domain = $1 AND is_active = true',
      [domain]
    );
    return result.rows[0] ?? null;
  }

  // ─── IdP Config CRUD ──────────────────────────────────────────────────────

  async createIdpConfig(tenantId: string, data: IdpConfigCreate): Promise<IdpConfigRow> {
    return withTransaction(async (client) => {
      // If this is marked as default, unset existing defaults
      if (data.isDefault) {
        await client.query(
          'UPDATE idp_configs SET is_default = false WHERE tenant_id = $1 AND protocol = $2',
          [tenantId, data.protocol]
        );
      }

      let row: IdpConfigRow;
      if (data.protocol === 'oidc') {
        const { oidc } = data;
        const result = await client.query<IdpConfigRow>(
          `INSERT INTO idp_configs (
            tenant_id, name, protocol, is_default, attribute_mapping,
            oidc_issuer, oidc_client_id, oidc_client_secret_enc,
            oidc_discovery_url, oidc_scopes
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          RETURNING *`,
          [
            tenantId,
            data.name,
            'oidc',
            data.isDefault,
            JSON.stringify(data.attributeMapping),
            oidc.issuer,
            oidc.clientId,
            encrypt(oidc.clientSecret),
            oidc.discoveryUrl ?? null,
            oidc.scopes,
          ]
        );
        row = result.rows[0];
      } else {
        const { saml } = data;
        const idpCertExpiry = parseCertExpiry(saml.idpCertificate);
        const spCertExpiry = saml.spCertificate ? parseCertExpiry(saml.spCertificate) : null;

        // Validate signature algorithm (reject SHA-1)
        if (!certificateService.validateSignatureAlgorithm(saml.idpCertificate)) {
          throw new Error(
            'IdP certificate must use SHA-256 or stronger signature algorithm'
          );
        }

        const result = await client.query<IdpConfigRow>(
          `INSERT INTO idp_configs (
            tenant_id, name, protocol, is_default, attribute_mapping,
            saml_idp_entity_id, saml_idp_sso_url, saml_idp_slo_url, saml_idp_certificate,
            saml_sp_entity_id, saml_sp_acs_url, saml_sp_slo_url,
            saml_sp_certificate, saml_sp_private_key_enc,
            saml_sign_requests, saml_want_assertions_signed, saml_name_id_format,
            idp_cert_expires_at, sp_cert_expires_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
          RETURNING *`,
          [
            tenantId,
            data.name,
            'saml',
            data.isDefault,
            JSON.stringify(data.attributeMapping),
            saml.idpEntityId,
            saml.idpSsoUrl,
            saml.idpSloUrl ?? null,
            saml.idpCertificate,
            saml.spEntityId ?? null,
            saml.spAcsUrl ?? null,
            saml.spSloUrl ?? null,
            saml.spCertificate ?? null,
            saml.spPrivateKey ? encrypt(saml.spPrivateKey) : null,
            saml.signRequests,
            saml.wantAssertionsSigned,
            saml.nameIdFormat,
            idpCertExpiry,
            spCertExpiry,
          ]
        );
        row = result.rows[0];
      }

      await auditService.log({
        tenantId,
        eventType: AuditEventType.IDP_CONFIG_CREATED,
        outcome: 'success',
        details: { configName: data.name, protocol: data.protocol },
      });

      return row;
    });
  }

  async getIdpConfig(tenantId: string, idpConfigId: string): Promise<IdpConfigRow | null> {
    const result = await query<IdpConfigRow>(
      'SELECT * FROM idp_configs WHERE id = $1 AND tenant_id = $2',
      [idpConfigId, tenantId]
    );
    return result.rows[0] ?? null;
  }

  async getDefaultIdpConfig(
    tenantId: string,
    protocol?: 'oidc' | 'saml'
  ): Promise<IdpConfigRow | null> {
    const conditions = ['tenant_id = $1', 'is_active = true'];
    const values: unknown[] = [tenantId];
    if (protocol) {
      conditions.push('protocol = $2');
      values.push(protocol);
      conditions.push('is_default = true');
    } else {
      conditions.push('is_default = true');
    }
    const result = await query<IdpConfigRow>(
      `SELECT * FROM idp_configs WHERE ${conditions.join(' AND ')} LIMIT 1`,
      values
    );
    return result.rows[0] ?? null;
  }

  async listIdpConfigs(tenantId: string): Promise<IdpConfigRow[]> {
    const result = await query<IdpConfigRow>(
      'SELECT * FROM idp_configs WHERE tenant_id = $1 ORDER BY created_at',
      [tenantId]
    );
    return result.rows;
  }

  /**
   * Returns the decrypted OIDC client secret for a config.
   * Must only be called server-side.
   */
  async getOidcClientSecret(idpConfig: IdpConfigRow): Promise<string> {
    const result = await query<{ oidc_client_secret_enc: string }>(
      'SELECT oidc_client_secret_enc FROM idp_configs WHERE id = $1',
      [idpConfig.id]
    );
    const enc = result.rows[0]?.oidc_client_secret_enc;
    if (!enc) throw new Error('OIDC client secret not found');
    return decrypt(enc);
  }

  /**
   * Returns the decrypted SAML SP private key for a config.
   */
  async getSamlSpPrivateKey(idpConfig: IdpConfigRow): Promise<string | null> {
    const result = await query<{ saml_sp_private_key_enc: string | null }>(
      'SELECT saml_sp_private_key_enc FROM idp_configs WHERE id = $1',
      [idpConfig.id]
    );
    const enc = result.rows[0]?.saml_sp_private_key_enc;
    if (!enc) return null;
    return decrypt(enc);
  }

  // ─── Role Mappings ────────────────────────────────────────────────────────

  async setRoleMappings(
    tenantId: string,
    idpConfigId: string,
    mappings: Array<{ idpGroupValue: string; legoraRole: string }>
  ): Promise<void> {
    await withTransaction(async (client) => {
      // Replace all existing mappings for this IdP config
      await client.query(
        'DELETE FROM role_mappings WHERE tenant_id = $1 AND idp_config_id = $2',
        [tenantId, idpConfigId]
      );
      for (const m of mappings) {
        await client.query(
          `INSERT INTO role_mappings (tenant_id, idp_config_id, idp_group_value, legora_role)
           VALUES ($1, $2, $3, $4)`,
          [tenantId, idpConfigId, m.idpGroupValue, m.legoraRole]
        );
      }
    });

    await auditService.log({
      tenantId,
      idpConfigId,
      eventType: AuditEventType.ROLE_MAPPING_UPDATED,
      outcome: 'success',
      details: { mappingCount: mappings.length },
    });
  }

  async getRoleMappings(
    tenantId: string,
    idpConfigId: string
  ): Promise<Array<{ idpGroupValue: string; legoraRole: string }>> {
    const result = await query<{ idp_group_value: string; legora_role: string }>(
      'SELECT idp_group_value, legora_role FROM role_mappings WHERE tenant_id = $1 AND idp_config_id = $2',
      [tenantId, idpConfigId]
    );
    return result.rows.map((r) => ({
      idpGroupValue: r.idp_group_value,
      legoraRole: r.legora_role,
    }));
  }

  /**
   * Maps IdP groups to Legora roles using the configured role mappings.
   * Least-privilege: only the lowest-privilege role is assigned unless explicit.
   */
  mapGroupsToRoles(
    groups: string[],
    mappings: Array<{ idpGroupValue: string; legoraRole: string }>
  ): string[] {
    const roles = new Set<string>();
    for (const group of groups) {
      const mapping = mappings.find((m) => m.idpGroupValue === group);
      if (mapping) {
        roles.add(mapping.legoraRole);
      }
    }
    // Default to 'user' role if no mapping found
    if (roles.size === 0) roles.add('user');
    return Array.from(roles);
  }
}

export const tenantService = new TenantService();
