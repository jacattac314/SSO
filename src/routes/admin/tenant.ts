/**
 * Tenant administration API.
 *
 * POST   /admin/tenants                               – create tenant
 * GET    /admin/tenants/:tenantId                     – get tenant
 * POST   /admin/tenants/:tenantId/idp-configs         – add IdP configuration
 * GET    /admin/tenants/:tenantId/idp-configs         – list IdP configurations
 * GET    /admin/tenants/:tenantId/idp-configs/:id     – get IdP config
 * DELETE /admin/tenants/:tenantId/idp-configs/:id     – delete IdP config
 * PUT    /admin/tenants/:tenantId/idp-configs/:id/role-mappings – set role mappings
 * GET    /admin/tenants/:tenantId/idp-configs/:id/role-mappings – get role mappings
 * POST   /admin/tenants/:tenantId/idp-configs/:id/certificate   – rotate certificate
 * GET    /admin/tenants/:tenantId/audit-logs                     – query audit logs
 * POST   /admin/tenants/:tenantId/scim-token                     – rotate SCIM token
 */
import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { tenantService, IdpConfigCreateSchema } from '../../services/tenant.service';
import { certificateService } from '../../services/certificate.service';
import { auditService, AuditEventType } from '../../services/audit.service';
import { query } from '../../config/database';
import { generateToken } from '../../utils/crypto';
import { z } from 'zod';

const router = Router();

// ─── Tenants ─────────────────────────────────────────────────────────────────

router.post('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const schema = z.object({
      name: z.string().min(1),
      domain: z.string().min(1),
      ssoEnabled: z.boolean().default(false),
      scimEnabled: z.boolean().default(false),
    });
    const body = schema.parse(req.body);

    const result = await query<{ id: string }>(
      `INSERT INTO tenants (name, domain, sso_enabled, scim_enabled)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [body.name, body.domain, body.ssoEnabled, body.scimEnabled]
    );

    await auditService.log({
      tenantId: result.rows[0].id,
      eventType: AuditEventType.TENANT_CONFIG_CREATED,
      outcome: 'success',
      details: { name: body.name, domain: body.domain },
    });

    res.status(201).json({ tenantId: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: 'Failed to create tenant', detail: String(err) });
  }
});

router.get('/:tenantId', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenant = await tenantService.getTenant(req.params['tenantId']);
    if (!tenant) {
      res.status(404).json({ error: 'Tenant not found' });
      return;
    }
    // Omit sensitive fields
    const { scim_token_hash: _omit, ...safe } = tenant as Record<string, unknown>;
    res.json(safe);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ─── IdP Configurations ───────────────────────────────────────────────────────

router.post('/:tenantId/idp-configs', async (req: Request, res: Response): Promise<void> => {
  try {
    const body = IdpConfigCreateSchema.parse(req.body);
    const config = await tenantService.createIdpConfig(req.params['tenantId'], body);

    res.status(201).json({
      id: config.id,
      name: config.name,
      protocol: config.protocol,
      isDefault: config.is_default,
      createdAt: config.created_at,
    });
  } catch (err) {
    res.status(400).json({ error: 'Failed to create IdP configuration', detail: String(err) });
  }
});

router.get('/:tenantId/idp-configs', async (req: Request, res: Response): Promise<void> => {
  try {
    const configs = await tenantService.listIdpConfigs(req.params['tenantId']);
    res.json(
      configs.map((c) => ({
        id: c.id,
        name: c.name,
        protocol: c.protocol,
        isActive: c.is_active,
        isDefault: c.is_default,
        idpCertExpiresAt: c.idp_cert_expires_at,
        spCertExpiresAt: c.sp_cert_expires_at,
        createdAt: c.created_at,
      }))
    );
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

router.get('/:tenantId/idp-configs/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const { tenantId, id } = req.params;
    const config = await tenantService.getIdpConfig(tenantId, id);
    if (!config) {
      res.status(404).json({ error: 'IdP configuration not found' });
      return;
    }
    // Return config without encrypted secrets
    const {
      oidc_client_secret_enc: _secret,
      saml_sp_private_key_enc: _key,
      ...safe
    } = config as unknown as Record<string, unknown>;
    res.json(safe);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

router.delete('/:tenantId/idp-configs/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const { tenantId, id } = req.params;
    await query(
      'DELETE FROM idp_configs WHERE id = $1 AND tenant_id = $2',
      [id, tenantId]
    );
    await auditService.log({
      tenantId,
      idpConfigId: id,
      eventType: AuditEventType.IDP_CONFIG_DELETED,
      outcome: 'success',
    });
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ─── Role Mappings ────────────────────────────────────────────────────────────

router.put(
  '/:tenantId/idp-configs/:id/role-mappings',
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId, id } = req.params;
      const schema = z.object({
        mappings: z.array(
          z.object({
            idpGroupValue: z.string(),
            legoraRole: z.string(),
          })
        ),
      });
      const { mappings } = schema.parse(req.body);
      await tenantService.setRoleMappings(tenantId, id, mappings);
      res.json({ success: true, count: mappings.length });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  }
);

router.get(
  '/:tenantId/idp-configs/:id/role-mappings',
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId, id } = req.params;
      const mappings = await tenantService.getRoleMappings(tenantId, id);
      res.json({ mappings });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

// ─── Certificate Rotation ─────────────────────────────────────────────────────

router.post(
  '/:tenantId/idp-configs/:id/certificate',
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId, id } = req.params;
      const schema = z.object({ certificate: z.string() });
      const { certificate } = schema.parse(req.body);

      const certInfo = await certificateService.updateIdpCertificate(tenantId, id, certificate);

      await auditService.log({
        tenantId,
        idpConfigId: id,
        eventType: AuditEventType.CERT_ROTATED,
        outcome: 'success',
        details: {
          fingerprint: certInfo.fingerprint,
          expiresAt: certInfo.expiresAt,
          daysUntilExpiry: certInfo.daysUntilExpiry,
        },
      });

      res.json({
        fingerprint: certInfo.fingerprint,
        expiresAt: certInfo.expiresAt,
        daysUntilExpiry: certInfo.daysUntilExpiry,
        isExpiringSoon: certInfo.isExpiringSoon,
      });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  }
);

// ─── Audit Logs ───────────────────────────────────────────────────────────────

router.get('/:tenantId/audit-logs', async (req: Request, res: Response): Promise<void> => {
  try {
    const { tenantId } = req.params;
    const limit = parseInt(req.query['limit'] as string, 10) || 100;
    const offset = parseInt(req.query['offset'] as string, 10) || 0;
    const eventType = req.query['eventType'] as string | undefined;
    const outcome = req.query['outcome'] as 'success' | 'failure' | 'error' | undefined;
    const from = req.query['from'] ? new Date(req.query['from'] as string) : undefined;
    const to = req.query['to'] ? new Date(req.query['to'] as string) : undefined;

    const result = await auditService.queryLogs({
      tenantId,
      eventType,
      outcome,
      from,
      to,
      limit,
      offset,
    });

    res.json({
      total: result.total,
      offset,
      limit,
      logs: result.rows,
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ─── SCIM Token Rotation ──────────────────────────────────────────────────────

router.post('/:tenantId/scim-token', async (req: Request, res: Response): Promise<void> => {
  try {
    const { tenantId } = req.params;
    const newToken = generateToken(32);
    const tokenHash = await bcrypt.hash(newToken, 12);

    await query(
      'UPDATE tenants SET scim_token_hash = $1, scim_enabled = true WHERE id = $2',
      [tokenHash, tenantId]
    );

    // Return the token only once – it cannot be recovered after this response
    res.json({
      scimToken: newToken,
      warning: 'Store this token securely. It will not be shown again.',
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

export default router;
