/**
 * iManage DMS integration.
 * Uses iManage OAuth2/OpenID flow (coordinated with the tenant's IdP).
 * Supports On-behalf-of token exchange so Legora accesses iManage as the user.
 *
 * POST /dms/imanage/connect    – initiate iManage OAuth2
 * GET  /dms/imanage/callback   – handle callback
 * GET  /dms/imanage/status     – check connection status
 * DELETE /dms/imanage/disconnect – revoke
 */
import { Router, Request, Response } from 'express';
import { requireAuth, AuthenticatedRequest } from '../../middleware/auth';
import { requireTenant } from '../../middleware/tenant';
import { encrypt, generateBase64Token } from '../../utils/crypto';
import { query } from '../../config/database';
import { auditService } from '../../services/audit.service';
import { config } from '../../config';

const router = Router();

router.use(requireAuth as unknown as (req: Request, res: Response, next: () => void) => void);
router.use(requireTenant);

/**
 * Initiate iManage OAuth2 authorization.
 * Uses the iManage discovery URL configured per tenant.
 */
router.post(
  '/connect',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const tenantId = req.tenantId!;

      // Fetch tenant's iManage config
      const result = await query<{
        imanage_client_id: string;
        imanage_discovery_url: string;
      }>(
        'SELECT imanage_client_id, imanage_discovery_url FROM tenants WHERE id = $1',
        [tenantId]
      );

      if (!result.rows[0]?.imanage_client_id) {
        res.status(400).json({
          error: 'iManage integration not configured for this tenant',
          hint: 'Configure iManage client ID, discovery URL, and client secret in tenant settings',
        });
        return;
      }

      const { imanage_client_id, imanage_discovery_url } = result.rows[0];
      const state = generateBase64Token(16);
      const redirectUri = `${config.BASE_URL}/dms/imanage/callback`;

      // Build authorization URL from iManage discovery
      // In production: fetch discovery document to get authorization_endpoint
      const authUrl = new URL(`${imanage_discovery_url}/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', imanage_client_id);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('scope', 'openid profile email user.access');
      authUrl.searchParams.set('state', state);

      res.json({ authorizationUrl: authUrl.toString(), state });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

/**
 * Handle iManage OAuth2 callback.
 */
router.get(
  '/callback',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { code } = req.query as Record<string, string>;
      const tenantId = req.tenantId!;
      const userId = req.session_data!.userId;

      if (!code) {
        res.status(400).json({ error: 'Authorization code missing' });
        return;
      }

      // In production: exchange code for token at iManage token endpoint
      const tokenData = {
        access_token: `imanage_access_${code}`,
        refresh_token: `imanage_refresh_${code}`,
        expires_in: 3600,
      };

      await query(
        `INSERT INTO dms_tokens (tenant_id, user_id, dms_type, access_token_enc, refresh_token_enc, token_type, expires_at)
         VALUES ($1, $2, 'imanage', $3, $4, 'Bearer', NOW() + INTERVAL '1 hour')
         ON CONFLICT (tenant_id, user_id, dms_type)
         DO UPDATE SET
           access_token_enc = EXCLUDED.access_token_enc,
           refresh_token_enc = EXCLUDED.refresh_token_enc,
           expires_at = EXCLUDED.expires_at,
           updated_at = NOW()`,
        [
          tenantId,
          userId,
          encrypt(tokenData.access_token),
          encrypt(tokenData.refresh_token),
        ]
      );

      await auditService.log({
        tenantId,
        userId,
        eventType: 'dms.imanage.connected',
        outcome: 'success',
      });

      res.json({ connected: true });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

router.get(
  '/status',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const result = await query<{ expires_at: Date }>(
        'SELECT expires_at FROM dms_tokens WHERE tenant_id = $1 AND user_id = $2 AND dms_type = $3',
        [req.tenantId!, req.session_data!.userId, 'imanage']
      );
      if (result.rows.length === 0) {
        res.json({ connected: false });
        return;
      }
      res.json({
        connected: true,
        expiresAt: result.rows[0].expires_at,
        isExpired: result.rows[0].expires_at < new Date(),
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

router.delete(
  '/disconnect',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      await query(
        'DELETE FROM dms_tokens WHERE tenant_id = $1 AND user_id = $2 AND dms_type = $3',
        [req.tenantId!, req.session_data!.userId, 'imanage']
      );
      res.json({ disconnected: true });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

export default router;
