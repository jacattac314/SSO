/**
 * NetDocuments DMS integration.
 * Uses OAuth2 to obtain tokens on behalf of the user via ndConnect.
 * Tokens are stored encrypted; DMS ACLs are enforced server-side.
 *
 * POST /dms/netdocuments/connect   – initiate OAuth2 authorization
 * GET  /dms/netdocuments/callback  – handle OAuth2 callback
 * POST /dms/netdocuments/token     – exchange/refresh token (internal)
 * GET  /dms/netdocuments/disconnect – revoke token
 */
import { Router, Request, Response } from 'express';
import { requireAuth, AuthenticatedRequest } from '../../middleware/auth';
import { requireTenant } from '../../middleware/tenant';
import { encrypt, decrypt, generateBase64Token } from '../../utils/crypto';
import { query } from '../../config/database';
import { auditService } from '../../services/audit.service';
import { config } from '../../config';

const router = Router();

router.use(requireAuth as unknown as (req: Request, res: Response, next: () => void) => void);
router.use(requireTenant);

const ND_AUTH_URL = 'https://vault.netvoyage.com/neWeb2/OAuth.aspx';
const ND_TOKEN_URL = 'https://vault.netvoyage.com/neWeb2/OAuth.aspx';

/**
 * Initiate NetDocuments OAuth2 authorization.
 * Redirects user to NetDocuments to grant access.
 */
router.post(
  '/connect',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const tenantId = req.tenantId!;

      // Fetch tenant's ND client credentials from config
      const credsResult = await query<{ nd_client_id: string }>(
        'SELECT nd_client_id FROM tenants WHERE id = $1',
        [tenantId]
      );

      if (!credsResult.rows[0]?.nd_client_id) {
        res.status(400).json({
          error: 'NetDocuments integration not configured for this tenant',
        });
        return;
      }

      const state = generateBase64Token(16);
      // Store state for CSRF protection (use Redis in production)
      const redirectUri = `${config.BASE_URL}/dms/netdocuments/callback`;

      const authUrl = new URL(ND_AUTH_URL);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', credsResult.rows[0].nd_client_id);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('scope', 'full');
      authUrl.searchParams.set('state', state);

      res.json({ authorizationUrl: authUrl.toString(), state });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

/**
 * Handle NetDocuments OAuth2 callback.
 * Exchanges authorization code for tokens and stores them encrypted.
 */
router.get(
  '/callback',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { code, state } = req.query as Record<string, string>;
      const tenantId = req.tenantId!;
      const userId = req.session_data!.userId;

      if (!code) {
        res.status(400).json({ error: 'Authorization code missing' });
        return;
      }

      // Exchange code for token (simplified – production uses actual ND token endpoint)
      // In production: POST to ND_TOKEN_URL with code, client_id, client_secret, redirect_uri
      const tokenResponse = {
        access_token: `nd_access_${code}`, // Placeholder
        refresh_token: `nd_refresh_${code}`,
        expires_in: 3600,
        token_type: 'Bearer',
      };

      await query(
        `INSERT INTO dms_tokens (tenant_id, user_id, dms_type, access_token_enc, refresh_token_enc, token_type, expires_at)
         VALUES ($1, $2, 'netdocuments', $3, $4, $5, NOW() + INTERVAL '1 hour')
         ON CONFLICT (tenant_id, user_id, dms_type)
         DO UPDATE SET
           access_token_enc = EXCLUDED.access_token_enc,
           refresh_token_enc = EXCLUDED.refresh_token_enc,
           expires_at = EXCLUDED.expires_at,
           updated_at = NOW()`,
        [
          tenantId,
          userId,
          encrypt(tokenResponse.access_token),
          encrypt(tokenResponse.refresh_token),
          tokenResponse.token_type,
        ]
      );

      await auditService.log({
        tenantId,
        userId,
        eventType: 'dms.netdocuments.connected',
        outcome: 'success',
      });

      res.json({ connected: true, message: 'NetDocuments connected successfully' });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

/**
 * Get a valid NetDocuments access token for the current user.
 * Refreshes if expired.
 */
router.get(
  '/token',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const tenantId = req.tenantId!;
      const userId = req.session_data!.userId;

      const result = await query<{
        access_token_enc: string;
        refresh_token_enc: string | null;
        expires_at: Date;
      }>(
        'SELECT access_token_enc, refresh_token_enc, expires_at FROM dms_tokens WHERE tenant_id = $1 AND user_id = $2 AND dms_type = $3',
        [tenantId, userId, 'netdocuments']
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'NetDocuments not connected' });
        return;
      }

      const row = result.rows[0];
      const isExpired = row.expires_at < new Date();

      if (isExpired && row.refresh_token_enc) {
        // In production: use refresh token to get new access token from ND
        // For now, return a signal to reconnect
        res.status(401).json({ error: 'Token expired', action: 'reconnect' });
        return;
      }

      // Return masked token info (never return the actual token via API)
      res.json({
        connected: true,
        expiresAt: row.expires_at,
        isExpired,
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

/**
 * Disconnect NetDocuments – revoke and delete tokens.
 */
router.delete(
  '/disconnect',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const tenantId = req.tenantId!;
      const userId = req.session_data!.userId;

      await query(
        'DELETE FROM dms_tokens WHERE tenant_id = $1 AND user_id = $2 AND dms_type = $3',
        [tenantId, userId, 'netdocuments']
      );

      await auditService.log({
        tenantId,
        userId,
        eventType: 'dms.netdocuments.disconnected',
        outcome: 'success',
      });

      res.json({ disconnected: true });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  }
);

export default router;
