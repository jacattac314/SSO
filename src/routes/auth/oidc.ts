/**
 * OIDC authentication routes.
 *
 * GET  /auth/oidc/:tenantId/login           – initiate SP-initiated OIDC login
 * GET  /auth/oidc/:tenantId/callback        – handle authorization code callback
 * GET  /auth/oidc/:tenantId/logout          – initiate OIDC RP-initiated logout
 * GET  /auth/logout/complete                – post-logout landing page
 */
import { Router, Request, Response } from 'express';
import { oidcService } from '../../services/oidc.service';
import { sessionService } from '../../services/session.service';
import { tenantService } from '../../services/tenant.service';
import { requireTenant } from '../../middleware/tenant';
import { requireAuth, AuthenticatedRequest } from '../../middleware/auth';
import { config } from '../../config';

const router = Router();

/**
 * SP-initiated OIDC login.
 * Optionally accepts `idpConfigId` query param; otherwise uses tenant default.
 */
router.get(
  '/:tenantId/login',
  requireTenant,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId } = req.params;
      const idpConfigId = req.query['idpConfigId'] as string | undefined;
      const redirectAfterLogin = req.query['redirect'] as string | undefined;

      let resolvedIdpConfigId = idpConfigId;
      if (!resolvedIdpConfigId) {
        const defaultConfig = await tenantService.getDefaultIdpConfig(tenantId, 'oidc');
        if (!defaultConfig) {
          res.status(404).json({ error: 'No OIDC configuration found for tenant' });
          return;
        }
        resolvedIdpConfigId = defaultConfig.id;
      }

      const authUrl = await oidcService.initiateLogin(
        tenantId,
        resolvedIdpConfigId,
        redirectAfterLogin
      );

      res.redirect(authUrl);
    } catch (err) {
      res.status(500).json({ error: 'Failed to initiate OIDC login', detail: String(err) });
    }
  }
);

/**
 * OIDC authorization code callback.
 */
router.get(
  '/:tenantId/callback',
  requireTenant,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId } = req.params;
      const state = req.query['state'] as string;
      const code = req.query['code'] as string;
      const error = req.query['error'] as string | undefined;

      if (error) {
        res.status(400).json({
          error: 'IdP returned error',
          idpError: error,
          description: req.query['error_description'],
        });
        return;
      }

      if (!state || !code) {
        res.status(400).json({ error: 'Missing state or code parameter' });
        return;
      }

      const { sessionToken, redirectUrl, user } = await oidcService.handleCallback(
        state,
        { code, state },
        req.ip,
        req.headers['user-agent']
      );

      // Set session cookie (HttpOnly, Secure, SameSite=Lax)
      res.cookie('legora_session', sessionToken, {
        httpOnly: true,
        secure: config.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: config.SESSION_ABSOLUTE_TIMEOUT * 1000,
        path: '/',
      });

      const destination = redirectUrl ?? `${config.BASE_URL}/app`;
      res.redirect(destination);
    } catch (err) {
      res.status(401).json({ error: 'OIDC authentication failed', detail: String(err) });
    }
  }
);

/**
 * OIDC logout (SP-initiated RP-initiated logout).
 */
router.get(
  '/:tenantId/logout',
  requireTenant,
  requireAuth as unknown as (req: Request, res: Response, next: () => void) => void,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const sessionToken = req.cookies?.['legora_session'] as string | undefined;
      if (sessionToken) {
        // Get session data for OIDC ID token hint
        const session = await sessionService.validate(sessionToken);
        const idToken = session?.oidcIdToken ?? undefined;
        const idpConfigId = session?.idpConfigId ?? undefined;

        await sessionService.terminate(sessionToken, 'logout');
        res.clearCookie('legora_session');

        if (idpConfigId) {
          const logoutUrl = await oidcService.initiateLogout(
            req.params['tenantId'],
            idpConfigId,
            idToken
          );
          if (logoutUrl) {
            res.redirect(logoutUrl);
            return;
          }
        }
      }

      res.redirect(`${config.BASE_URL}/auth/logout/complete`);
    } catch {
      res.status(500).json({ error: 'Logout failed' });
    }
  }
);

/**
 * Post-logout landing page.
 */
router.get('/logout/complete', (_req: Request, res: Response): void => {
  res.json({ message: 'You have been logged out successfully.' });
});

export default router;
