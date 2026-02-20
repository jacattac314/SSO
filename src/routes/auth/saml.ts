/**
 * SAML 2.0 authentication routes.
 *
 * GET  /auth/saml/:tenantId/login            – SP-initiated login (redirect binding)
 * POST /auth/saml/:tenantId/acs              – Assertion Consumer Service
 * GET  /auth/saml/:tenantId/metadata         – SP metadata XML
 * GET  /auth/saml/:tenantId/logout           – SP-initiated SLO
 * POST /auth/saml/:tenantId/slo              – IdP-initiated SLO (POST binding)
 * GET  /auth/saml/:tenantId/slo              – IdP-initiated SLO (Redirect binding)
 */
import { Router, Request, Response } from 'express';
import { samlService } from '../../services/saml.service';
import { sessionService } from '../../services/session.service';
import { tenantService } from '../../services/tenant.service';
import { requireTenant } from '../../middleware/tenant';
import { requireAuth, AuthenticatedRequest } from '../../middleware/auth';
import { config } from '../../config';

const router = Router();

/**
 * SP-initiated SAML login.
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
        const defaultConfig = await tenantService.getDefaultIdpConfig(tenantId, 'saml');
        if (!defaultConfig) {
          res.status(404).json({ error: 'No SAML configuration found for tenant' });
          return;
        }
        resolvedIdpConfigId = defaultConfig.id;
      }

      const authUrl = await samlService.initiateLogin(
        tenantId,
        resolvedIdpConfigId,
        redirectAfterLogin
      );

      res.redirect(authUrl);
    } catch (err) {
      res.status(500).json({ error: 'Failed to initiate SAML login', detail: String(err) });
    }
  }
);

/**
 * Assertion Consumer Service (ACS) – receives SAML assertion from IdP.
 * Supports both SP-initiated (with InResponseTo) and IdP-initiated flows.
 */
router.post(
  '/:tenantId/acs',
  requireTenant,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId } = req.params;

      // IdP config can be from query param or inferred from SAMLResponse
      const idpConfigId = req.query['idpConfigId'] as string | undefined;

      let resolvedIdpConfigId = idpConfigId;
      if (!resolvedIdpConfigId) {
        const defaultConfig = await tenantService.getDefaultIdpConfig(tenantId, 'saml');
        if (!defaultConfig) {
          res.status(404).json({ error: 'No SAML configuration found for tenant' });
          return;
        }
        resolvedIdpConfigId = defaultConfig.id;
      }

      const { sessionToken, relayState } = await samlService.handleAcs(
        tenantId,
        resolvedIdpConfigId,
        req.body as Record<string, string>,
        req.ip,
        req.headers['user-agent']
      );

      // Set session cookie
      res.cookie('legora_session', sessionToken, {
        httpOnly: true,
        secure: config.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: config.SESSION_ABSOLUTE_TIMEOUT * 1000,
        path: '/',
      });

      // Redirect to RelayState URL or default app
      let destination = `${config.BASE_URL}/app`;
      if (relayState && relayState.startsWith('http')) {
        // Validate RelayState is an allowed destination (prevent open redirect)
        try {
          const url = new URL(relayState);
          const allowedHosts = [new URL(config.BASE_URL).hostname];
          if (allowedHosts.includes(url.hostname)) {
            destination = relayState;
          }
        } catch {
          // Invalid URL – use default
        }
      }

      res.redirect(destination);
    } catch (err) {
      res.status(401).json({ error: 'SAML authentication failed', detail: String(err) });
    }
  }
);

/**
 * SP Metadata endpoint.
 * Returns SAML SP metadata XML for this tenant/IdP configuration.
 */
router.get(
  '/:tenantId/metadata',
  requireTenant,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId } = req.params;
      const idpConfigId = req.query['idpConfigId'] as string | undefined;

      let resolvedIdpConfigId = idpConfigId;
      if (!resolvedIdpConfigId) {
        const defaultConfig = await tenantService.getDefaultIdpConfig(tenantId, 'saml');
        if (!defaultConfig) {
          res.status(404).json({ error: 'No SAML configuration found for tenant' });
          return;
        }
        resolvedIdpConfigId = defaultConfig.id;
      }

      const metadata = await samlService.getSpMetadata(tenantId, resolvedIdpConfigId);

      res.set('Content-Type', 'application/xml');
      res.send(metadata);
    } catch (err) {
      res.status(500).json({ error: 'Failed to generate SP metadata', detail: String(err) });
    }
  }
);

/**
 * SP-initiated Single Logout.
 * Redirects to IdP SLO endpoint.
 */
router.get(
  '/:tenantId/logout',
  requireTenant,
  requireAuth as unknown as (req: Request, res: Response, next: () => void) => void,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { tenantId } = req.params;
      const sessionToken = req.cookies?.['legora_session'] as string | undefined;

      if (!sessionToken) {
        res.redirect(`${config.BASE_URL}/auth/logout/complete`);
        return;
      }

      const session = await sessionService.validate(sessionToken);
      if (!session) {
        res.clearCookie('legora_session');
        res.redirect(`${config.BASE_URL}/auth/logout/complete`);
        return;
      }

      const { samlNameId, samlSessionIndex, samlNameIdFormat, idpConfigId } = session;

      // Terminate local session first
      await sessionService.terminate(sessionToken, 'logout');
      res.clearCookie('legora_session');

      // Initiate SLO if SAML session data is available
      if (idpConfigId && samlNameId) {
        const sloUrl = await samlService.initiateLogout(
          tenantId,
          idpConfigId,
          samlNameId,
          samlSessionIndex ?? undefined,
          samlNameIdFormat ?? undefined
        );
        if (sloUrl) {
          res.redirect(sloUrl);
          return;
        }
      }

      res.redirect(`${config.BASE_URL}/auth/logout/complete`);
    } catch {
      res.status(500).json({ error: 'Logout failed' });
    }
  }
);

/**
 * Handle IdP-initiated SLO via HTTP-POST binding.
 */
router.post(
  '/:tenantId/slo',
  requireTenant,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId } = req.params;

      const idpConfigId = req.query['idpConfigId'] as string | undefined;
      let resolvedIdpConfigId = idpConfigId;
      if (!resolvedIdpConfigId) {
        const defaultConfig = await tenantService.getDefaultIdpConfig(tenantId, 'saml');
        if (!defaultConfig) {
          res.status(404).json({ error: 'No SAML configuration' });
          return;
        }
        resolvedIdpConfigId = defaultConfig.id;
      }

      const { redirectUrl } = await samlService.handleSloRequest(
        tenantId,
        resolvedIdpConfigId,
        req.body as Record<string, string>,
        req.query as Record<string, string>
      );

      res.redirect(redirectUrl);
    } catch (err) {
      res.status(400).json({ error: 'SLO request failed', detail: String(err) });
    }
  }
);

/**
 * Handle IdP-initiated SLO via HTTP-Redirect binding.
 */
router.get(
  '/:tenantId/slo',
  requireTenant,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { tenantId } = req.params;

      const idpConfigId = req.query['idpConfigId'] as string | undefined;
      let resolvedIdpConfigId = idpConfigId;
      if (!resolvedIdpConfigId) {
        const defaultConfig = await tenantService.getDefaultIdpConfig(tenantId, 'saml');
        if (!defaultConfig) {
          res.status(404).json({ error: 'No SAML configuration' });
          return;
        }
        resolvedIdpConfigId = defaultConfig.id;
      }

      const { redirectUrl } = await samlService.handleSloRequest(
        tenantId,
        resolvedIdpConfigId,
        req.body as Record<string, string>,
        req.query as Record<string, string>
      );

      res.redirect(redirectUrl);
    } catch (err) {
      res.status(400).json({ error: 'SLO request failed', detail: String(err) });
    }
  }
);

export default router;
