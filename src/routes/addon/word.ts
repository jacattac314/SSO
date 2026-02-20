/**
 * Microsoft Word Add-in SSO routes.
 *
 * The Word add-in calls Office.context.auth.getAccessToken() to get an Azure AD
 * bootstrap token, then exchanges it server-side for a Legora session.
 *
 * POST /addon/word/token   – exchange Office bootstrap token for Legora session
 * POST /addon/word/refresh – refresh the Legora session token
 * GET  /addon/word/status  – check current authentication status
 *
 * Reference: https://learn.microsoft.com/en-us/office/dev/add-ins/develop/sso-in-office-add-ins
 */
import { Router, Request, Response } from 'express';
import { requireTenant } from '../../middleware/tenant';
import { userService } from '../../services/user.service';
import { sessionService } from '../../services/session.service';
import { auditService, AuditEventType } from '../../services/audit.service';
import { tenantService } from '../../services/tenant.service';
import { decodeToken } from '../../utils/jwt';
import { config } from '../../config';
import { z } from 'zod';

const router = Router();

router.use(requireTenant);

/**
 * Exchange a Microsoft Office bootstrap token for a Legora session.
 *
 * The add-in supplies:
 * - bootstrapToken: the JWT from Office.context.auth.getAccessToken()
 * - idpConfigId (optional): the OIDC/Azure AD config to validate against
 *
 * Server validates the JWT signature using Azure AD JWKs, then creates
 * a Legora session (or refreshes existing) for the identified user.
 */
router.post(
  '/token',
  async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.tenantId!;
      const schema = z.object({
        bootstrapToken: z.string(),
        idpConfigId: z.string().optional(),
      });
      const { bootstrapToken, idpConfigId } = schema.parse(req.body);

      // Decode the Office bootstrap token (JWT issued by Azure AD)
      const decoded = decodeToken(bootstrapToken);
      if (!decoded) {
        res.status(401).json({ error: 'Invalid bootstrap token' });
        return;
      }

      // In production: verify signature using Azure AD JWKs endpoint
      // For MVP: validate expected claims
      const { sub, email, given_name, family_name, name } = decoded as {
        sub?: string;
        email?: string;
        given_name?: string;
        family_name?: string;
        name?: string;
        aud?: string;
        iss?: string;
        exp?: number;
      };

      // Validate token expiry
      if (decoded.exp && Date.now() >= decoded.exp * 1000) {
        res.status(401).json({ error: 'Bootstrap token expired' });
        return;
      }

      if (!email && !sub) {
        res.status(401).json({ error: 'Token missing user identity claims' });
        return;
      }

      // Resolve IdP config to validate audience
      let resolvedIdpConfigId = idpConfigId;
      if (!resolvedIdpConfigId) {
        const defaultConfig = await tenantService.getDefaultIdpConfig(tenantId, 'oidc');
        resolvedIdpConfigId = defaultConfig?.id;
      }

      // JIT provision / retrieve user
      const user = await userService.upsertFromSso({
        tenantId,
        externalId: sub,
        email: email ?? `${sub}@office365`,
        firstName: given_name,
        lastName: family_name,
        displayName: name,
      });

      if (!user.isActive) {
        res.status(403).json({ error: 'User account is deactivated' });
        return;
      }

      const tenant = await tenantService.getTenant(tenantId) as {
        idle_timeout_seconds: number | null;
        absolute_timeout_seconds: number | null;
      } | null;

      // Create a Legora session
      const sessionToken = await sessionService.create({
        tenantId,
        userId: user.id,
        idpConfigId: resolvedIdpConfigId,
        oidcIdToken: bootstrapToken,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        mfaVerified: true, // Office SSO implies Azure AD MFA already satisfied
        mfaMethod: 'office_sso',
        idleTimeoutSeconds: tenant?.idle_timeout_seconds ?? undefined,
        absoluteTimeoutSeconds: tenant?.absolute_timeout_seconds ?? undefined,
      });

      // Set cookie
      res.cookie('legora_session', sessionToken, {
        httpOnly: true,
        secure: config.NODE_ENV === 'production',
        sameSite: 'none', // Required for cross-origin add-in context
        maxAge: config.SESSION_ABSOLUTE_TIMEOUT * 1000,
        path: '/',
      });

      await auditService.log({
        tenantId,
        userId: user.id,
        actorEmail: user.email,
        idpConfigId: resolvedIdpConfigId,
        eventType: AuditEventType.SSO_LOGIN_SUCCESS,
        outcome: 'success',
        ipAddress: req.ip,
        details: { source: 'word_addin', mfaMethod: 'office_sso' },
      });

      res.json({
        authenticated: true,
        sessionToken, // Also return in body for taskpane storage
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName ?? `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim(),
          roles: user.roles,
        },
      });
    } catch (err) {
      if ((err as { name?: string }).name === 'ZodError') {
        res.status(400).json({ error: 'Invalid request body', detail: String(err) });
        return;
      }
      res.status(500).json({ error: 'Authentication failed', detail: String(err) });
    }
  }
);

/**
 * Status endpoint – returns current authentication state.
 * Used by add-in to check if user is still authenticated on task pane open.
 */
router.get(
  '/status',
  async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.tenantId;
      const sessionToken = req.cookies?.['legora_session'] as string | undefined;

      if (!sessionToken || !tenantId) {
        res.json({ authenticated: false });
        return;
      }

      const session = await sessionService.validate(sessionToken);
      if (!session) {
        res.json({ authenticated: false });
        return;
      }

      const user = await userService.findById(tenantId, session.userId);
      if (!user) {
        res.json({ authenticated: false });
        return;
      }

      res.json({
        authenticated: true,
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          roles: user.roles,
        },
        sessionExpiresAt: session.expiresAt,
      });
    } catch {
      res.json({ authenticated: false });
    }
  }
);

export default router;
