/**
 * WebAuthn / FIDO2 routes.
 *
 * POST /auth/webauthn/register/options    – get registration challenge
 * POST /auth/webauthn/register/verify     – verify registration
 * POST /auth/webauthn/authenticate/options – get authentication challenge
 * POST /auth/webauthn/authenticate/verify  – verify authentication
 * GET  /auth/webauthn/credentials          – list user's credentials
 * DELETE /auth/webauthn/credentials/:id    – remove a credential
 */
import { Router, Request, Response } from 'express';
import { webauthnService } from '../../services/webauthn.service';
import { userService } from '../../services/user.service';
import { requireAuth, AuthenticatedRequest } from '../../middleware/auth';
import { requireTenant } from '../../middleware/tenant';

const router = Router();

// All WebAuthn routes require an authenticated session
router.use(requireAuth as unknown as (req: Request, res: Response, next: () => void) => void);

/**
 * Generate registration options for adding a new FIDO2 credential.
 */
router.post(
  '/register/options',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { userId, tenantId } = req.session_data!;
      const user = await userService.findById(tenantId, userId);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const options = await webauthnService.generateRegistrationOptions(
        userId,
        tenantId,
        user.email,
        (user.displayName ?? `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim()) || user.email
      );

      res.json(options);
    } catch (err) {
      res.status(500).json({ error: 'Failed to generate registration options', detail: String(err) });
    }
  }
);

/**
 * Verify WebAuthn registration and store the new credential.
 */
router.post(
  '/register/verify',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { userId, tenantId } = req.session_data!;
      const credentialName = (req.body as { credentialName?: string }).credentialName;

      const result = await webauthnService.verifyRegistration(
        userId,
        tenantId,
        req.body,
        credentialName
      );

      res.json({ success: true, credentialId: result.credentialId });
    } catch (err) {
      res.status(400).json({ error: 'Registration verification failed', detail: String(err) });
    }
  }
);

/**
 * Generate authentication options for FIDO2 login.
 * Called after initial SSO assertion to add phishing-resistant MFA.
 */
router.post(
  '/authenticate/options',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { userId, tenantId } = req.session_data!;

      const options = await webauthnService.generateAuthenticationOptions(userId, tenantId);
      res.json(options);
    } catch (err) {
      res.status(400).json({ error: 'Failed to generate authentication options', detail: String(err) });
    }
  }
);

/**
 * Verify WebAuthn authentication.
 * On success, marks session as MFA-verified.
 */
router.post(
  '/authenticate/verify',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { userId, tenantId } = req.session_data!;

      const result = await webauthnService.verifyAuthentication(
        userId,
        tenantId,
        req.body,
        req.ip
      );

      if (!result.verified) {
        res.status(401).json({ error: 'WebAuthn verification failed' });
        return;
      }

      // Mark session as MFA-verified
      const { query } = await import('../../config/database');
      await query(
        `UPDATE sso_sessions
           SET mfa_verified = true, mfa_method = 'webauthn'
         WHERE user_id = $1 AND session_token = $2`,
        [userId, req.cookies?.['legora_session']]
      );

      res.json({ verified: true });
    } catch (err) {
      res.status(400).json({ error: 'Authentication verification failed', detail: String(err) });
    }
  }
);

/**
 * List registered WebAuthn credentials for the current user.
 */
router.get(
  '/credentials',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { userId, tenantId } = req.session_data!;
      const { query } = await import('../../config/database');

      const result = await query<{
        id: string;
        credential_id: string;
        device_type: string | null;
        backed_up: boolean;
        transports: string[] | null;
        aaguid: string | null;
        name: string | null;
        created_at: Date;
        last_used_at: Date | null;
      }>(
        `SELECT id, credential_id, device_type, backed_up, transports,
                aaguid, name, created_at, last_used_at
           FROM webauthn_credentials
          WHERE user_id = $1 AND tenant_id = $2
          ORDER BY created_at`,
        [userId, tenantId]
      );

      res.json({ credentials: result.rows });
    } catch (err) {
      res.status(500).json({ error: 'Failed to list credentials', detail: String(err) });
    }
  }
);

/**
 * Delete a WebAuthn credential.
 */
router.delete(
  '/credentials/:credentialId',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { userId, tenantId } = req.session_data!;
      const { credentialId } = req.params;

      const { query } = await import('../../config/database');
      const result = await query(
        'DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2 AND tenant_id = $3',
        [credentialId, userId, tenantId]
      );

      if ((result.rowCount ?? 0) === 0) {
        res.status(404).json({ error: 'Credential not found' });
        return;
      }

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to delete credential', detail: String(err) });
    }
  }
);

export default router;
