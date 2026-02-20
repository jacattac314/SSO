/**
 * WebAuthn / FIDO2 service.
 * Implements phishing-resistant MFA per W3C WebAuthn Level 2.
 * Uses @simplewebauthn/server for server-side operations.
 */
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';
import { query } from '../config/database';
import { auditService, AuditEventType } from './audit.service';
import { webauthnLogger } from '../utils/logger';
import { config } from '../config';

const RP_NAME = 'Legora';
const RP_ID = new URL(config.BASE_URL).hostname;
const ORIGIN = config.BASE_URL;

// Pending challenge store (use Redis in production)
interface PendingChallenge {
  challenge: string;
  userId: string;
  tenantId: string;
  type: 'registration' | 'authentication';
  expiresAt: number;
}
const challengeStore = new Map<string, PendingChallenge>();
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface WebAuthnCredential {
  id: string;
  credentialId: string;
  credentialPublicKey: string;
  counter: bigint;
  transports: string[] | null;
  backedUp: boolean;
  deviceType: string | null;
}

class WebAuthnService {
  /**
   * Generates registration options for adding a new FIDO2 credential.
   * Excludes existing credentials to prevent duplicate registration.
   */
  async generateRegistrationOptions(
    userId: string,
    tenantId: string,
    userEmail: string,
    displayName: string
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    // Fetch existing credentials for this user (to exclude)
    const existing = await this.getUserCredentials(userId);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: userEmail,
      userDisplayName: displayName,
      userID: userId,
      // Prefer platform authenticators (Touch ID, Windows Hello, etc.)
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'required',  // FIDO2 requires UV for phishing resistance
      },
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
      excludeCredentials: existing.map((c) => ({
        id: Buffer.from(c.credentialId, 'base64url'),
        type: 'public-key' as const,
        transports: (c.transports ?? []) as AuthenticatorTransport[],
      })),
      attestationType: 'indirect', // Privacy-preserving attestation
      timeout: 60000,
    });

    // Store challenge
    this.storeChallenge(userId, options.challenge, userId, tenantId, 'registration');

    await auditService.log({
      tenantId,
      userId,
      eventType: AuditEventType.WEBAUTHN_REGISTER_STARTED,
      outcome: 'success',
    });

    return options;
  }

  /**
   * Verifies registration response and stores the new credential.
   */
  async verifyRegistration(
    userId: string,
    tenantId: string,
    response: RegistrationResponseJSON,
    credentialName?: string
  ): Promise<{ credentialId: string }> {
    const challengeKey = userId;
    const pendingChallenge = challengeStore.get(challengeKey);
    if (!pendingChallenge || pendingChallenge.type !== 'registration') {
      throw new Error('No pending registration challenge found');
    }
    if (pendingChallenge.expiresAt < Date.now()) {
      challengeStore.delete(challengeKey);
      throw new Error('Registration challenge expired');
    }
    challengeStore.delete(challengeKey);

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: pendingChallenge.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true, // FIDO2 UV required
      });
    } catch (err) {
      await auditService.log({
        tenantId,
        userId,
        eventType: AuditEventType.WEBAUTHN_REGISTER_FAILURE,
        outcome: 'failure',
        details: { error: String(err) },
      });
      throw err;
    }

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('WebAuthn registration verification failed');
    }

    const { credentialID, credentialPublicKey, counter, aaguid } =
      verification.registrationInfo;

    // Store credential in DB
    await query(
      `INSERT INTO webauthn_credentials (
        tenant_id, user_id, credential_id, credential_public_key,
        counter, device_type, backed_up, transports, aaguid, name
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        tenantId,
        userId,
        Buffer.from(credentialID).toString('base64url'),
        Buffer.from(credentialPublicKey).toString('base64url'),
        counter,
        verification.registrationInfo.credentialDeviceType,
        verification.registrationInfo.credentialBackedUp,
        response.response.transports ?? null,
        aaguid ?? null,
        credentialName ?? 'Security Key',
      ]
    );

    const credentialId = Buffer.from(credentialID).toString('base64url');

    await auditService.log({
      tenantId,
      userId,
      eventType: AuditEventType.WEBAUTHN_REGISTER_SUCCESS,
      outcome: 'success',
      details: {
        credentialId,
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        aaguid,
      },
    });

    webauthnLogger.info('WebAuthn credential registered', { userId, credentialId });
    return { credentialId };
  }

  /**
   * Generates authentication options for FIDO2 login.
   */
  async generateAuthenticationOptions(
    userId: string,
    tenantId: string
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const credentials = await this.getUserCredentials(userId);
    if (credentials.length === 0) {
      throw new Error('No WebAuthn credentials registered for this user');
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'required',
      allowCredentials: credentials.map((c) => ({
        id: Buffer.from(c.credentialId, 'base64url'),
        type: 'public-key' as const,
        transports: (c.transports ?? []) as AuthenticatorTransport[],
      })),
      timeout: 60000,
    });

    this.storeChallenge(userId, options.challenge, userId, tenantId, 'authentication');

    return options;
  }

  /**
   * Verifies authentication response and updates the credential counter.
   */
  async verifyAuthentication(
    userId: string,
    tenantId: string,
    response: AuthenticationResponseJSON,
    ipAddress?: string
  ): Promise<{ verified: boolean; credentialId: string }> {
    const challengeKey = userId;
    const pendingChallenge = challengeStore.get(challengeKey);
    if (!pendingChallenge || pendingChallenge.type !== 'authentication') {
      throw new Error('No pending authentication challenge found');
    }
    if (pendingChallenge.expiresAt < Date.now()) {
      challengeStore.delete(challengeKey);
      throw new Error('Authentication challenge expired');
    }
    challengeStore.delete(challengeKey);

    const credentialId = response.id;
    const credential = await this.getCredentialById(credentialId);
    if (!credential || credential.userId !== userId) {
      await auditService.log({
        tenantId,
        userId,
        eventType: AuditEventType.WEBAUTHN_VERIFY_FAILURE,
        outcome: 'failure',
        ipAddress,
        details: { reason: 'credential_not_found', credentialId },
      });
      throw new Error('WebAuthn credential not found for this user');
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: pendingChallenge.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true,
        authenticator: {
          credentialID: Buffer.from(credential.credentialId, 'base64url'),
          credentialPublicKey: Buffer.from(credential.credentialPublicKey, 'base64url'),
          counter: Number(credential.counter),
          transports: (credential.transports ?? []) as AuthenticatorTransport[],
        },
      });
    } catch (err) {
      await auditService.log({
        tenantId,
        userId,
        eventType: AuditEventType.WEBAUTHN_VERIFY_FAILURE,
        outcome: 'failure',
        ipAddress,
        details: { error: String(err), credentialId },
      });
      throw err;
    }

    if (!verification.verified) {
      return { verified: false, credentialId };
    }

    // Update counter (anti-clone protection)
    await query(
      `UPDATE webauthn_credentials
         SET counter = $1, last_used_at = NOW()
       WHERE credential_id = $2`,
      [verification.authenticationInfo.newCounter, credentialId]
    );

    await auditService.log({
      tenantId,
      userId,
      eventType: AuditEventType.WEBAUTHN_VERIFY_SUCCESS,
      outcome: 'success',
      ipAddress,
      details: {
        credentialId,
        userVerified: verification.authenticationInfo.userVerified,
      },
    });

    webauthnLogger.info('WebAuthn authentication verified', { userId, credentialId });
    return { verified: true, credentialId };
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private async getUserCredentials(
    userId: string
  ): Promise<(WebAuthnCredential & { userId: string })[]> {
    const result = await query<WebAuthnCredential & { user_id: string }>(
      'SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at',
      [userId]
    );
    return result.rows.map((r) => ({ ...r, userId: r.user_id }));
  }

  private async getCredentialById(
    credentialId: string
  ): Promise<(WebAuthnCredential & { userId: string }) | null> {
    const result = await query<WebAuthnCredential & { user_id: string }>(
      'SELECT * FROM webauthn_credentials WHERE credential_id = $1',
      [credentialId]
    );
    if (result.rows.length === 0) return null;
    return { ...result.rows[0], userId: result.rows[0].user_id };
  }

  private storeChallenge(
    key: string,
    challenge: string,
    userId: string,
    tenantId: string,
    type: 'registration' | 'authentication'
  ): void {
    challengeStore.set(key, {
      challenge,
      userId,
      tenantId,
      type,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    });
    setTimeout(() => challengeStore.delete(key), CHALLENGE_TTL_MS);
  }
}

export const webauthnService = new WebAuthnService();
