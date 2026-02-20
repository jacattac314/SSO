/**
 * OIDC authentication service.
 * Implements the Authorization Code Flow with PKCE per RFC 7636.
 * Uses openid-client for standard OIDC interactions.
 */
import {
  Issuer,
  Client,
  generators,
  CallbackParamsType,
  TokenSet,
  UserinfoResponse,
} from 'openid-client';
import { query } from '../config/database';
import { tenantService, IdpConfigRow } from './tenant.service';
import { userService, User } from './user.service';
import { sessionService } from './session.service';
import { auditService, AuditEventType } from './audit.service';
import { oidcLogger } from '../utils/logger';
import { config } from '../config';

interface OidcStateStore {
  state: string;
  nonce: string;
  codeVerifier: string;
  tenantId: string;
  idpConfigId: string;
  redirectAfterLogin?: string;
}

// In-memory state store (use Redis in production for multi-instance deployments)
const stateStore = new Map<string, OidcStateStore>();
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// Client cache to avoid repeated OIDC discovery requests
const clientCache = new Map<string, { client: Client; expiresAt: number }>();
const CLIENT_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

class OidcService {
  /**
   * Resolves an openid-client Client instance for the given IdP config.
   * Uses discovery if discoveryUrl is set, otherwise uses manual endpoints.
   */
  async getClient(idpConfig: IdpConfigRow): Promise<Client> {
    const cacheKey = idpConfig.id;
    const cached = clientCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.client;
    }

    const clientSecret = await tenantService.getOidcClientSecret(idpConfig);

    let issuer: Issuer;
    if (idpConfig.oidc_discovery_url) {
      issuer = await Issuer.discover(idpConfig.oidc_discovery_url);
    } else if (idpConfig.oidc_issuer) {
      // Manual configuration
      issuer = new Issuer({
        issuer: idpConfig.oidc_issuer,
        authorization_endpoint: idpConfig.oidc_authorization_endpoint ?? undefined,
        token_endpoint: idpConfig.oidc_token_endpoint ?? undefined,
        jwks_uri: idpConfig.oidc_jwks_uri ?? undefined,
        userinfo_endpoint: idpConfig.oidc_userinfo_endpoint ?? undefined,
        end_session_endpoint: idpConfig.oidc_logout_endpoint ?? undefined,
      });
    } else {
      throw new Error('OIDC config must have either discoveryUrl or issuer');
    }

    const client = new issuer.Client({
      client_id: idpConfig.oidc_client_id!,
      client_secret: clientSecret,
      redirect_uris: [
        `${config.BASE_URL}/auth/oidc/${idpConfig.tenant_id}/callback`,
      ],
      response_types: ['code'],
    });

    clientCache.set(cacheKey, { client, expiresAt: Date.now() + CLIENT_CACHE_TTL_MS });
    return client;
  }

  /**
   * Generates the OIDC authorization URL for an SP-initiated login.
   * Returns the redirect URL and stores PKCE state.
   */
  async initiateLogin(
    tenantId: string,
    idpConfigId: string,
    redirectAfterLogin?: string
  ): Promise<string> {
    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig || !idpConfig.is_active) {
      throw new Error('IdP configuration not found or inactive');
    }
    if (idpConfig.protocol !== 'oidc') {
      throw new Error('IdP configuration is not OIDC');
    }

    const client = await this.getClient(idpConfig);

    // PKCE parameters (RFC 7636)
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const state = generators.state();
    const nonce = generators.nonce();

    // Store PKCE state
    const storeEntry: OidcStateStore = {
      state,
      nonce,
      codeVerifier,
      tenantId,
      idpConfigId,
      redirectAfterLogin,
    };
    stateStore.set(state, storeEntry);

    // Auto-expire state
    setTimeout(() => stateStore.delete(state), STATE_TTL_MS);

    const authUrl = client.authorizationUrl({
      scope: (idpConfig.oidc_scopes ?? ['openid', 'profile', 'email']).join(' '),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    await auditService.log({
      tenantId,
      idpConfigId,
      eventType: AuditEventType.SSO_LOGIN_INITIATED,
      outcome: 'success',
      details: { protocol: 'oidc', flow: 'sp_initiated' },
    });

    oidcLogger.info('OIDC login initiated', { tenantId, idpConfigId });
    return authUrl;
  }

  /**
   * Handles the OIDC callback (authorization code exchange).
   * Returns session token on success.
   */
  async handleCallback(
    state: string,
    callbackParams: CallbackParamsType,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ sessionToken: string; redirectUrl?: string; user: User }> {
    const storeEntry = stateStore.get(state);
    if (!storeEntry) {
      throw new Error('Invalid or expired OIDC state parameter');
    }
    stateStore.delete(state);

    const { tenantId, idpConfigId, nonce, codeVerifier, redirectAfterLogin } = storeEntry;

    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig) throw new Error('IdP configuration not found');

    const client = await this.getClient(idpConfig);

    // Exchange authorization code for tokens (with PKCE verification)
    let tokenSet: TokenSet;
    try {
      tokenSet = await client.callback(
        `${config.BASE_URL}/auth/oidc/${tenantId}/callback`,
        callbackParams,
        {
          code_verifier: codeVerifier,
          state,
          nonce,
        }
      );
    } catch (err) {
      await auditService.log({
        tenantId,
        idpConfigId,
        eventType: AuditEventType.SSO_LOGIN_FAILURE,
        outcome: 'failure',
        ipAddress,
        details: { protocol: 'oidc', error: String(err) },
      });
      throw err;
    }

    // Extract claims from ID token
    const claims = tokenSet.claims();
    const sub = claims.sub;
    const email = (claims.email as string | undefined) ?? '';
    const firstName = claims.given_name as string | undefined;
    const lastName = claims.family_name as string | undefined;
    const displayName = claims.name as string | undefined;

    if (!email) {
      throw new Error('ID token missing email claim');
    }

    // Resolve attribute mapping
    const mapping = idpConfig.attribute_mapping as Record<string, string>;

    // Fetch userinfo for group claims if needed
    let groupClaims: string[] = [];
    try {
      const userinfo: UserinfoResponse = await client.userinfo(tokenSet);
      const groupsKey = mapping['groups'] ?? 'groups';
      const rawGroups = userinfo[groupsKey];
      if (Array.isArray(rawGroups)) {
        groupClaims = rawGroups.map(String);
      }
    } catch {
      oidcLogger.warn('Failed to fetch userinfo (non-fatal)', { tenantId, sub });
    }

    // Map groups to roles
    const roleMappings = await tenantService.getRoleMappings(tenantId, idpConfigId);
    const roles = tenantService.mapGroupsToRoles(groupClaims, roleMappings);

    // JIT provision user
    const user = await userService.upsertFromSso({
      tenantId,
      externalId: sub,
      email,
      firstName,
      lastName,
      displayName,
      roles,
      groups: groupClaims,
    });

    if (!user.isActive) {
      throw new Error('User account is deactivated');
    }

    // Fetch tenant timeout overrides
    const tenant = await tenantService.getTenant(tenantId) as {
      idle_timeout_seconds: number | null;
      absolute_timeout_seconds: number | null;
    } | null;

    // Create session
    const sessionToken = await sessionService.create({
      tenantId,
      userId: user.id,
      idpConfigId,
      oidcIdToken: tokenSet.id_token,
      oidcAccessToken: tokenSet.access_token,
      oidcRefreshToken: tokenSet.refresh_token,
      oidcTokenExp: tokenSet.expires_at
        ? new Date(tokenSet.expires_at * 1000)
        : undefined,
      ipAddress,
      userAgent,
      mfaVerified: this.checkMfaFromClaims(claims),
      mfaMethod: this.extractMfaMethod(claims),
      idleTimeoutSeconds: tenant?.idle_timeout_seconds ?? undefined,
      absoluteTimeoutSeconds: tenant?.absolute_timeout_seconds ?? undefined,
    });

    await auditService.log({
      tenantId,
      userId: user.id,
      actorEmail: email,
      idpConfigId,
      eventType: AuditEventType.SSO_LOGIN_SUCCESS,
      outcome: 'success',
      ipAddress,
      userAgent,
      details: { protocol: 'oidc', sub, roles },
    });

    oidcLogger.info('OIDC login successful', { tenantId, userId: user.id });

    return { sessionToken, redirectUrl: redirectAfterLogin, user };
  }

  /**
   * Initiates OIDC RP-initiated logout (if end_session_endpoint is configured).
   */
  async initiateLogout(
    tenantId: string,
    idpConfigId: string,
    idToken?: string,
    postLogoutRedirectUri?: string
  ): Promise<string | null> {
    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig?.oidc_logout_endpoint) return null;

    const client = await this.getClient(idpConfig);

    const url = client.endSessionUrl({
      id_token_hint: idToken,
      post_logout_redirect_uri: postLogoutRedirectUri ?? `${config.BASE_URL}/auth/logout/complete`,
      state: generators.state(),
    });

    await auditService.log({
      tenantId,
      idpConfigId,
      eventType: AuditEventType.SSO_LOGOUT_INITIATED,
      outcome: 'success',
      details: { protocol: 'oidc' },
    });

    return url;
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private checkMfaFromClaims(claims: Record<string, unknown>): boolean {
    // Check AMR (Authentication Methods References) claim
    const amr = claims['amr'] as string[] | undefined;
    if (amr) {
      return amr.some((m) =>
        ['mfa', 'otp', 'sms', 'hwk', 'swk', 'pin', 'fido'].includes(m)
      );
    }
    // Check ACR (Authentication Context Class Reference)
    const acr = claims['acr'] as string | undefined;
    if (acr) {
      return ['urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
              'http://schemas.microsoft.com/claims/multipleauthn',
              'possessionorinherence'].some(c => acr.includes(c));
    }
    return false;
  }

  private extractMfaMethod(claims: Record<string, unknown>): string | undefined {
    const amr = claims['amr'] as string[] | undefined;
    if (amr?.includes('hwk') || amr?.includes('fido')) return 'webauthn';
    if (amr?.includes('otp')) return 'totp';
    if (amr?.includes('sms')) return 'sms';
    return undefined;
  }
}

export const oidcService = new OidcService();
