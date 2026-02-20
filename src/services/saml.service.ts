/**
 * SAML 2.0 authentication service.
 * Supports SP-initiated and IdP-initiated flows.
 * Implements Single Logout (SLO) per SAML 2.0 bindings.
 * Uses passport-saml under the hood.
 */
import { SAML, SamlConfig, Profile } from 'passport-saml';
import { tenantService, IdpConfigRow } from './tenant.service';
import { userService, User } from './user.service';
import { sessionService } from './session.service';
import { auditService, AuditEventType } from './audit.service';
import { samlLogger } from '../utils/logger';
import { config } from '../config';
import { generateSpMetadata } from '../utils/xml';
import { decrypt } from '../utils/crypto';
import { query } from '../config/database';

// SAML instance cache (keyed by idpConfigId)
const samlCache = new Map<string, { saml: SAML; expiresAt: number }>();
const SAML_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

class SamlService {
  /**
   * Builds a configured SAML instance for a given IdP config.
   */
  async getSamlInstance(idpConfig: IdpConfigRow): Promise<SAML> {
    const cacheKey = idpConfig.id;
    const cached = samlCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.saml;
    }

    const privateKey = await tenantService.getSamlSpPrivateKey(idpConfig);

    const samlConfig: SamlConfig = {
      entryPoint: idpConfig.saml_idp_sso_url!,
      issuer: idpConfig.saml_sp_entity_id ?? config.SAML_SP_ENTITY_ID,
      callbackUrl: idpConfig.saml_sp_acs_url ?? config.SAML_SP_ACS_URL,
      cert: idpConfig.saml_idp_certificate ?? '',
      privateKey: privateKey ?? undefined,
      signatureAlgorithm: 'sha256',
      digestAlgorithm: 'sha256',
      wantAssertionsSigned: idpConfig.saml_want_assertions_signed,
      identifierFormat: idpConfig.saml_name_id_format,
      // Strict validation
      validateInResponseTo: true,
      disableRequestedAuthnContext: false,
      authnContext: [
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      ],
      // SLO
      logoutUrl: idpConfig.saml_idp_slo_url ?? undefined,
      logoutCallbackUrl: idpConfig.saml_sp_slo_url ?? config.SAML_SP_SLO_URL,
      acceptedClockSkewMs: 5000,
    };

    const saml = new SAML(samlConfig);
    samlCache.set(cacheKey, { saml, expiresAt: Date.now() + SAML_CACHE_TTL_MS });
    return saml;
  }

  /**
   * Generates the SP-initiated SAML AuthnRequest redirect URL.
   */
  async initiateLogin(
    tenantId: string,
    idpConfigId: string,
    _redirectAfterLogin?: string
  ): Promise<string> {
    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig || !idpConfig.is_active) {
      throw new Error('SAML IdP configuration not found or inactive');
    }
    if (idpConfig.protocol !== 'saml') {
      throw new Error('IdP configuration is not SAML');
    }

    const saml = await this.getSamlInstance(idpConfig);

    const { url } = await (saml as unknown as {
      getAuthorizeUrlAsync: (opts?: object) => Promise<{ url: string; id: string }>;
    }).getAuthorizeUrlAsync();

    await auditService.log({
      tenantId,
      idpConfigId,
      eventType: AuditEventType.SSO_LOGIN_INITIATED,
      outcome: 'success',
      details: { protocol: 'saml', flow: 'sp_initiated' },
    });

    samlLogger.info('SAML SP-initiated login', { tenantId, idpConfigId });
    return url;
  }

  /**
   * Processes a SAML Assertion Consumer Service (ACS) POST.
   * Handles both SP-initiated and IdP-initiated flows.
   */
  async handleAcs(
    tenantId: string,
    idpConfigId: string,
    body: Record<string, string>,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ sessionToken: string; user: User; relayState?: string }> {
    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig) throw new Error('SAML IdP configuration not found');

    const saml = await this.getSamlInstance(idpConfig);

    let profile: Profile;
    try {
      profile = await (saml as unknown as {
        validatePostResponseAsync: (body: object) => Promise<{ profile: Profile; loggedOut: boolean }>;
      }).validatePostResponseAsync(body).then((r) => r.profile);
    } catch (err) {
      await auditService.log({
        tenantId,
        idpConfigId,
        eventType: AuditEventType.SSO_LOGIN_FAILURE,
        outcome: 'failure',
        ipAddress,
        details: { protocol: 'saml', error: String(err) },
      });
      samlLogger.error('SAML assertion validation failed', { tenantId, idpConfigId, err });
      throw new Error(`SAML validation failed: ${String(err)}`);
    }

    // Validate audience (prevent cross-tenant assertion replay)
    const expectedAudience =
      idpConfig.saml_sp_entity_id ?? config.SAML_SP_ENTITY_ID;
    const audience = profile.audience as string | string[] | undefined;
    if (audience) {
      const audiences = Array.isArray(audience) ? audience : [audience];
      if (!audiences.includes(expectedAudience)) {
        throw new Error(
          `SAML assertion audience mismatch: expected ${expectedAudience}`
        );
      }
    }

    // Extract user attributes using configured mapping
    const attrMapping = idpConfig.attribute_mapping as Record<string, string>;
    const email = this.extractAttribute(profile, attrMapping['email'] ?? 'email') ??
      (profile.nameID && profile.nameIDFormat?.includes('email') ? profile.nameID : undefined);

    if (!email) {
      throw new Error('SAML assertion missing email attribute');
    }

    const firstName = this.extractAttribute(profile, attrMapping['firstName'] ?? 'firstName') ??
      this.extractAttribute(profile, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname');
    const lastName = this.extractAttribute(profile, attrMapping['lastName'] ?? 'lastName') ??
      this.extractAttribute(profile, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname');
    const displayName = this.extractAttribute(profile, attrMapping['displayName'] ?? 'displayName') ??
      this.extractAttribute(profile, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name');

    // Extract groups
    const groupsKey = attrMapping['groups'] ?? 'groups';
    const rawGroups = profile[groupsKey] as string | string[] | undefined;
    const groups: string[] = Array.isArray(rawGroups)
      ? rawGroups
      : rawGroups
        ? [rawGroups]
        : [];

    // Map groups to roles
    const roleMappings = await tenantService.getRoleMappings(tenantId, idpConfigId);
    const roles = tenantService.mapGroupsToRoles(groups, roleMappings);

    // JIT provision user
    const user = await userService.upsertFromSso({
      tenantId,
      externalId: profile.nameID ?? undefined,
      email,
      firstName: firstName ?? undefined,
      lastName: lastName ?? undefined,
      displayName: displayName ?? undefined,
      roles,
      groups,
    });

    if (!user.isActive) {
      throw new Error('User account is deactivated');
    }

    const tenant = await tenantService.getTenant(tenantId) as {
      idle_timeout_seconds: number | null;
      absolute_timeout_seconds: number | null;
    } | null;

    // Create session (store SAML session data for SLO)
    const sessionToken = await sessionService.create({
      tenantId,
      userId: user.id,
      idpConfigId,
      samlNameId: profile.nameID,
      samlSessionIndex: profile.sessionIndex as string | undefined,
      samlNameIdFormat: profile.nameIDFormat,
      ipAddress,
      userAgent,
      mfaVerified: this.checkMfaFromProfile(profile),
      mfaMethod: 'saml_idp',
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
      details: {
        protocol: 'saml',
        nameId: profile.nameID,
        sessionIndex: profile.sessionIndex,
        roles,
      },
    });

    samlLogger.info('SAML login successful', { tenantId, userId: user.id });

    return {
      sessionToken,
      user,
      relayState: body['RelayState'],
    };
  }

  /**
   * Initiates SP-initiated Single Logout (SLO).
   * Sends a LogoutRequest to the IdP.
   */
  async initiateLogout(
    tenantId: string,
    idpConfigId: string,
    nameId: string,
    sessionIndex?: string,
    nameIdFormat?: string
  ): Promise<string | null> {
    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig?.saml_idp_slo_url) {
      samlLogger.warn('SLO not configured for IdP', { tenantId, idpConfigId });
      return null;
    }

    const saml = await this.getSamlInstance(idpConfig);

    const logoutUrl = await (saml as unknown as {
      getLogoutUrlAsync: (user: object, relayState: string) => Promise<string>;
    }).getLogoutUrlAsync(
      {
        nameID: nameId,
        sessionIndex,
        nameIDFormat: nameIdFormat,
      },
      '' // relayState
    );

    await auditService.log({
      tenantId,
      idpConfigId,
      eventType: AuditEventType.SSO_SLO_REQUEST_SENT,
      outcome: 'success',
      details: { nameId, sessionIndex },
    });

    return logoutUrl;
  }

  /**
   * Processes an incoming SAML SLO request (from IdP-initiated logout).
   * Terminates matching sessions.
   */
  async handleSloRequest(
    tenantId: string,
    idpConfigId: string,
    body: Record<string, string>,
    query_: Record<string, string>
  ): Promise<{ redirectUrl: string }> {
    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig) throw new Error('SAML IdP configuration not found');

    const saml = await this.getSamlInstance(idpConfig);

    let nameId: string;
    let sessionIndex: string | undefined;

    try {
      const result = await (saml as unknown as {
        validateRedirectAsync: (
          query: object,
          originalQuery: string
        ) => Promise<{ profile: Profile; loggedOut: boolean }>;
      }).validateRedirectAsync(query_, '');
      nameId = result.profile.nameID ?? '';
      sessionIndex = result.profile.sessionIndex as string | undefined;
    } catch (err) {
      samlLogger.error('SLO request validation failed', { err });
      throw err;
    }

    // Find and terminate all matching sessions
    const sessions = await sessionService.findBySamlSession(
      tenantId,
      nameId,
      sessionIndex
    );

    for (const session of sessions) {
      await sessionService.terminate(session.sessionToken, 'idp_slo');
    }

    await auditService.log({
      tenantId,
      idpConfigId,
      eventType: AuditEventType.SSO_SLO_REQUEST_RECEIVED,
      outcome: 'success',
      details: { nameId, sessionIndex, sessionsTerminated: sessions.length },
    });

    // Return a SAML SLO response redirect URL
    const logoutResponseUrl = await (saml as unknown as {
      getLogoutResponseUrlAsync: (user: object, relayState: string, options: object) => Promise<string>;
    }).getLogoutResponseUrlAsync(
      { nameID: nameId, sessionIndex },
      body['RelayState'] ?? '',
      {}
    );

    return { redirectUrl: logoutResponseUrl };
  }

  /**
   * Returns SP metadata XML for a given tenant/IdP config.
   */
  async getSpMetadata(tenantId: string, idpConfigId: string): Promise<string> {
    const idpConfig = await tenantService.getIdpConfig(tenantId, idpConfigId);
    if (!idpConfig) throw new Error('IdP configuration not found');

    const saml = await this.getSamlInstance(idpConfig);
    const metadata = (saml as unknown as { generateServiceProviderMetadata: (a: string | null, b: string | null) => string }).generateServiceProviderMetadata(
      idpConfig.saml_sp_certificate ?? null,
      idpConfig.saml_sp_certificate ?? null
    );
    return metadata;
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private extractAttribute(
    profile: Profile,
    key: string
  ): string | undefined {
    const val = (profile as Record<string, unknown>)[key];
    if (!val) return undefined;
    if (Array.isArray(val)) return String(val[0]);
    return String(val);
  }

  private checkMfaFromProfile(profile: Profile): boolean {
    const authnContext = (profile as Record<string, unknown>)['authnContextClassRef'] as string | undefined;
    if (!authnContext) return false;
    const mfaContexts = [
      'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
      'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken',
      'urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI',
    ];
    return mfaContexts.includes(authnContext);
  }
}

export const samlService = new SamlService();
