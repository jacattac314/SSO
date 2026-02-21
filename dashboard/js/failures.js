// === Failure Lab ===
window.Failures = (function () {
  'use strict';

  const toggles = [
    {
      id: 'expired-state',
      title: '1. Expired OIDC State',
      desc: 'stateStore.get(state) returns undefined (>10 min elapsed)',
      protocol: 'oidc',
      detail: {
        trigger: 'User takes longer than 10 minutes to authenticate at the IdP, or the state store entry is evicted.',
        location: 'src/services/oidc.service.ts — handleCallback()',
        behavior: 'Throws "Invalid or expired OIDC state parameter" propagated as 401 to the client.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "Invalid or expired OIDC state parameter"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['User must restart the login flow', 'In-memory store means a server restart also triggers this', 'No retry mechanism — full redirect required']
      }
    },
    {
      id: 'pkce-mismatch',
      title: '2. PKCE Mismatch',
      desc: 'codeVerifier corrupted before token exchange',
      protocol: 'oidc',
      detail: {
        trigger: 'The codeVerifier stored in stateStore does not match the codeChallenge sent during authorization. Could indicate a MitM attack or memory corruption.',
        location: 'src/services/oidc.service.ts — client.callback() via openid-client',
        behavior: 'openid-client throws an error during token exchange. The IdP rejects the token request because SHA256(verifier) !== challenge.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "PKCE verification failed"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['Prevents authorization code interception attacks', 'This is a critical security control working as intended', 'Could indicate active attack on the auth flow']
      }
    },
    {
      id: 'nonce-mismatch',
      title: '3. Nonce Mismatch',
      desc: 'Stored nonce differs from ID token nonce claim',
      protocol: 'oidc',
      detail: {
        trigger: 'The nonce in the returned ID token does not match the nonce stored in the stateStore. Indicates token injection or replay attempt.',
        location: 'src/services/oidc.service.ts — client.callback() via openid-client',
        behavior: 'openid-client validates nonce claim against expected value and throws on mismatch.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "Nonce mismatch in ID token"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['Prevents ID token replay attacks', 'Prevents token substitution/injection', 'Nonce is single-use — consumed with state entry']
      }
    },
    {
      id: 'invalid-sig',
      title: '4. Invalid ID Token Signature',
      desc: 'JWKS key rotated after token was issued',
      protocol: 'oidc',
      detail: {
        trigger: 'The ID token signature cannot be verified against any key in the IdP\'s JWKS endpoint. This can happen during key rotation or if the token was tampered with.',
        location: 'src/services/oidc.service.ts — client.callback() via openid-client',
        behavior: 'openid-client fetches JWKS from the IdP discovery endpoint and attempts to verify the ID token signature. If no matching key is found, an error is thrown.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "ID token signature verification failed"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['Gap: no algorithm pinning — trusts whatever JWKS advertises', 'Key rotation during login can cause transient failures', 'Could indicate token tampering']
      }
    },
    {
      id: 'missing-email',
      title: '5. Missing Email Claim',
      desc: 'ID token contains no email field',
      protocol: 'oidc',
      detail: {
        trigger: 'The ID token from the IdP does not contain an email claim. This can happen if the IdP scope configuration is incomplete or the user has no email set.',
        location: 'src/services/oidc.service.ts — post claims extraction',
        behavior: 'Explicit check for email claim presence. Throws "ID token missing email claim" if absent.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "ID token missing email claim"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['Email is the primary user identifier for UPSERT', 'IdP admin must ensure email scope is configured', 'Other claims (name, groups) are optional']
      }
    },
    {
      id: 'saml-audience',
      title: '6. SAML Audience Mismatch',
      desc: 'Assertion Audience targets a different SP entity ID',
      protocol: 'saml',
      detail: {
        trigger: 'The SAML assertion\'s AudienceRestriction element contains an entity ID that does not match this SP\'s configured entity ID. Indicates misconfiguration or assertion forwarding attack.',
        location: 'src/services/saml.service.ts — handleAcs() explicit check',
        behavior: 'Explicit audience comparison after passport-saml validation. Throws "audience mismatch" on failure.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "SAML audience mismatch"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['Prevents assertion forwarding between SPs', 'IdP must configure correct audience/entity ID', 'Double-checked: passport-saml validates, then explicit check']
      }
    },
    {
      id: 'saml-sig',
      title: '7. SAML Signature Tampered',
      desc: 'Assertion XML modified after IdP signing',
      protocol: 'saml',
      detail: {
        trigger: 'The XML signature on the SAML assertion is invalid because the assertion content was modified after the IdP signed it. This is a direct attack indicator.',
        location: 'src/services/saml.service.ts — validatePostResponseAsync() via passport-saml',
        behavior: 'passport-saml verifies the XML signature against the IdP\'s certificate. Modified content causes signature verification failure.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "SAML signature verification failed"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['SHA-256 signature algorithm enforced (SHA-1 rejected)', 'IdP certificate must be correctly configured', 'Any XML modification invalidates the signature']
      }
    },
    {
      id: 'saml-replay',
      title: '8. SAML Replay Attack',
      desc: 'Resubmit a valid assertion (InResponseTo consumed)',
      protocol: 'saml',
      detail: {
        trigger: 'A previously valid SAML assertion is resubmitted to the ACS endpoint. The InResponseTo value has already been consumed and validated.',
        location: 'src/services/saml.service.ts — validateInResponseTo: true in passport-saml',
        behavior: 'passport-saml checks InResponseTo against stored request IDs. Previously consumed IDs are rejected.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "InResponseTo validation failed"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['Prevents classic replay attacks on SAML assertions', 'InResponseTo links response to specific SP-initiated request', 'IdP-initiated flows bypass this check (by design)']
      }
    },
    {
      id: 'idle-timeout',
      title: '9. Session Idle Timeout',
      desc: 'last_activity_at + idle_timeout exceeded',
      protocol: 'session',
      detail: {
        trigger: 'No request has been made within the idle timeout window (default 30 minutes). The next validate() call detects the gap.',
        location: 'src/services/session.service.ts — validate()',
        behavior: 'Session row deleted from database. Returns null to auth middleware, which responds with 401 and clears the session cookie.',
        response: '401 Unauthorized\n(legora_session cookie cleared)\n{\n  "error": "Session expired"\n}',
        logged: true,
        auditEvent: 'SESSION_EXPIRED_IDLE',
        impact: ['Limits window for stolen session tokens', 'User must re-authenticate via IdP', 'Configurable per tenant via session settings']
      }
    },
    {
      id: 'abs-timeout',
      title: '10. Session Absolute Timeout',
      desc: 'expires_at exceeded regardless of activity',
      protocol: 'session',
      detail: {
        trigger: 'The session has existed beyond its absolute timeout (set at creation). Activity does not extend this deadline.',
        location: 'src/services/session.service.ts — validate()',
        behavior: 'Session row deleted from database. Returns null, triggering 401 and cookie clear. Cannot be prevented by staying active.',
        response: '401 Unauthorized\n(legora_session cookie cleared)\n{\n  "error": "Session expired"\n}',
        logged: true,
        auditEvent: 'SESSION_EXPIRED_ABSOLUTE',
        impact: ['Forces periodic re-authentication', 'Prevents indefinite session extension', 'Configurable per tenant']
      }
    },
    {
      id: 'token-tamper',
      title: '11. Session Token Tampered',
      desc: 'Submit random/modified cookie value',
      protocol: 'session',
      detail: {
        trigger: 'Client submits a session token that does not match any row in the sso_sessions table. Could be random data, expired token, or manipulated value.',
        location: 'src/services/session.service.ts — validate()',
        behavior: 'Database lookup returns no rows. validate() returns null. Auth middleware sends 401.',
        response: '401 Unauthorized\n(legora_session cookie cleared)\n{\n  "error": "Authentication required"\n}',
        logged: false,
        auditEvent: '(None — gap: token miss is not logged)',
        impact: ['Gap: no audit event for invalid tokens', 'Could mask brute-force attempts against session tokens', 'Should be logged with IP address for monitoring']
      }
    },
    {
      id: 'user-deactivated',
      title: '12. User Deactivated',
      desc: 'is_active = false during assertion processing',
      protocol: 'global',
      detail: {
        trigger: 'User account has been deactivated (via SCIM deprovisioning or admin action) between the IdP authentication and the session creation step.',
        location: 'src/services/oidc.service.ts, src/services/saml.service.ts — userService.upsertFromSso() result',
        behavior: 'upsertFromSso() checks is_active flag. Throws "User account is deactivated" which propagates as 401.',
        response: '401 Unauthorized\n{\n  "error": "SSO authentication failed",\n  "details": "User account is deactivated"\n}',
        logged: true,
        auditEvent: 'SSO_LOGIN_FAILURE',
        impact: ['Immediate enforcement of SCIM deprovisioning', 'Existing sessions are NOT terminated (gap)', 'User must be re-activated by admin']
      }
    },
    {
      id: 'rate-limit',
      title: '13. Rate Limit Hit',
      desc: '21st auth request in 15-minute window',
      protocol: 'global',
      detail: {
        trigger: 'Client IP has sent 20 authentication requests within 15 minutes. The 21st request triggers the rate limiter.',
        location: 'src/app.ts — express-rate-limit authLimiter',
        behavior: 'express-rate-limit returns 429 with default message. Request does not reach the auth handler.',
        response: '429 Too Many Requests\n{\n  "error": "Too many authentication attempts, please try again later"\n}',
        logged: false,
        auditEvent: '(None — express-rate-limit default, not in audit log)',
        impact: ['Gap: rate limit events not in audit log', 'Uses in-memory store — not shared across instances', 'Should use Redis store for production']
      }
    },
    {
      id: 'wa-challenge-exp',
      title: '14. WebAuthn Challenge Expired',
      desc: '>5 minutes between options and verify',
      protocol: 'webauthn',
      detail: {
        trigger: 'More than 5 minutes elapsed between generating WebAuthn options and submitting the authenticator response. The challenge entry has been evicted from the challengeStore.',
        location: 'src/services/webauthn.service.ts — verifyAuthentication()',
        behavior: 'challengeStore lookup returns undefined. Throws "challenge expired or not found".',
        response: '400 Bad Request\n{\n  "error": "WebAuthn verification failed",\n  "details": "Challenge expired"\n}',
        logged: false,
        auditEvent: '(None — gap: challenge expiry not logged)',
        impact: ['Gap: no audit event for expired challenges', 'User must re-request options and try again', 'In-memory store — lost on server restart']
      }
    },
    {
      id: 'wa-counter-rollback',
      title: '15. WebAuthn Counter Rollback',
      desc: 'Counter lower than stored value (clone detection)',
      protocol: 'webauthn',
      detail: {
        trigger: 'The authenticator response contains a counter value less than or equal to the stored counter. This indicates the authenticator may have been cloned.',
        location: 'src/services/webauthn.service.ts — verifyAuthenticationResponse()',
        behavior: '@simplewebauthn/server detects counter rollback and throws. This is anti-clone protection.',
        response: '400 Bad Request\n{\n  "error": "WebAuthn verification failed",\n  "details": "Authenticator counter mismatch"\n}',
        logged: true,
        auditEvent: 'WEBAUTHN_VERIFY_FAILURE',
        impact: ['Detects cloned authenticators', 'Counter should monotonically increase', 'Legitimate cause: some authenticators reset counter on firmware update']
      }
    },
    {
      id: 'mfa-gate',
      title: '16. MFA Required Gate',
      desc: 'Access protected route without mfa_verified = true',
      protocol: 'session',
      detail: {
        trigger: 'User attempts to access a route protected by requireMfa() middleware without having completed WebAuthn MFA verification.',
        location: 'src/middleware/auth.ts — requireMfa()',
        behavior: 'Checks session.mfa_verified. If false, returns 403 with a specific error code for the client to trigger the MFA flow.',
        response: '403 Forbidden\n{\n  "error": "MFA required",\n  "code": "mfa_required"\n}',
        logged: false,
        auditEvent: '(None — gap: MFA denial not logged)',
        impact: ['Gap: MFA required denials not in audit log', 'Client should redirect to WebAuthn flow', 'Session remains valid — just not elevated']
      }
    }
  ];

  let activeToggle = null;

  function init() {
    renderToggles();
    bindToggles();
  }

  function renderToggles() {
    const grid = document.getElementById('failure-grid');
    if (!grid) return;

    let html = '';
    for (const t of toggles) {
      html += `<div class="failure-toggle" data-toggle="${t.id}">
        <div class="toggle-switch"></div>
        <div class="toggle-info">
          <div class="toggle-title">${t.title}</div>
          <div class="toggle-desc">${t.desc}</div>
          <span class="toggle-protocol proto-${t.protocol}">${t.protocol}</span>
        </div>
      </div>`;
    }
    grid.innerHTML = html;
  }

  function bindToggles() {
    document.querySelectorAll('.failure-toggle').forEach(el => {
      el.addEventListener('click', () => {
        const id = el.dataset.toggle;
        const wasActive = el.classList.contains('active');

        // Deactivate all
        document.querySelectorAll('.failure-toggle').forEach(e => e.classList.remove('active'));

        if (wasActive) {
          activeToggle = null;
          document.getElementById('failure-detail').innerHTML = '<div class="detail-placeholder">Activate a toggle to see failure details</div>';
        } else {
          el.classList.add('active');
          activeToggle = id;
          renderDetail(id);
        }
      });
    });
  }

  function renderDetail(id) {
    const t = toggles.find(x => x.id === id);
    if (!t) return;
    const d = t.detail;
    const container = document.getElementById('failure-detail');

    container.innerHTML = `<div class="detail-title">${t.title}</div>
      <div class="failure-detail-inner">
        <div class="fd-section">
          <h4>Trigger Condition</h4>
          <p>${d.trigger}</p>
          <div class="fd-location">Location: ${d.location}</div>
          <h4 style="margin-top:14px">Behavior</h4>
          <p>${d.behavior}</p>
          <div class="fd-logged ${d.logged ? 'yes' : 'no'}">
            ${d.logged ? '&#10003; Audit Logged' : '&#10007; Not Logged (gap)'}
          </div>
          ${d.logged ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:2px">Event: ${d.auditEvent}</div>` : `<div style="font-size:0.75rem;color:var(--red);margin-top:2px">${d.auditEvent}</div>`}
        </div>
        <div class="fd-section">
          <h4>HTTP Response</h4>
          <div class="fd-code">${d.response}</div>
          <h4 style="margin-top:14px">Impact Analysis</h4>
          <ul>${d.impact.map(i => `<li>${i}</li>`).join('')}</ul>
        </div>
      </div>`;
  }

  return { init };
})();
