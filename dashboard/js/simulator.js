// === Flow Simulator ===
window.Simulator = (function () {
  'use strict';

  const flows = {
    oidc: {
      name: 'OIDC Authorization Code + PKCE',
      steps: [
        {
          title: '1. Login Entry Point',
          detail: 'User navigates to GET /:tenantId/login. The requireTenant middleware validates the tenant exists and resolves the IdP configuration (default or specified via query param).',
          security: ['requireTenant middleware validates tenant', 'IdP config checked for is_active and protocol=oidc'],
          data: '// Route: GET /auth/oidc/:tenantId/login\n// Resolves: idpConfigId from query or tenant default\n// Failure: 404 if no OIDC config found',
          file: 'src/routes/auth/oidc.ts'
        },
        {
          title: '2. PKCE Generation & IdP Redirect',
          detail: 'OidcService.initiateLogin() generates cryptographic parameters: a 256-bit codeVerifier, its SHA-256 codeChallenge, a random state, and a random nonce. All are stored in the in-memory stateStore with a 10-minute TTL. The browser is redirected to the IdP authorization endpoint.',
          importance: 'Protects the system against CSRF and credential interception. Modern PKCE prevents attacks where authorization codes are intercepted and exchanged maliciously, showcasing zero-trust principles.',
          security: ['PKCE S256 method (RFC 7636)', 'State parameter for CSRF protection', 'Nonce for replay protection', 'Audit: SSO_LOGIN_INITIATED'],
          vulnerability: { risk: 'low', reason: 'PKCE mitigates interception risks.' },
          data: '{\n  state: "a1b2c3...",           // random, links callback to request\n  nonce: "d4e5f6...",           // random, embedded in ID token\n  codeVerifier: "[256-bit]",    // never sent to IdP\n  codeChallenge: "SHA256(cv)", // sent to IdP\n  tenantId: "tenant-uuid",\n  idpConfigId: "idp-uuid",\n  redirectUrl: "/app/dashboard",\n  createdAt: 1708531200000,     // 10-min TTL\n}',
          file: 'src/services/oidc.service.ts'
        },
        {
          title: '3. IdP Authentication (External)',
          detail: 'The Identity Provider authenticates the user using its own credential store and MFA policy. This step is entirely outside the Legora SSO system. The IdP may use passwords, push notifications, hardware keys, or any method it supports.',
          security: ['Credential validation by IdP', 'MFA policy enforced by IdP', 'IdP issues authorization code (not tokens)'],
          data: '// External to this system\n// IdP validates: username/password, MFA\n// IdP generates: authorization_code\n// IdP redirects to: callback_url?code=xxx&state=yyy',
          file: '(External IdP)'
        },
        {
          title: '4. Callback — State Validation',
          detail: 'The callback handler receives the authorization code and state. It validates the state against the stateStore (one-time use — the entry is deleted after retrieval). If the state is missing, expired (>10 min), or already consumed, the request fails.',
          security: ['State validated against stateStore', 'State entry deleted after use (one-time)', 'Error query params checked first', 'Audit: SSO_LOGIN_FAILURE on any error'],
          vulnerability: { risk: 'medium', reason: 'In-memory state store resets during restarts, dropping ongoing logins.' },
          data: '// GET /auth/oidc/:tenantId/callback?code=abc&state=a1b2c3\n\n// stateStore.get("a1b2c3") → stored params\n// stateStore.delete("a1b2c3")  ← one-time use\n\n// If state not found: 401 "Invalid or expired OIDC state"',
          file: 'src/routes/auth/oidc.ts → src/services/oidc.service.ts'
        },
        {
          title: '5. Token Exchange (PKCE Verified)',
          detail: 'The authorization code is exchanged at the IdP token endpoint. The original codeVerifier is sent along — the IdP verifies SHA256(codeVerifier) matches the codeChallenge from step 2. The openid-client library validates the returned ID token: signature via JWKS, issuer, audience, nonce, and expiry.',
          security: ['PKCE verifier sent to token endpoint', 'ID token signature verified via JWKS', 'Nonce claim validated against stored nonce', 'Issuer and audience validated by openid-client', 'Token expiry checked'],
          data: '// client.callback(redirectUri, { code, state }, {\n//   code_verifier: storedParams.codeVerifier,\n//   state: storedParams.state,\n//   nonce: storedParams.nonce,\n// })\n\n// Returns: { id_token, access_token, refresh_token }',
          file: 'src/services/oidc.service.ts'
        },
        {
          title: '6. Claims Extraction & Attribute Mapping',
          detail: 'Claims are extracted from the ID token: sub, email, given_name, family_name, name. The userinfo endpoint is called for group membership claims. The attribute_mapping JSONB from the IdP config transforms IdP claim names to Legora field names. IdP groups are mapped to Legora roles via the role_mappings table.',
          importance: 'Ensures seamless enterprise integration. Translating diverse IdP schemas into a standardized internal format minimizes friction when onboarding large institutional clients like banks or hedge funds.',
          security: ['Email claim required (throws if missing)', 'Userinfo fetch failure is non-fatal (warning)', 'AMR/ACR claims inspected for IdP-reported MFA'],
          data: '// Claims from ID token:\n{\n  sub: "user-id-at-idp",\n  email: "user@company.com",\n  given_name: "Jane",\n  family_name: "Doe",\n  amr: ["pwd", "mfa"],  // MFA indicators\n  acr: "urn:mfa"         // fallback MFA indicator\n}\n\n// Groups from userinfo endpoint:\n{\n  groups: ["Legal-Team", "Admin"]\n}',
          file: 'src/services/oidc.service.ts'
        },
        {
          title: '7. JIT User Provisioning',
          detail: 'userService.upsertFromSso() performs an UPSERT on (tenant_id, email). If the user exists, roles, groups, and last_login_at are updated. If new, a user record is created. The is_active flag is checked — deactivated accounts throw a 401.',
          importance: 'Automates lifecycle management (JIT Provisioning). Removes the need for manual admin intervention when new employees join or leave a client organization, drastically reducing operational overhead.',
          security: ['UPSERT prevents duplicate accounts', 'is_active check blocks deactivated users', 'Audit: SSO_LOGIN_FAILURE if deactivated'],
          data: '// UPSERT users ON (tenant_id, email)\n// SET:\n//   roles = mapped_roles,\n//   groups = idp_groups,\n//   last_login_at = NOW()\n// CHECK: is_active = true\n// FAIL: "User account is deactivated" → 401',
          file: 'src/services/user.service.ts'
        },
        {
          title: '8. Session Creation',
          detail: 'SessionService.create() generates a 256-bit opaque token (crypto.randomBytes(32).toString("hex")), inserts a row into sso_sessions with absolute timeout, and stores OIDC tokens, MFA status, IP address, and user agent.',
          importance: 'Opaque tokens ensure that sensitive user attributes never reach the browser, preventing client-side token tampering or inspection common with JWTs.',
          security: ['256-bit random token (not JWT)', 'Absolute timeout set at creation', 'Tenant-scoped timeout overrides', 'IP address and user agent recorded', 'Audit: SESSION_CREATED'],
          data: '// generateToken(32) → 64-char hex string\n\n// INSERT sso_sessions:\n{\n  session_token: "a8f3...64 hex chars",\n  tenant_id: "...",\n  user_id: "...",\n  expires_at: "NOW() + absolute_timeout",\n  oidc_id_token: "eyJ...",     // stored plaintext\n  oidc_access_token: "...",\n  oidc_refresh_token: "...",\n  mfa_verified: false,\n  ip_address: "203.0.113.1",\n  user_agent: "Mozilla/5.0..."\n}',
          file: 'src/services/session.service.ts'
        },
        {
          title: '9. Cookie Set & Redirect',
          detail: 'The session token is set as an HttpOnly cookie and the user is redirected to the application. The redirect URL comes from the pre-login state (stored in stateStore) or defaults to BASE_URL/app.',
          security: ['HttpOnly: true (no JavaScript access)', 'Secure: true (production only)', 'SameSite: Lax (CSRF mitigation)', 'Path: / (available to all routes)', 'Gap: redirect URL not validated against allowlist'],
          vulnerability: { risk: 'high', reason: 'Open Redirect Vulnerability: RelayState hostname is missing proper allowlist validation.' },
          data: '// Set-Cookie: legora_session=a8f3...;\n//   HttpOnly;\n//   Secure;        (production)\n//   SameSite=Lax;\n//   Path=/;\n//   Max-Age=86400  (absolute_timeout)\n\n// 302 Redirect → /app/dashboard (or stored redirectUrl)',
          file: 'src/routes/auth/oidc.ts'
        },
        {
          title: '10. Authenticated Request (Middleware)',
          detail: 'On subsequent requests, requireAuth() extracts the token from the cookie or Authorization header. SessionService.validate() checks absolute timeout (expires_at), idle timeout (last_activity_at + idle_timeout), and updates last_activity_at on success.',
          importance: 'Continuous enforcement of session boundaries (idle and absolute timeouts) is mandated by institutional security standards (e.g., SOC2, ISO27001).',
          security: ['Absolute timeout enforced on every request', 'Idle timeout enforced on every request', 'Session data attached to req for downstream use', 'Cookie cleared on invalid session', 'requireMfa() available for protected routes'],
          data: '// SessionService.validate(token):\n//\n// 1. SELECT FROM sso_sessions WHERE token = ?\n// 2. Check: expires_at > NOW()         → SESSION_EXPIRED_ABSOLUTE\n// 3. Check: last_activity + idle < NOW → SESSION_EXPIRED_IDLE\n// 4. UPDATE last_activity_at = NOW()\n// 5. Return session_data → req.session\n//\n// On failure: 401 + clear legora_session cookie',
          file: 'src/middleware/auth.ts → src/services/session.service.ts'
        }
      ]
    },
    saml: {
      name: 'SAML 2.0 (SP-Initiated)',
      steps: [
        {
          title: '1. Login Entry Point',
          detail: 'User navigates to the SAML login endpoint. Tenant is resolved and the SAML IdP configuration is loaded, including the IdP SSO URL, certificate, and SP entity ID.',
          security: ['requireTenant validates tenant', 'IdP config checked for is_active and protocol=saml'],
          data: '// GET /auth/saml/:tenantId/login\n// Loads: IdP SSO URL, cert, SP entity ID, signing algo',
          file: 'src/routes/auth/saml.ts'
        },
        {
          title: '2. AuthnRequest Generation',
          detail: 'An AuthnRequest XML document is generated via passport-saml getAuthorizeUrlAsync(). It contains the SP entity ID, ACS URL, and a unique request ID (used later for InResponseTo validation).',
          security: ['Request ID generated for InResponseTo CSRF protection', 'Signature algorithm: SHA-256 (SHA-1 rejected)', 'Audit: SSO_LOGIN_INITIATED'],
          data: '// AuthnRequest contains:\n//   ID="req_abc123"        (for InResponseTo)\n//   AssertionConsumerServiceURL="https://.../acs"\n//   Issuer="legora-sp-entity-id"\n//   NameIDPolicy: emailAddress',
          file: 'src/services/saml.service.ts'
        },
        {
          title: '3. IdP Authentication (External)',
          detail: 'The IdP authenticates the user and generates a signed SAML assertion containing the user\'s identity claims, including NameID, attributes, and session information.',
          security: ['Credential validation by IdP', 'IdP signs assertion with its private key', 'Assertion includes InResponseTo matching request ID'],
          data: '// External to this system\n// IdP validates credentials\n// IdP generates signed SAML Response with:\n//   InResponseTo="req_abc123"\n//   Assertion with NameID, attributes\n//   SessionIndex for SLO',
          file: '(External IdP)'
        },
        {
          title: '4. Assertion Consumer Service (ACS)',
          detail: 'The signed assertion arrives as an HTTP POST to /auth/saml/:tenantId/acs. passport-saml validatePostResponseAsync() verifies the XML signature, InResponseTo value, audience restriction, and assertion timing.',
          security: ['XML signature verified against IdP certificate', 'InResponseTo validated (CSRF for SP-initiated)', 'Audience restriction checked against SP entity ID', 'SHA-256 signature required', 'Audit: SSO_LOGIN_FAILURE on validation error'],
          data: '// POST /auth/saml/:tenantId/acs\n// Body: SAMLResponse (base64-encoded XML)\n\n// Validation checklist:\n// ✓ XML signature valid (IdP cert)\n// ✓ InResponseTo matches request ID\n// ✓ Audience = SP entity ID\n// ✓ NotBefore / NotOnOrAfter timing\n// ✓ SHA-256 signature algorithm',
          file: 'src/routes/auth/saml.ts → src/services/saml.service.ts'
        },
        {
          title: '5. User Provisioning & Session Creation',
          detail: 'User is upserted from SAML claims (NameID as email, attributes mapped). Session is created with SAML-specific fields: saml_name_id and saml_session_index (needed for Single Logout).',
          security: ['Same user provisioning as OIDC (upsertFromSso)', 'is_active check blocks deactivated users', 'nameID/sessionIndex stored for SLO'],
          data: '// Extract from assertion:\n//   nameID: "user@company.com"\n//   sessionIndex: "saml_session_idx_123"\n//   attributes: { firstName, lastName, groups }\n\n// Session includes:\n//   saml_name_id: "user@company.com"\n//   saml_session_index: "saml_session_idx_123"',
          file: 'src/services/saml.service.ts → src/services/session.service.ts'
        },
        {
          title: '6. Cookie Set & RelayState Redirect',
          detail: 'Session cookie is set (same flags as OIDC). Redirect target comes from RelayState parameter, which is validated against the BASE_URL hostname allowlist to mitigate open redirect attacks.',
          security: ['HttpOnly; Secure; SameSite=Lax', 'RelayState hostname validated against BASE_URL', 'Invalid RelayState falls back to BASE_URL/app', 'Gap: silent fallback not logged to audit'],
          data: '// Set-Cookie: legora_session=...\n// Validate RelayState hostname\n// 302 Redirect → RelayState URL or BASE_URL/app',
          file: 'src/routes/auth/saml.ts'
        },
        {
          title: '7. Authenticated (Same as OIDC)',
          detail: 'Subsequent requests use the same requireAuth() middleware and SessionService.validate() flow as OIDC. The session is protocol-agnostic after creation — the middleware does not distinguish between OIDC and SAML sessions.',
          security: ['Same session validation as OIDC path', 'Absolute and idle timeout enforcement', 'SLO possible via nameID + sessionIndex'],
          data: '// Same as OIDC step 10\n// SessionService.validate() is protocol-agnostic\n\n// SLO: POST /auth/saml/:tenantId/logout\n//   → sends LogoutRequest with nameID + sessionIndex\n//   → IdP terminates federated session',
          file: 'src/middleware/auth.ts'
        }
      ]
    },
    webauthn: {
      name: 'WebAuthn MFA (Session Step-Up)',
      steps: [
        {
          title: '1. Existing Session Required',
          detail: 'WebAuthn is not a standalone authentication mechanism. The user must already have an authenticated session (via OIDC or SAML) with mfa_verified = false. The requireAuth() middleware is applied at the router level.',
          security: ['requireAuth() enforced before WebAuthn endpoints', 'Session must exist and be valid', 'mfa_verified starts as false'],
          data: '// Pre-condition: valid legora_session cookie\n// Session state:\n{\n  mfa_verified: false,\n  mfa_method: null,\n  user_id: "...",\n  tenant_id: "..."\n}',
          file: 'src/routes/auth/webauthn.ts'
        },
        {
          title: '2. Registration/Authentication Options',
          detail: 'The server generates WebAuthn options (challenge, RP info, user info, supported algorithms). The challenge is stored in the in-memory challengeStore with a 5-minute TTL.',
          security: ['Challenge: cryptographically random', 'User verification: required', 'Supported algorithms: ES256 (-7), RS256 (-257)', 'Attestation: indirect (privacy-preserving)', '5-minute challenge TTL'],
          data: '// generateRegistrationOptions() or\n// generateAuthenticationOptions()\n\n{\n  challenge: "random-base64url",\n  rp: { name: "Legora", id: "legora.com" },\n  user: { id: "user-id", name: "user@co.com" },\n  authenticatorSelection: {\n    userVerification: "required"\n  },\n  pubKeyCredParams: [\n    { alg: -7,   type: "public-key" },  // ES256\n    { alg: -257, type: "public-key" }   // RS256\n  ]\n}\n\n// challengeStore.set(userId, { challenge, ttl: 5min })',
          file: 'src/services/webauthn.service.ts'
        },
        {
          title: '3. Authenticator Signs Challenge',
          detail: 'The browser\'s WebAuthn API prompts the user for biometric/PIN verification. The authenticator (Touch ID, Windows Hello, security key) signs the challenge with its private key and returns the assertion.',
          security: ['User verification enforced at hardware level', 'Private key never leaves authenticator', 'Counter incremented by authenticator (anti-clone)'],
          data: '// Browser: navigator.credentials.get() or .create()\n// User performs: fingerprint / face / PIN\n// Authenticator returns:\n{\n  id: "credential-id",\n  rawId: ArrayBuffer,\n  response: {\n    authenticatorData: "...",  // includes counter\n    clientDataJSON: "...",     // includes challenge\n    signature: "..."           // signed by private key\n  }\n}',
          file: '(Client-side browser API)'
        },
        {
          title: '4. Server Verification & Counter Update',
          detail: 'The server retrieves the stored challenge from challengeStore (deleted after use). @simplewebauthn/server verifies the signature against the stored public key, validates user verification flag, and checks the counter against the stored value (anti-clone protection).',
          security: ['Challenge consumed (one-time use)', 'Signature verified against COSE public key', 'User verification flag validated', 'Counter must be > stored counter (anti-clone)', 'Audit: WEBAUTHN_VERIFY_FAILURE on error'],
          data: '// verifyAuthenticationResponse({\n//   response: clientResponse,\n//   expectedChallenge: stored.challenge,\n//   expectedOrigin: "https://legora.com",\n//   expectedRPID: "legora.com",\n//   authenticator: {\n//     credentialPublicKey: stored.publicKey,\n//     counter: stored.counter,\n//   },\n//   requireUserVerification: true,\n// })\n\n// UPDATE webauthn_credentials\n//   SET counter = new_counter,\n//       last_used_at = NOW()',
          file: 'src/services/webauthn.service.ts'
        },
        {
          title: '5. Session Elevated to MFA-Verified',
          detail: 'On successful verification, the session is directly updated: mfa_verified = true, mfa_method = "webauthn". The user can now access routes protected by requireMfa() middleware.',
          security: ['Direct session UPDATE (no new session created)', 'mfa_method recorded for audit trail', 'Audit: WEBAUTHN_VERIFY_SUCCESS', 'requireMfa() gates now pass'],
          data: '// UPDATE sso_sessions\n//   SET mfa_verified = true,\n//       mfa_method = \'webauthn\'\n//   WHERE session_token = ?\n\n// Session state after:\n{\n  mfa_verified: true,\n  mfa_method: "webauthn",\n  // ... rest unchanged\n}\n\n// requireMfa() middleware now passes ✓',
          file: 'src/services/webauthn.service.ts → src/services/session.service.ts'
        }
      ]
    },
    session: {
      name: 'Session Lifecycle',
      steps: [
        {
          title: '1. Session Active',
          detail: 'After authentication (OIDC or SAML), a session is active with a defined absolute timeout (expires_at) and idle timeout (last_activity_at + idle_timeout). Every successful validate() call updates last_activity_at.',
          security: ['256-bit random opaque token', 'Absolute timeout set at creation', 'Idle timeout checked per request', 'last_activity_at updated on each valid request'],
          data: '// Active session state:\n{\n  session_token: "a8f3...64chars",\n  expires_at: "2026-02-22T12:00:00Z",  // absolute\n  last_activity_at: "2026-02-21T15:30:00Z",\n  idle_timeout: 1800,                   // 30 min\n  mfa_verified: true,\n  ip_address: "203.0.113.1",\n  user_agent: "Mozilla/5.0..."\n}',
          file: 'src/services/session.service.ts'
        },
        {
          title: '2. Idle Timeout',
          detail: 'If no request arrives within the idle_timeout window (e.g., 30 minutes), the next validate() call detects last_activity_at + idle_timeout < NOW(). The session is deleted from the database.',
          security: ['Detected on next validate() call', 'Session row deleted from DB', 'Cookie cleared in response', 'Audit: SESSION_EXPIRED_IDLE'],
          data: '// SessionService.validate():\n//   last_activity_at + idle_timeout < NOW()\n//   → DELETE FROM sso_sessions WHERE token = ?\n//   → 401 response\n//   → Set-Cookie: legora_session=; Max-Age=0\n\n// Audit event:\n{\n  event: "SESSION_EXPIRED_IDLE",\n  outcome: "terminated",\n  user_id: "...",\n  idle_since: "2026-02-21T15:30:00Z"\n}',
          file: 'src/services/session.service.ts'
        },
        {
          title: '3. Absolute Timeout',
          detail: 'Even with continuous activity, when NOW() exceeds expires_at (set at session creation), the session is terminated. This prevents indefinite session extension through activity.',
          security: ['Cannot be extended by activity', 'Enforces re-authentication', 'Session row deleted from DB', 'Audit: SESSION_EXPIRED_ABSOLUTE'],
          data: '// SessionService.validate():\n//   expires_at < NOW()\n//   → DELETE FROM sso_sessions WHERE token = ?\n//   → 401 response\n//   → Set-Cookie: legora_session=; Max-Age=0\n\n// Audit event:\n{\n  event: "SESSION_EXPIRED_ABSOLUTE",\n  outcome: "terminated",\n  user_id: "...",\n  created_at: "2026-02-21T12:00:00Z",\n  expired_at: "2026-02-22T12:00:00Z"\n}',
          file: 'src/services/session.service.ts'
        },
        {
          title: '4. Explicit Logout',
          detail: 'User-initiated logout terminates the session. For SAML, a LogoutRequest with the stored nameID and sessionIndex is sent to the IdP (Single Logout). For OIDC, an id_token_hint is used at the IdP end_session_endpoint.',
          security: ['Session deleted from database', 'Cookie cleared', 'OIDC: id_token_hint sent to IdP', 'SAML: LogoutRequest with nameID + sessionIndex', 'Audit: SESSION_TERMINATED'],
          data: '// POST /auth/logout or protocol-specific logout\n\n// OIDC logout:\n//   Redirect to IdP end_session_endpoint\n//   with id_token_hint = stored oidc_id_token\n\n// SAML SLO:\n//   POST LogoutRequest to IdP SLO URL\n//   with nameID + sessionIndex\n\n// Both:\n//   DELETE FROM sso_sessions WHERE token = ?\n//   Set-Cookie: legora_session=; Max-Age=0',
          file: 'src/routes/auth/oidc.ts, src/routes/auth/saml.ts'
        }
      ]
    }
  };

  let currentFlow = 'oidc';
  let currentStep = 0;

  function init() {
    bindProtocolButtons();
    bindStepButtons();
    renderFlow();
  }

  function bindProtocolButtons() {
    document.querySelectorAll('.proto-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.proto-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFlow = btn.dataset.flow;
        currentStep = 0;
        renderFlow();
      });
    });
  }

  function bindStepButtons() {
    document.getElementById('sim-prev').addEventListener('click', () => {
      if (currentStep > 0) { currentStep--; renderFlow(); }
    });
    document.getElementById('sim-next').addEventListener('click', () => {
      const max = flows[currentFlow].steps.length - 1;
      if (currentStep < max) { currentStep++; renderFlow(); }
    });
    document.getElementById('sim-reset').addEventListener('click', () => {
      currentStep = 0;
      renderFlow();
    });
  }

  function renderFlow() {
    const flow = flows[currentFlow];
    const steps = flow.steps;
    const step = steps[currentStep];

    // Update step label
    document.getElementById('sim-step-label').textContent = `Step ${currentStep + 1} / ${steps.length}`;

    // Update buttons
    document.getElementById('sim-prev').disabled = currentStep === 0;
    document.getElementById('sim-next').disabled = currentStep === steps.length - 1;

    // Render diagram (step list)
    const diagram = document.getElementById('sim-diagram');
    let html = '<div class="sim-flow">';
    steps.forEach((s, i) => {
      let state = i < currentStep ? 'past' : i === currentStep ? 'current' : 'future';

      // If this is the active step AND it has a vulnerability, apply the risk color strictly
      if (s.vulnerability && i === currentStep) {
        state += ` risk-${s.vulnerability.risk}`;
      }

      html += `<div class="sim-flow-step ${state}">
        <div class="sim-flow-vuln-container">
          <div class="sim-flow-name-wrapper" style="flex-direction: row; align-items: center; gap: 16px;">
            <div class="sim-flow-num">${i < currentStep ? '&#10003;' : i + 1}</div>
            <div class="sim-flow-name">${s.title}</div>
          </div>
          ${s.vulnerability && i === currentStep ? `<div class="sim-flow-reason text-risk-${s.vulnerability.risk}">Why: ${s.vulnerability.reason}</div>` : ''}
        </div>
      </div>`;
      if (i < steps.length - 1) {
        html += `<div class="sim-flow-arrow ${i < currentStep ? 'past' : ''}">&darr;</div>`;
      }
    });
    html += '</div>';
    diagram.innerHTML = html;

    // Render info panel
    document.getElementById('sim-step-title').textContent = step.title;
    let contentHtml = step.detail;

    if (step.importance) {
      contentHtml += `<div style="margin-top: 16px; padding: 12px; background: rgba(99, 102, 241, 0.1); border-left: 3px solid var(--accent); border-radius: 4px; color: #f8fafc; font-size: 0.95rem;">
        <strong style="color: var(--accent-light); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px;">Executive Value</strong><br/>
        ${step.importance}
      </div>`;
    }

    document.getElementById('sim-step-detail').innerHTML = contentHtml;

    let secHtml = '<h4>Security Controls</h4><ul>';
    step.security.forEach(s => { secHtml += `<li>${s}</li>`; });
    secHtml += '</ul>';
    if (step.file) secHtml += `<p style="margin-top:8px;font-size:0.75rem;color:var(--text-muted)">File: ${step.file}</p>`;
    document.getElementById('sim-step-security').innerHTML = secHtml;

    document.getElementById('sim-step-data').textContent = step.data;
  }

  // --- Recruiter Demo Implementation ---
  let demoInterval = null;

  function runDemo() {
    // Stop any existing demo
    if (demoInterval) {
      clearInterval(demoInterval);
      demoInterval = null;
    }

    // Switch to OIDC flow and reset to step 0
    document.querySelector('.proto-btn[data-flow="oidc"]').click();
    currentStep = 0;
    renderFlow();

    // Start automated progression
    demoInterval = setInterval(() => {
      const max = flows[currentFlow].steps.length - 1;
      if (currentStep < max) {
        currentStep++;
        renderFlow();
      } else {
        // End of flow, stop demo
        clearInterval(demoInterval);
        demoInterval = null;
      }
    }, 2500); // Fast 2.5-second pacing
  }

  // Stop demo if user manually interacts with steps or protocols
  document.addEventListener('click', (e) => {
    if (e.target.matches('.proto-btn') || e.target.matches('#sim-prev') || e.target.matches('#sim-next') || e.target.matches('#sim-reset')) {
      if (demoInterval && !e.target.matches('.proto-btn[data-flow="oidc"]') && e.target.textContent !== '🚀 Demo') {
      }

      if (e.isTrusted && demoInterval) {
        clearInterval(demoInterval);
        demoInterval = null;
      }
    }
  });

  return { init, runDemo };
})();
