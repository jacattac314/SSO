// === Security Audit ===
window.Security = (function () {
  'use strict';

  const comparisonData = [
    { feature: 'Auth protocols',            system: 'OIDC + SAML 2.0 + WebAuthn',                 baseline: 'OIDC + SAML 2.0 + WebAuthn',                  status: 'pass' },
    { feature: 'PKCE',                       system: 'S256 enforced (RFC 7636)',                    baseline: 'S256 required',                                 status: 'pass' },
    { feature: 'Token at rest',              system: 'Plaintext session token in DB',               baseline: 'SHA-256 hashed before storage',                 status: 'warn' },
    { feature: 'Distributed state',          system: 'In-memory Map (single instance only)',        baseline: 'Redis cluster (shared across instances)',        status: 'fail' },
    { feature: 'Refresh token logic',        system: 'Schema only — no implementation in code',     baseline: 'Full rotation with family replay detection',    status: 'fail' },
    { feature: 'Algorithm pinning',          system: 'None (trusts JWKS from IdP)',                 baseline: 'Pin to RS256 / ES256',                          status: 'warn' },
    { feature: 'Conditional access',         system: 'None — MFA is binary',                        baseline: 'IP, device posture, risk score evaluation',     status: 'fail' },
    { feature: 'Session binding',            system: 'IP + UA stored but not enforced',             baseline: 'IP binding optional, UA enforced',              status: 'warn' },
    { feature: 'Audit log',                  system: 'PostgreSQL partitioned, 365-day retention',   baseline: 'SIEM-integrated, immutable',                    status: 'pass' },
    { feature: 'MFA enforcement',            system: 'Policy-enforced (no OIDC without MFA)',       baseline: 'Same',                                          status: 'pass' },
    { feature: 'Certificate rotation',       system: '30-day expiry alerts',                        baseline: 'Automated rotation',                            status: 'warn' },
    { feature: 'Secret encryption at rest',  system: 'AES-256-GCM (OIDC secrets, SAML keys)',      baseline: 'Same or HSM-backed',                            status: 'pass' },
    { feature: 'Cookie security',            system: 'HttpOnly; Secure; SameSite=Lax',              baseline: 'Same',                                          status: 'pass' },
    { feature: 'Rate limiting',              system: '20 req/15 min (in-memory store)',             baseline: 'Same with Redis-backed distributed store',      status: 'pass' },
    { feature: 'CORS',                       system: 'Explicit allowlist, credentials: true',       baseline: 'Same',                                          status: 'pass' },
    { feature: 'Security headers',           system: 'Helmet CSP + HSTS (1 year)',                  baseline: 'Same',                                          status: 'pass' },
    { feature: 'SAML signature algo',        system: 'SHA-256 enforced (SHA-1 rejected)',           baseline: 'SHA-256 minimum',                               status: 'pass' },
    { feature: 'WebAuthn user verification', system: 'required (UV flag enforced)',                 baseline: 'Same',                                          status: 'pass' },
  ];

  const gaps = [
    {
      title: 'Session tokens stored in plaintext',
      desc: 'Session tokens are stored verbatim in sso_sessions. If the database is read-compromised, all active sessions can be hijacked. Tokens should be SHA-256 hashed before storage.',
      severity: 'high'
    },
    {
      title: 'In-memory state stores (no Redis)',
      desc: 'Both OIDC state/nonce/PKCE and WebAuthn challenges are stored in JavaScript Map objects. Server restart loses all in-flight authentications. Horizontal scaling is impossible without Redis.',
      severity: 'high'
    },
    {
      title: 'Refresh token rotation unimplemented',
      desc: 'The refresh_tokens table exists with family-based replay detection columns, but no service code reads or writes to this table. OIDC refresh tokens from IdPs are stored in sessions but never used for token rotation.',
      severity: 'high'
    },
    {
      title: 'No OIDC algorithm pinning',
      desc: 'The system trusts whatever algorithm the IdP\'s JWKS endpoint advertises. A misconfigured or compromised IdP could advertise "none" or a weak algorithm, enabling token forgery.',
      severity: 'medium'
    },
    {
      title: 'OIDC ID token stored in plaintext',
      desc: 'The raw OIDC ID token is stored in sso_sessions.oidc_id_token. It contains PII (email, name) and can be used as id_token_hint for logout. Database compromise exposes this data.',
      severity: 'medium'
    },
    {
      title: 'Redirect URL not validated (OIDC)',
      desc: 'The post-login redirect URL stored in the OIDC stateStore is not validated against an allowlist. An attacker could inject a malicious redirect URL if they can influence the login initiation request.',
      severity: 'medium'
    },
    {
      title: 'Audit gaps in failure paths',
      desc: 'Several failure conditions are not logged to the audit trail: IdP error returns, missing state/code params, session token misses, WebAuthn challenge expiry, MFA denials, rate limit hits, tenant resolution failures.',
      severity: 'medium'
    },
    {
      title: 'No conditional access engine',
      desc: 'No IP allowlisting, device posture evaluation, or risk-based step-up authentication. MFA is binary (verified or not) and is not triggered dynamically based on context.',
      severity: 'low'
    },
    {
      title: 'Session IP/UA not enforced',
      desc: 'IP address and user agent are stored in the session record but not actively validated on subsequent requests. A stolen session token can be used from any IP/device.',
      severity: 'low'
    },
    {
      title: 'Certificate auto-rotation absent',
      desc: 'Certificate expiry is monitored with 30-day alerts via background job, but there is no automated rotation capability. Rotation is manual.',
      severity: 'low'
    }
  ];

  const validationChecklist = [
    { check: 'Issuer validated',       oidc: true,  saml: true,  webauthn: false, notes: 'openid-client / passport-saml' },
    { check: 'Audience validated',     oidc: true,  saml: true,  webauthn: false, notes: 'openid-client / explicit check' },
    { check: 'Signature verified',     oidc: true,  saml: true,  webauthn: true,  notes: 'JWKS / IdP cert / COSE key' },
    { check: 'Nonce validated',        oidc: true,  saml: false, webauthn: false, notes: 'OIDC only' },
    { check: 'State validated',        oidc: true,  saml: false, webauthn: false, notes: 'via InResponseTo for SAML' },
    { check: 'InResponseTo validated', oidc: false, saml: true,  webauthn: false, notes: 'SP-initiated only' },
    { check: 'Expiry enforced',        oidc: true,  saml: true,  webauthn: true,  notes: 'Session level / challenge TTL' },
    { check: 'PKCE enforced',          oidc: true,  saml: false, webauthn: false, notes: 'S256 method' },
    { check: 'User verification',      oidc: false, saml: false, webauthn: true,  notes: 'UV flag required' },
    { check: 'Replay protection',      oidc: true,  saml: true,  webauthn: true,  notes: 'nonce / InResponseTo / counter' },
  ];

  function init() {
    const container = document.getElementById('security-content');
    if (!container) return;

    let html = '';

    // Feature Comparison Table
    html += `<div class="sec-section">
      <div class="sec-section-header">Feature Comparison: This System vs. Enterprise Baseline</div>
      <table class="sec-table">
        <thead><tr>
          <th>Feature</th>
          <th>This System</th>
          <th>Enterprise Baseline</th>
          <th>Status</th>
        </tr></thead>
        <tbody>`;
    for (const row of comparisonData) {
      const icon = row.status === 'pass' ? '&#10003;' : row.status === 'warn' ? '&#9888;' : '&#10007;';
      const label = row.status === 'pass' ? 'Pass' : row.status === 'warn' ? 'Gap' : 'Missing';
      html += `<tr>
        <td>${row.feature}</td>
        <td>${row.system}</td>
        <td>${row.baseline}</td>
        <td><span class="status-icon ${row.status}">${icon} ${label}</span></td>
      </tr>`;
    }
    html += '</tbody></table></div>';

    // Validation Checklist
    html += `<div class="sec-section">
      <div class="sec-section-header">Protocol Validation Checklist</div>
      <table class="sec-table">
        <thead><tr>
          <th>Validation Check</th>
          <th>OIDC</th>
          <th>SAML</th>
          <th>WebAuthn</th>
          <th>Notes</th>
        </tr></thead>
        <tbody>`;
    for (const row of validationChecklist) {
      const cell = (v) => v ? '<span class="status-icon pass">&#10003;</span>' : '<span class="status-icon" style="color:var(--text-muted)">N/A</span>';
      html += `<tr>
        <td>${row.check}</td>
        <td>${cell(row.oidc)}</td>
        <td>${cell(row.saml)}</td>
        <td>${cell(row.webauthn)}</td>
        <td style="color:var(--text-secondary);font-size:0.8rem">${row.notes}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';

    // Security Gaps
    html += `<div class="sec-section">
      <div class="sec-section-header">Security Gap Analysis</div>
      <div class="gap-cards">`;
    for (const gap of gaps) {
      const cls = gap.severity === 'high' ? '' : gap.severity === 'medium' ? 'medium' : 'low';
      html += `<div class="gap-card ${cls}">
        <h5>${gap.title}</h5>
        <p>${gap.desc}</p>
        <span class="gap-severity sev-${gap.severity}">${gap.severity}</span>
      </div>`;
    }
    html += '</div></div>';

    // Key Material Summary
    html += `<div class="sec-section">
      <div class="sec-section-header">Key Material &amp; Encryption Summary</div>
      <table class="sec-table">
        <thead><tr>
          <th>Material</th>
          <th>Storage Method</th>
          <th>Algorithm</th>
          <th>Status</th>
        </tr></thead>
        <tbody>
          <tr>
            <td>OIDC client secrets</td>
            <td>AES-256-GCM encrypted in idp_configs.oidc_client_secret_enc</td>
            <td>AES-256-GCM (96-bit IV, 128-bit tag)</td>
            <td><span class="status-icon pass">&#10003; Encrypted</span></td>
          </tr>
          <tr>
            <td>SAML SP private key</td>
            <td>AES-256-GCM encrypted in idp_configs.saml_sp_private_key_enc</td>
            <td>AES-256-GCM</td>
            <td><span class="status-icon pass">&#10003; Encrypted</span></td>
          </tr>
          <tr>
            <td>DMS OAuth tokens</td>
            <td>AES-256-GCM encrypted in dms_tokens</td>
            <td>AES-256-GCM</td>
            <td><span class="status-icon pass">&#10003; Encrypted</span></td>
          </tr>
          <tr>
            <td>SCIM bearer token</td>
            <td>bcrypt-hashed in tenants.scim_token_hash</td>
            <td>bcrypt</td>
            <td><span class="status-icon pass">&#10003; Hashed</span></td>
          </tr>
          <tr>
            <td>Session tokens</td>
            <td>Plaintext in sso_sessions.session_token</td>
            <td>None</td>
            <td><span class="status-icon warn">&#9888; Plaintext</span></td>
          </tr>
          <tr>
            <td>OIDC ID tokens</td>
            <td>Plaintext in sso_sessions.oidc_id_token</td>
            <td>None</td>
            <td><span class="status-icon warn">&#9888; Plaintext</span></td>
          </tr>
          <tr>
            <td>Master encryption key</td>
            <td>TENANT_SECRET_ENCRYPTION_KEY env variable</td>
            <td>64-char hex (32 bytes)</td>
            <td><span class="status-icon pass">&#10003; External</span></td>
          </tr>
        </tbody>
      </table>
    </div>`;

    container.innerHTML = html;
  }

  return { init };
})();
