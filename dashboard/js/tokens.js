// === Token Inspector ===
window.Tokens = (function () {
  'use strict';

  const now = new Date();
  const ts = (offset) => new Date(now.getTime() + offset * 1000).toISOString();

  const cards = [
    {
      title: 'Session Record',
      badge: 'Session',
      badgeClass: 'badge-session',
      fields: [
        { key: 'session_token', value: 'a8f3e1b2c4d6...9f0a (64 hex chars)', cls: 'redacted' },
        { key: 'tenant_id', value: 'e7a2b1c4-3d5f-4a89-b6e1-f0c2d4e6a8b0' },
        { key: 'user_id', value: '1a2b3c4d-5e6f-7a8b-9c0d-e1f2a3b4c5d6' },
        { key: 'idp_config_id', value: 'f0e1d2c3-b4a5-6789-0abc-def123456789' },
        { key: 'created_at', value: ts(0) },
        { key: 'last_activity_at', value: ts(-120) },
        { key: 'expires_at', value: ts(86400), cls: 'ok' },
        { key: 'idle_timeout', value: '1800s (30 min)' },
        { key: 'ip_address', value: '203.0.113.42' },
        { key: 'user_agent', value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        { key: 'mfa_verified', value: 'true', cls: 'ok' },
        { key: 'mfa_method', value: 'webauthn' },
        { key: 'oidc_token_exp', value: ts(3600) },
        { key: 'saml_name_id', value: '(null — OIDC session)' },
        { key: 'saml_session_index', value: '(null — OIDC session)' },
      ]
    },
    {
      title: 'OIDC ID Token Claims',
      badge: 'OIDC',
      badgeClass: 'badge-oidc',
      fields: [
        { key: 'iss', value: 'https://company.okta.com/oauth2/default' },
        { key: 'sub', value: '00u1a2b3c4d5e6f7g8' },
        { key: 'aud', value: '0oa1b2c3d4e5f6g7h8i9' },
        { key: 'email', value: 'jane.doe@company.com' },
        { key: 'given_name', value: 'Jane' },
        { key: 'family_name', value: 'Doe' },
        { key: 'name', value: 'Jane Doe' },
        { key: 'iat', value: ts(0) },
        { key: 'exp', value: ts(3600), cls: 'ok' },
        { key: 'nonce', value: 'd4e5f6a1b2c3... (validated ✓)', cls: 'ok' },
        { key: 'amr', value: '["pwd", "mfa"]' },
        { key: 'acr', value: 'urn:oasis:names:tc:SAML:2.0:ac:classes:MFA' },
      ],
      jwtInteractive: true,
      jwtString: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhMmIzYzRkNWU2ZjcifQ.eyJpc3MiOiJodHRwczovL2NvbXBhbnkub2t0YS5jb20vb2F1dGgyL2RlZmF1bHQiLCJzdWIiOiIwMHUxYTJiM2M0ZDVlNmY3ZzgiLCJhdWQiOiIwb2ExYjJjM2Q0ZTVmNmc3aDhpOSIsImVtYWlsIjoiamFuZS5kb2VAY29tcGFueS5jb20iLCJnaXZlbl9uYW1lIjoiSmFuZSIsImZhbWlseV9uYW1lIjoiRG9lIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNzA4NTMxMjAwLCJleHAiOjE3MDg1MzQ4MDAsIm5vbmNlIjoiZDRlNWY2YTFiMmMz...In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    },
    {
      title: 'WebAuthn Credential',
      badge: 'WebAuthn',
      badgeClass: 'badge-webauthn',
      fields: [
        { key: 'credential_id', value: 'YWJjZGVm...base64url (32 bytes)' },
        { key: 'public_key', value: 'COSE ES256 key (CBOR-encoded)' },
        { key: 'aaguid', value: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' },
        { key: 'device_type', value: 'singleDevice' },
        { key: 'backed_up', value: 'false' },
        { key: 'transports', value: '["usb", "nfc"]' },
        { key: 'counter', value: '42', cls: 'ok' },
        { key: 'last_used_at', value: ts(-300) },
        { key: 'created_at', value: ts(-2592000) },
        { key: 'user_verification', value: 'required', cls: 'ok' },
        { key: 'algorithms', value: 'ES256 (-7), RS256 (-257)' },
        { key: 'attestation', value: 'indirect (privacy-preserving)' },
      ]
    },
    {
      title: 'PKCE State Store Entry',
      badge: 'PKCE',
      badgeClass: 'badge-pkce',
      fields: [
        { key: 'state', value: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6' },
        { key: 'nonce', value: 'q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2' },
        { key: 'codeVerifier', value: '[256-bit — NEVER displayed]', cls: 'redacted' },
        { key: 'codeChallenge', value: 'SHA256(codeVerifier) = E9Melhoa2OwvFrE...' },
        { key: 'challengeMethod', value: 'S256 (RFC 7636)' },
        { key: 'tenantId', value: 'e7a2b1c4-3d5f-4a89-b6e1-f0c2d4e6a8b0' },
        { key: 'idpConfigId', value: 'f0e1d2c3-b4a5-6789-0abc-def123456789' },
        { key: 'redirectUrl', value: '/app/dashboard' },
        { key: 'ttl_remaining', value: '7m 23s', cls: 'warn' },
        { key: 'store_type', value: 'In-memory Map (not Redis)', cls: 'warn' },
        { key: 'created_at', value: ts(-157) },
        { key: 'expires_at', value: ts(443) },
      ]
    }
  ];

  function init() {
    const grid = document.getElementById('token-grid');
    if (!grid) return;

    let html = '';
    for (const card of cards) {
      html += `<div class="token-card">
        <div class="token-card-header">
          <span class="token-card-title">${card.title}</span>
          <span class="token-card-badge ${card.badgeClass}">${card.badge}</span>
        </div>
        <div class="token-card-body">`;
      for (const f of card.fields) {
        const cls = f.cls ? ` ${f.cls}` : '';
        html += `<div class="token-field">
          <span class="token-field-key">${f.key}</span>
          <span class="token-field-value${cls}">${f.value}</span>
        </div>`;
      }

      if (card.jwtInteractive) {
        const parts = card.jwtString.split('.');
        html += `
          <button class="jwt-decoder-btn" onclick="document.getElementById('jwt-view').classList.toggle('active')">
            &#128269; Toggle JWT Decoder
          </button>
          <div id="jwt-view" class="jwt-decoded-view">
            <span class="jwt-header">${parts[0]}</span><span class="jwt-dot">.</span><span class="jwt-payload">${parts[1]}</span><span class="jwt-dot">.</span><span class="jwt-signature">${parts[2]}</span>
            <div class="jwt-legend">
              <span class="jwt-header">■ Header (ALGO/KID)</span>
              <span class="jwt-payload">■ Payload (Claims)</span>
              <span class="jwt-signature">■ Signature</span>
            </div>
            <div class="jwt-sig-valid">
              &#10004; Signature verified against IdP JWKS
            </div>
          </div>
        `;
      }

      html += '</div></div>';
    }
    grid.innerHTML = html;
  }

  return { init };
})();
