// === Architecture Diagram ===
window.Architecture = (function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';

  // Node definitions: { id, label, sublabel, x, y, w, h, color, group }
  const nodes = [
    // External
    { id: 'browser',  label: 'Browser / Client',    sublabel: 'End-User Agent',           x: 80,  y: 40,  w: 160, h: 52, color: '#4f6ef7', group: 'external' },
    { id: 'idp',      label: 'Identity Provider',   sublabel: 'Okta / Azure AD / Ping',   x: 500, y: 40,  w: 200, h: 52, color: '#a78bfa', group: 'external' },
    { id: 'scim-dir', label: 'SCIM Directory',      sublabel: 'IdP User/Group Store',      x: 920, y: 40,  w: 180, h: 52, color: '#a78bfa', group: 'external' },

    // Middleware layer
    { id: 'tenant-mw',  label: 'Tenant Resolver',   sublabel: 'middleware/tenant.ts',      x: 80,  y: 160, w: 160, h: 48, color: '#636880', group: 'middleware' },
    { id: 'auth-mw',    label: 'Auth Middleware',    sublabel: 'requireAuth / requireMfa',  x: 280, y: 160, w: 160, h: 48, color: '#636880', group: 'middleware' },
    { id: 'rate-limit', label: 'Rate Limiter',       sublabel: '20 req / 15 min (auth)',    x: 480, y: 160, w: 160, h: 48, color: '#636880', group: 'middleware' },

    // Services layer
    { id: 'oidc-svc',    label: 'OIDC Service',      sublabel: 'Authorization Code + PKCE', x: 80,  y: 290, w: 160, h: 52, color: '#34d399', group: 'services' },
    { id: 'saml-svc',    label: 'SAML Service',       sublabel: 'SP-initiated & IdP-init',  x: 280, y: 290, w: 160, h: 52, color: '#fbbf24', group: 'services' },
    { id: 'webauthn-svc',label: 'WebAuthn Service',   sublabel: 'FIDO2 MFA Layer',          x: 480, y: 290, w: 160, h: 52, color: '#a78bfa', group: 'services' },
    { id: 'session-svc', label: 'Session Service',    sublabel: 'Opaque token lifecycle',    x: 680, y: 290, w: 160, h: 52, color: '#4f6ef7', group: 'services' },
    { id: 'audit-svc',   label: 'Audit Service',      sublabel: 'Event logging + retention', x: 880, y: 290, w: 160, h: 52, color: '#fb923c', group: 'services' },
    { id: 'user-svc',    label: 'User Service',       sublabel: 'JIT provisioning / UPSERT', x: 1060,y: 290, w: 140, h: 52, color: '#22d3ee', group: 'services' },

    // State stores
    { id: 'oidc-state', label: 'OIDC State Store',   sublabel: 'In-memory Map (10 min TTL)', x: 80,  y: 420, w: 170, h: 48, color: '#f87171', group: 'state' },
    { id: 'wa-challenge',label: 'Challenge Store',   sublabel: 'In-memory Map (5 min TTL)',  x: 300, y: 420, w: 170, h: 48, color: '#f87171', group: 'state' },
    { id: 'redis',       label: 'Redis',             sublabel: 'Declared but not wired',     x: 520, y: 420, w: 140, h: 48, color: '#f87171', group: 'state' },

    // Database
    { id: 'postgres',      label: 'PostgreSQL',         sublabel: 'Primary data store',        x: 240, y: 540, w: 180, h: 52, color: '#4f6ef7', group: 'database' },
    { id: 'tbl-sessions',  label: 'sso_sessions',       sublabel: 'Active session tokens',     x: 80,  y: 630, w: 140, h: 42, color: '#2a2f42', group: 'tables' },
    { id: 'tbl-users',     label: 'users',              sublabel: 'User profiles',             x: 240, y: 630, w: 120, h: 42, color: '#2a2f42', group: 'tables' },
    { id: 'tbl-idpconfig', label: 'idp_configs',        sublabel: 'IdP settings (encrypted)',  x: 380, y: 630, w: 140, h: 42, color: '#2a2f42', group: 'tables' },
    { id: 'tbl-wacreds',   label: 'webauthn_credentials',sublabel: 'FIDO2 keys',              x: 540, y: 630, w: 180, h: 42, color: '#2a2f42', group: 'tables' },
    { id: 'tbl-audit',     label: 'audit_logs',         sublabel: 'Partitioned, 365-day',      x: 740, y: 630, w: 140, h: 42, color: '#2a2f42', group: 'tables' },
    { id: 'tbl-refresh',   label: 'refresh_tokens',     sublabel: 'Schema only (unused)',      x: 900, y: 630, w: 150, h: 42, color: '#2a2f42', group: 'tables' },
  ];

  // Connections: { from, to, label, color, dashed }
  const connections = [
    { from: 'browser',    to: 'tenant-mw',   label: 'HTTP Request' },
    { from: 'tenant-mw',  to: 'auth-mw',     label: '' },
    { from: 'auth-mw',    to: 'rate-limit',   label: '' },
    { from: 'browser',    to: 'idp',          label: 'OIDC Redirect / SAML POST', color: '#34d399' },
    { from: 'idp',        to: 'oidc-svc',     label: 'Auth Code Callback', color: '#34d399' },
    { from: 'idp',        to: 'saml-svc',     label: 'SAML Assertion POST', color: '#fbbf24' },
    { from: 'scim-dir',   to: 'user-svc',     label: 'SCIM 2.0', color: '#22d3ee' },
    { from: 'oidc-svc',   to: 'oidc-state',   label: 'state / nonce / verifier' },
    { from: 'oidc-svc',   to: 'session-svc',  label: 'Create session' },
    { from: 'oidc-svc',   to: 'user-svc',     label: 'UPSERT user' },
    { from: 'saml-svc',   to: 'session-svc',  label: 'Create session' },
    { from: 'saml-svc',   to: 'user-svc',     label: 'UPSERT user' },
    { from: 'webauthn-svc',to: 'wa-challenge', label: 'Store challenge' },
    { from: 'webauthn-svc',to: 'session-svc', label: 'Elevate to mfa_verified' },
    { from: 'session-svc',to: 'postgres',     label: 'Read/Write sessions' },
    { from: 'user-svc',   to: 'postgres',     label: 'Read/Write users' },
    { from: 'audit-svc',  to: 'postgres',     label: 'Append audit events' },
    { from: 'auth-mw',    to: 'session-svc',  label: 'Validate token', color: '#4f6ef7' },
    { from: 'redis',      to: 'oidc-state',   label: 'Should replace', dashed: true, color: '#f87171' },
    { from: 'redis',      to: 'wa-challenge', label: 'Should replace', dashed: true, color: '#f87171' },
    { from: 'postgres',   to: 'tbl-sessions', label: '' },
    { from: 'postgres',   to: 'tbl-users',    label: '' },
    { from: 'postgres',   to: 'tbl-idpconfig',label: '' },
    { from: 'postgres',   to: 'tbl-wacreds',  label: '' },
    { from: 'postgres',   to: 'tbl-audit',    label: '' },
    { from: 'postgres',   to: 'tbl-refresh',  label: '' },
    { from: 'oidc-svc',   to: 'audit-svc',    label: 'Log events', color: '#fb923c' },
    { from: 'saml-svc',   to: 'audit-svc',    label: 'Log events', color: '#fb923c' },
  ];

  // Group backgrounds
  const groups = [
    { id: 'grp-ext',  label: 'EXTERNAL',    x: 60,  y: 20,  w: 1060, h: 90,  color: 'rgba(167,139,250,0.04)' },
    { id: 'grp-mw',   label: 'MIDDLEWARE',   x: 60,  y: 140, w: 600,  h: 80,  color: 'rgba(99,104,128,0.04)' },
    { id: 'grp-svc',  label: 'SERVICES',     x: 60,  y: 265, w: 1160, h: 100, color: 'rgba(79,110,247,0.04)' },
    { id: 'grp-state',label: 'STATE STORES', x: 60,  y: 395, w: 620,  h: 90,  color: 'rgba(248,113,113,0.04)' },
    { id: 'grp-db',   label: 'DATABASE',     x: 60,  y: 515, w: 1020, h: 180, color: 'rgba(79,110,247,0.04)' },
  ];

  // Detail info per node
  const nodeDetails = {
    browser: {
      title: 'Browser / Client',
      body: `<p>End-user agent (browser or Word add-in). Initiates authentication flows and carries the <code>legora_session</code> cookie for subsequent requests.</p>
<ul><li>Cookie: <code>HttpOnly; Secure; SameSite=Lax</code></li><li>Redirected to IdP for credential entry</li><li>Never handles tokens directly (PKCE S256 prevents interception)</li></ul>`
    },
    idp: {
      title: 'Identity Provider (Okta / Azure AD / Ping)',
      body: `<p>External IdP that owns user identities. This system <strong>never issues identity assertions</strong> — it is exclusively an SP/RP.</p>
<ul><li>OIDC: issues authorization codes, ID tokens, access tokens</li><li>SAML: issues signed XML assertions</li><li>SCIM: provisions/deprovisions users and groups</li><li>No local password fallback — hard dependency</li></ul>`
    },
    'scim-dir': {
      title: 'SCIM Directory',
      body: `<p>IdP directory service for automated user lifecycle management via SCIM 2.0 protocol.</p>
<ul><li>Endpoints: <code>/scim/v2/Users</code>, <code>/scim/v2/Groups</code></li><li>Auth: Bearer token (bcrypt-hashed in <code>tenants.scim_token_hash</code>)</li><li>Supports create, update, deactivate, group membership sync</li></ul>`
    },
    'tenant-mw': {
      title: 'Tenant Resolver Middleware',
      body: `<p>Resolves the tenant context from the request. Located at <code>src/middleware/tenant.ts</code>.</p>
<ul><li>Extracts tenant from URL path param, subdomain, or header</li><li>Attaches resolved tenant to <code>req.tenant</code></li><li>Returns 400 if tenant cannot be determined</li><li>No audit log on failure (gap)</li></ul>`
    },
    'auth-mw': {
      title: 'Auth Middleware',
      body: `<p>Enforces authentication and MFA requirements. Located at <code>src/middleware/auth.ts</code>.</p>
<ul><li><code>requireAuth()</code>: validates session token from cookie or Bearer header</li><li><code>requireMfa()</code>: checks <code>mfa_verified = true</code> on session</li><li>Clears cookie and returns 401 on invalid/expired session</li><li>403 with <code>mfa_required</code> code if MFA not satisfied</li></ul>`
    },
    'rate-limit': {
      title: 'Rate Limiter',
      body: `<p>Express-rate-limit configuration in <code>src/app.ts</code>.</p>
<ul><li>Global: 100 requests per 60 seconds</li><li>Auth endpoints: 20 requests per 15 minutes</li><li>Uses in-memory store (should use Redis in production)</li><li>Returns 429 on limit exceeded</li></ul>`
    },
    'oidc-svc': {
      title: 'OIDC Service',
      body: `<p>Implements Authorization Code + PKCE flow. Located at <code>src/services/oidc.service.ts</code>.</p>
<ul><li>Generates <code>codeVerifier</code> (256-bit), <code>codeChallenge</code> (S256), <code>state</code>, <code>nonce</code></li><li>Stores PKCE parameters in in-memory stateStore (10 min TTL)</li><li>Validates: state, nonce, ID token signature (JWKS), PKCE</li><li>Extracts claims: sub, email, name, groups (from userinfo)</li><li>Applies <code>attribute_mapping</code> JSONB from IdP config</li></ul>`
    },
    'saml-svc': {
      title: 'SAML Service',
      body: `<p>Implements SAML 2.0 SP-initiated and IdP-initiated flows. Located at <code>src/services/saml.service.ts</code>.</p>
<ul><li>Generates AuthnRequest, validates assertions via passport-saml</li><li>Verifies: XML signature (SHA-256), audience, InResponseTo</li><li>Stores nameID and sessionIndex for Single Logout (SLO)</li><li>SHA-1 rejected at config level</li><li>RelayState validated against BASE_URL hostname</li></ul>`
    },
    'webauthn-svc': {
      title: 'WebAuthn Service',
      body: `<p>FIDO2 MFA layer via @simplewebauthn/server. Located at <code>src/services/webauthn.service.ts</code>.</p>
<ul><li>Not standalone — requires existing authenticated session</li><li>Registration: generates options, stores challenge (5 min TTL)</li><li>Authentication: verifies response, updates counter (anti-clone)</li><li>On success: <code>UPDATE sso_sessions SET mfa_verified = true</code></li><li>Algorithms: ES256 (-7), RS256 (-257)</li><li>User verification: <code>required</code></li></ul>`
    },
    'session-svc': {
      title: 'Session Service',
      body: `<p>Manages opaque session tokens. Located at <code>src/services/session.service.ts</code>.</p>
<ul><li>Token: <code>crypto.randomBytes(32).toString('hex')</code> — 256-bit entropy</li><li>Stored <strong>in plaintext</strong> in DB (gap — should be hashed)</li><li>Absolute timeout: checked via <code>expires_at</code></li><li>Idle timeout: checked via <code>last_activity_at + idle_timeout</code></li><li>Updates <code>last_activity_at</code> on every successful validation</li></ul>`
    },
    'audit-svc': {
      title: 'Audit Service',
      body: `<p>Immutable audit logging. Located at <code>src/services/audit.service.ts</code>.</p>
<ul><li>Events: SSO_LOGIN_INITIATED, SSO_LOGIN_FAILURE, SESSION_CREATED, etc.</li><li>Stored in <code>audit_logs</code> table (partitioned by year)</li><li>365-day retention with automated purge</li><li>Some failure paths lack audit events (see Failure Lab)</li></ul>`
    },
    'user-svc': {
      title: 'User Service',
      body: `<p>Handles JIT user provisioning and SCIM lifecycle. Located at <code>src/services/user.service.ts</code>.</p>
<ul><li><code>upsertFromSso()</code>: INSERT or UPDATE on (tenant_id, email)</li><li>Sets roles via <code>role_mappings</code> table (IdP groups to Legora roles)</li><li>Checks <code>is_active</code> — throws 401 if deactivated</li><li>Updates <code>last_login_at</code> on every SSO login</li></ul>`
    },
    'oidc-state': {
      title: 'OIDC State Store',
      body: `<p><strong>In-memory Map</strong> — critical production gap.</p>
<ul><li>Stores: state, nonce, codeVerifier, tenantId, idpConfigId, redirectUrl</li><li>10-minute TTL (entries auto-deleted)</li><li>Lost on process restart — active logins will fail</li><li>Not shared across instances — breaks horizontal scaling</li><li>Code comment: "use Redis in production"</li></ul>`
    },
    'wa-challenge': {
      title: 'WebAuthn Challenge Store',
      body: `<p><strong>In-memory Map</strong> — same gap as OIDC state store.</p>
<ul><li>Stores: challenge, userId, tenantId</li><li>5-minute TTL</li><li>Not shared across instances</li><li>Challenge expiry not logged to audit (gap)</li></ul>`
    },
    redis: {
      title: 'Redis',
      body: `<p><strong>Declared but not wired</strong> in the current codebase.</p>
<ul><li>Referenced in <code>.env.example</code> (REDIS_URL)</li><li><code>ioredis</code> is in package.json dependencies</li><li>No import or usage found in any service file</li><li>Should replace both in-memory Maps and rate limiter store</li><li>Critical for horizontal scaling and session persistence</li></ul>`
    },
    postgres: {
      title: 'PostgreSQL',
      body: `<p>Primary persistent data store. Connection via <code>src/config/database.ts</code>.</p>
<ul><li>Multi-tenant: every table scoped by <code>tenant_id</code></li><li>AES-256-GCM encryption for secrets at rest</li><li>Audit logs partitioned by year</li><li>Migration system in <code>src/db/migrations/</code></li></ul>`
    },
    'tbl-sessions': { title: 'sso_sessions', body: '<p>Active session records. Contains opaque token (plaintext), OIDC/SAML tokens, MFA status, IP, user agent, expiry timestamps. Indexed on <code>(tenant_id, session_token)</code>.</p>' },
    'tbl-users': { title: 'users', body: '<p>User profiles with <code>is_active</code> flag, roles array, groups array, <code>last_login_at</code>. Unique on <code>(tenant_id, email)</code>.</p>' },
    'tbl-idpconfig': { title: 'idp_configs', body: '<p>IdP configuration per tenant. OIDC client secrets and SAML SP private keys stored as AES-256-GCM encrypted blobs. Supports <code>is_default</code> flag and <code>attribute_mapping</code> JSONB.</p>' },
    'tbl-wacreds': { title: 'webauthn_credentials', body: '<p>FIDO2 authenticator registrations. Stores credential ID, public key (COSE), AAGUID, counter, device type, backed-up flag, transports, last used timestamp.</p>' },
    'tbl-audit': { title: 'audit_logs', body: '<p>Immutable audit trail. Partitioned by year (2026 partition exists). Contains event type, actor, target, outcome, IP, user agent, metadata JSONB. 365-day automated retention.</p>' },
    'tbl-refresh': { title: 'refresh_tokens', body: '<p><strong>Schema only — no implementation.</strong> Table exists with family-based replay detection columns, but no service code reads or writes to this table. This is a production gap.</p>' },
  };

  function init() {
    const svg = document.getElementById('arch-svg');
    if (!svg) return;
    drawGroups(svg);
    drawConnections(svg);
    drawNodes(svg);
    bindClicks();
  }

  function svgEl(tag, attrs) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
    return el;
  }

  function drawGroups(svg) {
    for (const g of groups) {
      const rect = svgEl('rect', {
        x: g.x, y: g.y, width: g.w, height: g.h,
        fill: g.color, stroke: 'rgba(42,47,66,0.4)', 'stroke-width': 1,
        class: 'group-rect'
      });
      svg.appendChild(rect);
      const label = svgEl('text', { x: g.x + 10, y: g.y + 14, class: 'group-label' });
      label.textContent = g.label;
      svg.appendChild(label);
    }
  }

  function nodeCenter(n) {
    return { x: n.x + n.w / 2, y: n.y + n.h / 2 };
  }

  function drawConnections(svg) {
    for (const c of connections) {
      const from = nodes.find(n => n.id === c.from);
      const to = nodes.find(n => n.id === c.to);
      if (!from || !to) continue;
      const fc = nodeCenter(from);
      const tc = nodeCenter(to);

      const line = svgEl('line', {
        x1: fc.x, y1: fc.y, x2: tc.x, y2: tc.y,
        class: 'connection',
        stroke: c.color || 'rgba(42,47,66,0.7)',
        'stroke-dasharray': c.dashed ? '4,3' : 'none'
      });
      svg.appendChild(line);

      if (c.label) {
        const mx = (fc.x + tc.x) / 2;
        const my = (fc.y + tc.y) / 2;
        const label = svgEl('text', { x: mx, y: my - 4, class: 'connection-label', 'text-anchor': 'middle' });
        label.textContent = c.label;
        svg.appendChild(label);
      }
    }
  }

  function drawNodes(svg) {
    for (const n of nodes) {
      const g = svgEl('g', { 'data-node': n.id, style: 'cursor:pointer' });

      const rect = svgEl('rect', {
        x: n.x, y: n.y, width: n.w, height: n.h,
        rx: 6, ry: 6,
        fill: n.color + '18',
        stroke: n.color,
        'stroke-width': 1.5,
        class: 'node-rect'
      });
      g.appendChild(rect);

      const label = svgEl('text', { x: n.x + n.w / 2, y: n.y + n.h / 2 - 4, class: 'node-label', 'text-anchor': 'middle' });
      label.textContent = n.label;
      g.appendChild(label);

      const sub = svgEl('text', { x: n.x + n.w / 2, y: n.y + n.h / 2 + 10, class: 'node-sublabel', 'text-anchor': 'middle' });
      sub.textContent = n.sublabel;
      g.appendChild(sub);

      svg.appendChild(g);
    }
  }

  function bindClicks() {
    const svg = document.getElementById('arch-svg');
    const detail = document.getElementById('arch-detail');
    svg.addEventListener('click', (e) => {
      const g = e.target.closest('[data-node]');
      if (!g) return;
      const id = g.dataset.node;
      const info = nodeDetails[id];
      if (!info) return;

      // Highlight
      svg.querySelectorAll('.node-rect').forEach(r => r.setAttribute('stroke-width', '1.5'));
      g.querySelector('.node-rect').setAttribute('stroke-width', '3');

      detail.innerHTML = `<div class="detail-title">${info.title}</div><div class="detail-body">${info.body}</div>`;
    });
  }

  return { init };
})();
