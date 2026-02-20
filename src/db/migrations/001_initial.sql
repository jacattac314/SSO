-- Legora SSO MVP – Initial Database Schema
-- Supports multi-tenancy via tenant_id on every table

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- TENANTS
-- ============================================================
CREATE TABLE IF NOT EXISTS tenants (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            VARCHAR(255) NOT NULL,
  domain          VARCHAR(255) NOT NULL UNIQUE,
  is_active       BOOLEAN NOT NULL DEFAULT true,
  sso_enabled     BOOLEAN NOT NULL DEFAULT false,
  -- Provisioning settings
  scim_enabled    BOOLEAN NOT NULL DEFAULT false,
  scim_token_hash VARCHAR(512),           -- bcrypt hash of SCIM bearer token
  -- Timeouts (seconds; NULL = use global defaults)
  idle_timeout_seconds     INTEGER,
  absolute_timeout_seconds INTEGER,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_domain ON tenants(domain);

-- ============================================================
-- IDP CONFIGURATIONS  (one tenant can have multiple IdP configs)
-- ============================================================
CREATE TABLE IF NOT EXISTS idp_configs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            VARCHAR(255) NOT NULL,
  protocol        VARCHAR(10) NOT NULL CHECK (protocol IN ('oidc', 'saml')),
  is_active       BOOLEAN NOT NULL DEFAULT true,
  is_default      BOOLEAN NOT NULL DEFAULT false,

  -- OIDC fields
  oidc_issuer            TEXT,
  oidc_client_id         TEXT,
  oidc_client_secret_enc TEXT,   -- AES-256 encrypted
  oidc_discovery_url     TEXT,
  oidc_jwks_uri          TEXT,
  oidc_token_endpoint    TEXT,
  oidc_userinfo_endpoint TEXT,
  oidc_authorization_endpoint TEXT,
  oidc_logout_endpoint   TEXT,
  oidc_scopes            TEXT[] DEFAULT ARRAY['openid','profile','email'],

  -- SAML fields
  saml_idp_entity_id     TEXT,
  saml_idp_sso_url       TEXT,
  saml_idp_slo_url       TEXT,
  saml_idp_certificate   TEXT,           -- PEM public cert
  saml_sp_entity_id      TEXT,
  saml_sp_acs_url        TEXT,
  saml_sp_slo_url        TEXT,
  saml_sp_certificate    TEXT,           -- PEM public cert
  saml_sp_private_key_enc TEXT,          -- AES-256 encrypted private key
  saml_sign_requests     BOOLEAN NOT NULL DEFAULT true,
  saml_want_assertions_signed BOOLEAN NOT NULL DEFAULT true,
  saml_name_id_format    TEXT DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',

  -- Attribute mapping (JSON): { "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", ... }
  attribute_mapping       JSONB NOT NULL DEFAULT '{}',

  -- Certificate expiry tracking
  idp_cert_expires_at    TIMESTAMPTZ,
  sp_cert_expires_at     TIMESTAMPTZ,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (tenant_id, name)
);

CREATE INDEX idx_idp_configs_tenant ON idp_configs(tenant_id);
CREATE INDEX idx_idp_configs_protocol ON idp_configs(tenant_id, protocol, is_active);

-- ============================================================
-- ROLE MAPPINGS  (IdP group/role → Legora role)
-- ============================================================
CREATE TABLE IF NOT EXISTS role_mappings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  idp_config_id   UUID NOT NULL REFERENCES idp_configs(id) ON DELETE CASCADE,
  idp_group_value TEXT NOT NULL,     -- the value from IdP claim/attribute
  legora_role     VARCHAR(100) NOT NULL,  -- e.g. 'admin', 'user', 'viewer'
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_role_mappings_tenant ON role_mappings(tenant_id, idp_config_id);

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_id     VARCHAR(512),              -- IdP subject / SCIM externalId
  username        VARCHAR(255),
  email           VARCHAR(255) NOT NULL,
  first_name      VARCHAR(255),
  last_name       VARCHAR(255),
  display_name    VARCHAR(512),
  is_active       BOOLEAN NOT NULL DEFAULT true,
  roles           TEXT[] NOT NULL DEFAULT '{}',
  groups          TEXT[] NOT NULL DEFAULT '{}',
  -- SCIM metadata
  scim_id         UUID UNIQUE,
  scim_version    INTEGER NOT NULL DEFAULT 0,
  -- WebAuthn / FIDO2
  webauthn_credentials JSONB NOT NULL DEFAULT '[]',
  webauthn_challenge   TEXT,                -- current pending challenge
  -- Timestamps
  last_login_at   TIMESTAMPTZ,
  password_reset_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (tenant_id, email),
  UNIQUE (tenant_id, external_id)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(tenant_id, email);
CREATE INDEX idx_users_external ON users(tenant_id, external_id);
CREATE INDEX idx_users_scim ON users(scim_id);

-- ============================================================
-- SESSIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS sso_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  idp_config_id   UUID REFERENCES idp_configs(id),
  session_token   VARCHAR(512) NOT NULL UNIQUE,  -- random opaque token
  -- SAML session data (for SLO)
  saml_name_id        TEXT,
  saml_session_index  TEXT,
  saml_name_id_format TEXT,
  -- OIDC session data
  oidc_id_token       TEXT,
  oidc_access_token   TEXT,
  oidc_refresh_token  TEXT,
  oidc_token_exp      TIMESTAMPTZ,
  -- Timing
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_activity_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at          TIMESTAMPTZ NOT NULL,
  -- Metadata
  ip_address          INET,
  user_agent          TEXT,
  mfa_verified        BOOLEAN NOT NULL DEFAULT false,
  mfa_method          VARCHAR(50)    -- 'webauthn', 'totp', 'sms'
);

CREATE INDEX idx_sessions_token ON sso_sessions(session_token);
CREATE INDEX idx_sessions_user ON sso_sessions(user_id);
CREATE INDEX idx_sessions_tenant ON sso_sessions(tenant_id);
CREATE INDEX idx_sessions_expires ON sso_sessions(expires_at);
CREATE INDEX idx_sessions_saml ON sso_sessions(saml_session_index) WHERE saml_session_index IS NOT NULL;

-- ============================================================
-- REFRESH TOKENS  (rotating)
-- ============================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id      UUID REFERENCES sso_sessions(id) ON DELETE CASCADE,
  token_hash      VARCHAR(512) NOT NULL UNIQUE,  -- SHA-256 hash of token
  is_revoked      BOOLEAN NOT NULL DEFAULT false,
  family_id       UUID NOT NULL,             -- token family for rotation detection
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at         TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);

-- ============================================================
-- WEBAUTHN CREDENTIALS
-- ============================================================
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id     TEXT NOT NULL UNIQUE,     -- base64url encoded
  credential_public_key TEXT NOT NULL,        -- base64url encoded COSE key
  counter           BIGINT NOT NULL DEFAULT 0,
  device_type       VARCHAR(32),              -- 'singleDevice' | 'multiDevice'
  backed_up         BOOLEAN NOT NULL DEFAULT false,
  transports        TEXT[],
  aaguid            TEXT,
  name              VARCHAR(255),             -- user-friendly name
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at      TIMESTAMPTZ
);

CREATE INDEX idx_webauthn_user ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_cred_id ON webauthn_credentials(credential_id);

-- ============================================================
-- AUDIT LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
  id              BIGSERIAL PRIMARY KEY,
  tenant_id       UUID REFERENCES tenants(id),
  user_id         UUID REFERENCES users(id),
  actor_email     VARCHAR(255),
  event_type      VARCHAR(100) NOT NULL,    -- e.g. 'sso.login', 'scim.user.create'
  outcome         VARCHAR(20) NOT NULL CHECK (outcome IN ('success', 'failure', 'error')),
  ip_address      INET,
  user_agent      TEXT,
  idp_config_id   UUID REFERENCES idp_configs(id),
  details         JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Create initial partition (current year)
CREATE TABLE audit_logs_2026 PARTITION OF audit_logs
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_event ON audit_logs(event_type, created_at DESC);
CREATE INDEX idx_audit_outcome ON audit_logs(outcome, created_at DESC);

-- ============================================================
-- SCIM GROUPS
-- ============================================================
CREATE TABLE IF NOT EXISTS scim_groups (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  display_name    VARCHAR(255) NOT NULL,
  external_id     VARCHAR(512),
  members         UUID[] NOT NULL DEFAULT '{}',   -- array of user IDs
  scim_version    INTEGER NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (tenant_id, display_name)
);

CREATE INDEX idx_scim_groups_tenant ON scim_groups(tenant_id);

-- ============================================================
-- DMS TOKENS  (OAuth tokens for DMS integrations)
-- ============================================================
CREATE TABLE IF NOT EXISTS dms_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  dms_type        VARCHAR(50) NOT NULL CHECK (dms_type IN ('netdocuments', 'imanage', 'sharepoint')),
  access_token_enc TEXT NOT NULL,    -- AES-256 encrypted
  refresh_token_enc TEXT,            -- AES-256 encrypted
  token_type      VARCHAR(50),
  expires_at      TIMESTAMPTZ,
  scope           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (tenant_id, user_id, dms_type)
);

CREATE INDEX idx_dms_tokens_user ON dms_tokens(user_id, dms_type);

-- ============================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================

-- Auto-update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_tenants_updated_at
  BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_idp_configs_updated_at
  BEFORE UPDATE ON idp_configs
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scim_groups_updated_at
  BEFORE UPDATE ON scim_groups
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
