/**
 * Jest global setup – configure environment variables for tests.
 */
process.env.NODE_ENV = 'test';
process.env.PORT = '3001';
process.env.BASE_URL = 'http://localhost:3001';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/legora_sso_test';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-session-secret-at-least-32-chars-long';
process.env.JWT_SECRET = 'test-jwt-secret-min-32-chars-long-xxxx';
process.env.JWT_ISSUER = 'http://localhost:3001';
process.env.JWT_ACCESS_TOKEN_TTL = '3600';
process.env.JWT_REFRESH_TOKEN_TTL = '7776000';
process.env.SESSION_IDLE_TIMEOUT = '900';
process.env.SESSION_ABSOLUTE_TIMEOUT = '28800';
process.env.TENANT_SECRET_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SAML_SP_ENTITY_ID = 'http://localhost:3001/saml/metadata';
process.env.SAML_SP_ACS_URL = 'http://localhost:3001/auth/saml/acs';
process.env.SAML_SP_SLO_URL = 'http://localhost:3001/auth/saml/slo';
process.env.SCIM_BASE_URL = 'http://localhost:3001/scim/v2';
process.env.SCIM_BEARER_SECRET = 'test-scim-secret';
process.env.CERT_EXPIRY_WARN_DAYS = '30';
process.env.AUDIT_LOG_RETENTION_DAYS = '365';
process.env.RATE_LIMIT_WINDOW_MS = '60000';
process.env.RATE_LIMIT_MAX_REQUESTS = '1000';
process.env.CORS_ALLOWED_ORIGINS = 'http://localhost:3001';
