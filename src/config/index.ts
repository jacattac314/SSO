import { z } from 'zod';

const configSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),
  BASE_URL: z.string().url().default('http://localhost:3000'),

  // Database
  DATABASE_URL: z.string().default('postgresql://legora:password@localhost:5432/legora_sso'),
  DATABASE_POOL_MIN: z.coerce.number().default(2),
  DATABASE_POOL_MAX: z.coerce.number().default(10),

  // Redis
  REDIS_URL: z.string().default('redis://localhost:6379'),
  SESSION_SECRET: z.string().min(32).default('dev-session-secret-change-in-prod-xxxxx'),

  // JWT
  JWT_SECRET: z.string().min(32).default('dev-jwt-secret-change-in-prod-xxxxxxxxx'),
  JWT_ISSUER: z.string().default('http://localhost:3000'),
  JWT_ACCESS_TOKEN_TTL: z.coerce.number().default(3600),
  JWT_REFRESH_TOKEN_TTL: z.coerce.number().default(7776000),

  // Session timeouts (seconds)
  SESSION_IDLE_TIMEOUT: z.coerce.number().default(900),
  SESSION_ABSOLUTE_TIMEOUT: z.coerce.number().default(28800),

  // SAML SP
  SAML_SP_ENTITY_ID: z.string().default('http://localhost:3000/saml/metadata'),
  SAML_SP_ACS_URL: z.string().default('http://localhost:3000/auth/saml/acs'),
  SAML_SP_SLO_URL: z.string().default('http://localhost:3000/auth/saml/slo'),
  SAML_SP_CERT_FILE: z.string().default('./certs/sp.crt'),
  SAML_SP_KEY_FILE: z.string().default('./certs/sp.key'),

  // SCIM
  SCIM_BASE_URL: z.string().default('http://localhost:3000/scim/v2'),
  SCIM_BEARER_SECRET: z.string().default('dev-scim-bearer-token'),

  // Certificate monitoring
  CERT_EXPIRY_WARN_DAYS: z.coerce.number().default(30),

  // Tenant secret encryption (AES-256, 64-char hex = 32 bytes)
  TENANT_SECRET_ENCRYPTION_KEY: z
    .string()
    .default('0000000000000000000000000000000000000000000000000000000000000000'),

  // Audit log retention
  AUDIT_LOG_RETENTION_DAYS: z.coerce.number().default(365),

  // Rate limiting
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(60000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100),

  // CORS
  CORS_ALLOWED_ORIGINS: z.string().default('http://localhost:3001'),
});

function loadConfig(): z.infer<typeof configSchema> {
  const result = configSchema.safeParse(process.env);
  if (!result.success) {
    const errors = result.error.format();
    throw new Error(`Configuration validation failed: ${JSON.stringify(errors, null, 2)}`);
  }
  return result.data;
}

export const config = loadConfig();

export type Config = typeof config;
