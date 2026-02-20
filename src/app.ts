/**
 * Express application factory.
 * Configures middleware, routes, and security headers.
 */
import express, { Application, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import { config } from './config';
import { requestLogger } from './middleware/audit';
import { resolveTenant } from './middleware/tenant';
import { logger } from './utils/logger';

// Route imports
import oidcRouter from './routes/auth/oidc';
import samlRouter from './routes/auth/saml';
import webauthnRouter from './routes/auth/webauthn';
import scimUsersRouter from './routes/scim/users';
import scimGroupsRouter from './routes/scim/groups';
import adminTenantRouter from './routes/admin/tenant';
import netdocumentsRouter from './routes/dms/netdocuments';
import imanageRouter from './routes/dms/imanage';
import wordAddinRouter from './routes/addon/word';

export function createApp(): Application {
  const app = express();

  // ─── Security Headers ────────────────────────────────────────────────────
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: config.NODE_ENV === 'production' ? [] : null,
        },
      },
      hsts: config.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
    })
  );

  // ─── CORS ─────────────────────────────────────────────────────────────────
  const allowedOrigins = config.CORS_ALLOWED_ORIGINS.split(',').map((o) => o.trim());
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error(`CORS: origin ${origin} not allowed`));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
    })
  );

  // ─── Compression & Parsing ────────────────────────────────────────────────
  app.use(compression());
  // Parse JSON including application/scim+json (SCIM protocol content type)
  app.use(express.json({ limit: '1mb', type: ['application/json', 'application/scim+json'] }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));
  app.use(cookieParser());

  // ─── Rate Limiting ────────────────────────────────────────────────────────
  const limiter = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: config.RATE_LIMIT_MAX_REQUESTS,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later' },
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === '/health';
    },
  });
  app.use(limiter);

  // Stricter limit for auth endpoints
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    message: { error: 'Too many authentication attempts, please try again later' },
  });

  // ─── Request Logging ──────────────────────────────────────────────────────
  app.use(requestLogger);

  // ─── Trust Proxy (for correct IP behind reverse proxy) ───────────────────
  if (config.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
  }

  // ─── Tenant Resolution ───────────────────────────────────────────────────
  app.use(resolveTenant);

  // ─── Health Check ────────────────────────────────────────────────────────
  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // ─── SAML SP Metadata (public endpoint) ──────────────────────────────────
  app.get('/saml/metadata', (_req: Request, res: Response) => {
    // Global default metadata – tenant-specific at /auth/saml/:tenantId/metadata
    res.set('Content-Type', 'application/xml');
    res.send(`<?xml version="1.0"?><EntityDescriptor entityID="${config.SAML_SP_ENTITY_ID}" />`);
  });

  // ─── SCIM Service Provider Configuration ─────────────────────────────────
  app.get('/scim/v2/ServiceProviderConfig', (_req: Request, res: Response) => {
    res.type('application/scim+json').json({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 200 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [
        {
          name: 'OAuth Bearer Token',
          description: 'Authentication scheme using the OAuth Bearer Token Standard',
          specUri: 'http://www.rfc-editor.org/info/rfc6750',
          type: 'oauthbearertoken',
          primary: true,
        },
      ],
      meta: {
        resourceType: 'ServiceProviderConfig',
        location: `${config.SCIM_BASE_URL}/ServiceProviderConfig`,
      },
    });
  });

  // ─── Routes ───────────────────────────────────────────────────────────────
  app.use('/auth/oidc', authLimiter, oidcRouter);
  app.use('/auth/saml', authLimiter, samlRouter);
  app.use('/auth/webauthn', webauthnRouter);
  app.use('/scim/v2/Users', scimUsersRouter);
  app.use('/scim/v2/Groups', scimGroupsRouter);
  app.use('/admin/tenants', adminTenantRouter);
  app.use('/dms/netdocuments', netdocumentsRouter);
  app.use('/dms/imanage', imanageRouter);
  app.use('/addon/word', wordAddinRouter);

  // ─── 404 Handler ─────────────────────────────────────────────────────────
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });

  // ─── Error Handler ────────────────────────────────────────────────────────
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled error', { err: err.message, stack: err.stack });
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
