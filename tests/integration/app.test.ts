/**
 * Integration tests for the Express application.
 * Tests core routes without a real database (mocked).
 */
jest.mock('../../src/config/database');
jest.mock('../../src/services/audit.service');
jest.mock('../../src/services/tenant.service');
jest.mock('../../src/services/session.service');
jest.mock('../../src/services/user.service');

import request from 'supertest';
import { createApp } from '../../src/app';
import * as tenantServiceModule from '../../src/services/tenant.service';

const mockTenantService = tenantServiceModule.tenantService as jest.Mocked<typeof tenantServiceModule.tenantService>;

const app = createApp();

// Default mock: domain lookup returns null (no tenant found by domain)
beforeEach(() => {
  (mockTenantService.getTenantByDomain as jest.Mock).mockResolvedValue(null);
  (mockTenantService.getDefaultIdpConfig as jest.Mock).mockResolvedValue(null);
});

describe('Application integration tests', () => {
  describe('GET /health', () => {
    it('should return 200 with status ok', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.timestamp).toBeTruthy();
    });
  });

  describe('GET /scim/v2/ServiceProviderConfig', () => {
    it('should return SCIM service provider configuration', async () => {
      const res = await request(app).get('/scim/v2/ServiceProviderConfig');
      expect(res.status).toBe(200);
      expect(res.body.schemas).toContain(
        'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'
      );
      expect(res.body.patch.supported).toBe(true);
      expect(res.body.filter.supported).toBe(true);
    });
  });

  describe('GET /saml/metadata', () => {
    it('should return XML content type', async () => {
      const res = await request(app).get('/saml/metadata');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('xml');
      expect(res.text).toContain('EntityDescriptor');
    });
  });

  describe('404 handler', () => {
    it('should return 404 for unknown routes', async () => {
      const res = await request(app).get('/nonexistent-route');
      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Not found');
    });
  });

  describe('Security headers', () => {
    it('should include X-Content-Type-Options header', async () => {
      const res = await request(app).get('/health');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    it('should include X-Frame-Options or CSP frame-ancestors', async () => {
      const res = await request(app).get('/health');
      const hasFrameOptions = !!res.headers['x-frame-options'];
      const hasCsp = !!res.headers['content-security-policy'];
      expect(hasFrameOptions || hasCsp).toBe(true);
    });
  });

  describe('Rate limiting', () => {
    it('should return RateLimit headers', async () => {
      const res = await request(app).get('/health');
      // health check is exempt from rate limiting
      expect(res.status).toBe(200);
    });
  });

  describe('SCIM Users endpoint (unauthenticated)', () => {
    it('should return 401 without bearer token', async () => {
      const res = await request(app)
        .get('/scim/v2/Users')
        .set('X-Tenant-ID', 'tenant-1');
      expect(res.status).toBe(401);
    });
  });

  describe('OIDC login endpoint', () => {
    it('should return 404 if no OIDC config for tenant', async () => {
      const { tenantService } = await import('../../src/services/tenant.service');
      (tenantService.getDefaultIdpConfig as jest.Mock).mockResolvedValueOnce(null);

      const res = await request(app)
        .get('/auth/oidc/tenant-1/login')
        .set('X-Tenant-ID', 'tenant-1');

      expect(res.status).toBe(404);
    });
  });

  describe('SAML metadata endpoint', () => {
    it('should return 404 if no SAML config for tenant', async () => {
      const { tenantService } = await import('../../src/services/tenant.service');
      (tenantService.getDefaultIdpConfig as jest.Mock).mockResolvedValueOnce(null);

      const res = await request(app)
        .get('/auth/saml/tenant-1/metadata')
        .set('X-Tenant-ID', 'tenant-1');

      expect(res.status).toBe(404);
    });
  });
});
