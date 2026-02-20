/**
 * Integration tests for SCIM 2.0 API endpoints.
 */
jest.mock('../../src/config/database');
jest.mock('../../src/services/audit.service');
jest.mock('../../src/services/user.service');
jest.mock('../../src/services/session.service');
jest.mock('../../src/services/tenant.service');
jest.mock('bcrypt');

import request from 'supertest';
import { createApp } from '../../src/app';
import * as db from '../../src/config/database';
import * as userServiceModule from '../../src/services/user.service';
import * as tenantServiceModule from '../../src/services/tenant.service';
import { User } from '../../src/services/user.service';
import bcrypt from 'bcrypt';

const mockQuery = db.query as jest.MockedFunction<typeof db.query>;
const mockUserService = userServiceModule.userService as jest.Mocked<typeof userServiceModule.userService>;
const mockTenantService = tenantServiceModule.tenantService as jest.Mocked<typeof tenantServiceModule.tenantService>;
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

const app = createApp();

const SCIM_TOKEN = 'test-scim-bearer-token';
const TENANT_ID = 'tenant-test-1';

const mockUser: User = {
  id: 'user-1',
  tenantId: TENANT_ID,
  externalId: null,
  username: 'testuser',
  email: 'test@example.com',
  firstName: 'Test',
  lastName: 'User',
  displayName: 'Test User',
  isActive: true,
  roles: ['user'],
  groups: [],
  scimId: 'scim-1',
  scimVersion: 0,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01'),
};

function authHeaders() {
  return {
    Authorization: `Bearer ${SCIM_TOKEN}`,
    'X-Tenant-ID': TENANT_ID,
    'Content-Type': 'application/scim+json',
  };
}

describe('SCIM 2.0 API', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Mock SCIM token validation
    mockQuery.mockResolvedValue({ rows: [{ scim_token_hash: '$2b$12$hash' }], rowCount: 1 });
    (mockBcrypt.compare as jest.Mock).mockResolvedValue(true);
    (mockTenantService.getTenantByDomain as jest.Mock).mockResolvedValue(null);
  });

  describe('GET /scim/v2/Users', () => {
    it('should return a list response', async () => {
      mockUserService.list.mockResolvedValueOnce({
        users: [mockUser],
        total: 1,
      });

      const res = await request(app)
        .get('/scim/v2/Users')
        .set(authHeaders());

      expect(res.status).toBe(200);
      expect(res.body.schemas).toContain('urn:ietf:params:scim:api:messages:2.0:ListResponse');
      expect(res.body.totalResults).toBe(1);
      expect(res.body.Resources).toHaveLength(1);
      expect(res.body.Resources[0].emails[0].value).toBe('test@example.com');
    });
  });

  describe('GET /scim/v2/Users/:id', () => {
    it('should return a single user', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce(mockUser);

      const res = await request(app)
        .get('/scim/v2/Users/scim-1')
        .set(authHeaders());

      expect(res.status).toBe(200);
      expect(res.body.id).toBe('scim-1');
      expect(res.body.userName).toBe('testuser');
    });

    it('should return 404 for unknown user', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce(null);

      const res = await request(app)
        .get('/scim/v2/Users/nonexistent')
        .set(authHeaders());

      expect(res.status).toBe(404);
      expect(res.body.schemas).toContain('urn:ietf:params:scim:api:messages:2.0:Error');
    });
  });

  describe('POST /scim/v2/Users', () => {
    it('should create a new user and return 201', async () => {
      mockUserService.findByEmail.mockResolvedValueOnce(null);
      // First query: SCIM auth check (from beforeEach default), second: INSERT
      mockQuery.mockResolvedValueOnce({ rows: [{ scim_token_hash: '$2b$12$hash' }], rowCount: 1 });
      mockQuery.mockResolvedValueOnce({ rows: [mockUser], rowCount: 1 });

      const res = await request(app)
        .post('/scim/v2/Users')
        .set(authHeaders())
        .send({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'newuser',
          name: { givenName: 'New', familyName: 'User' },
          emails: [{ value: 'new@example.com', primary: true, type: 'work' }],
          active: true,
        });

      expect(res.status).toBe(201);
    });

    it('should return 400 if userName is missing', async () => {
      const res = await request(app)
        .post('/scim/v2/Users')
        .set(authHeaders())
        .send({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          emails: [{ value: 'no-username@example.com', primary: true }],
        });

      expect(res.status).toBe(400);
    });
  });

  describe('DELETE /scim/v2/Users/:id', () => {
    it('should return 204 on successful deletion', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce(mockUser);
      const { sessionService } = await import('../../src/services/session.service');
      (sessionService.terminateAllForUser as jest.Mock).mockResolvedValueOnce(0);
      // auth check + DELETE query
      mockQuery.mockResolvedValueOnce({ rows: [{ scim_token_hash: '$2b$12$hash' }], rowCount: 1 });
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      const res = await request(app)
        .delete('/scim/v2/Users/scim-1')
        .set(authHeaders());

      expect(res.status).toBe(204);
    });
  });

  describe('PATCH /scim/v2/Users/:id – deactivation', () => {
    it('should deactivate user via PATCH', async () => {
      const inactiveUser = { ...mockUser, isActive: false };
      (mockUserService.findByScimId as jest.Mock).mockResolvedValue(mockUser);
      (mockUserService.deactivate as jest.Mock).mockResolvedValue(undefined);
      (mockUserService.findById as jest.Mock).mockResolvedValue(inactiveUser);
      // auth check + UPDATE query
      mockQuery.mockResolvedValueOnce({ rows: [{ scim_token_hash: '$2b$12$hash' }], rowCount: 1 });
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      const res = await request(app)
        .patch('/scim/v2/Users/scim-1')
        .set(authHeaders())
        .send({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [{ op: 'replace', path: 'active', value: false }],
        });

      expect(res.status).toBe(200);
      expect(res.body.active).toBe(false);
    });
  });
});
