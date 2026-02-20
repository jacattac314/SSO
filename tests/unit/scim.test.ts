/**
 * Unit tests for SCIM service.
 */
jest.mock('../../src/config/database');
jest.mock('../../src/services/audit.service');
jest.mock('../../src/services/user.service');
jest.mock('../../src/services/session.service');

import { scimService, ScimError } from '../../src/services/scim.service';
import * as userServiceModule from '../../src/services/user.service';
import { User } from '../../src/services/user.service';
import * as db from '../../src/config/database';

const mockQuery = db.query as jest.MockedFunction<typeof db.query>;
const mockUserService = userServiceModule.userService as jest.Mocked<typeof userServiceModule.userService>;

const mockUser: User = {
  id: 'user-1',
  tenantId: 'tenant-1',
  externalId: 'ext-1',
  username: 'jdoe',
  email: 'john.doe@example.com',
  firstName: 'John',
  lastName: 'Doe',
  displayName: 'John Doe',
  isActive: true,
  roles: ['user'],
  groups: [],
  scimId: 'scim-user-1',
  scimVersion: 0,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01'),
};

describe('ScimService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getUser', () => {
    it('should return SCIM user for valid ID', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce(mockUser);

      const result = await scimService.getUser('tenant-1', 'scim-user-1');

      expect(result.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:User');
      expect(result.emails[0].value).toBe('john.doe@example.com');
      expect(result.name?.givenName).toBe('John');
      expect(result.active).toBe(true);
    });

    it('should throw ScimError 404 if user not found', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce(null);

      await expect(scimService.getUser('tenant-1', 'nonexistent')).rejects.toThrow(ScimError);
      await expect(scimService.getUser('tenant-1', 'nonexistent')).rejects.toMatchObject({ status: 404 });
    });

    it('should throw ScimError 404 if user belongs to different tenant', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce({ ...mockUser, tenantId: 'other-tenant' });

      await expect(scimService.getUser('tenant-1', 'scim-user-1')).rejects.toThrow(ScimError);
    });
  });

  describe('createUser', () => {
    it('should create a user with valid data', async () => {
      mockUserService.findByEmail.mockResolvedValueOnce(null); // No existing user
      mockQuery.mockResolvedValueOnce({ rows: [mockUser], rowCount: 1 });

      const result = await scimService.createUser('tenant-1', {
        userName: 'jdoe',
        emails: [{ value: 'john.doe@example.com', primary: true }],
        name: { givenName: 'John', familyName: 'Doe' },
        active: true,
      });

      expect(result.emails[0].value).toBe('john.doe@example.com');
    });

    it('should throw ScimError 400 if email missing', async () => {
      await expect(
        scimService.createUser('tenant-1', { userName: 'x' })
      ).rejects.toMatchObject({ status: 400, scimType: 'invalidValue' });
    });

    it('should throw ScimError 409 if user already exists', async () => {
      mockUserService.findByEmail.mockResolvedValueOnce(mockUser);

      await expect(
        scimService.createUser('tenant-1', {
          userName: 'existing',
          emails: [{ value: 'john.doe@example.com', primary: true }],
        })
      ).rejects.toMatchObject({ status: 409, scimType: 'uniqueness' });
    });
  });

  describe('deleteUser', () => {
    it('should delete an existing user', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce(mockUser);
      const { sessionService } = await import('../../src/services/session.service');
      (sessionService.terminateAllForUser as jest.Mock).mockResolvedValueOnce(0);
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await expect(scimService.deleteUser('tenant-1', 'scim-user-1')).resolves.toBeUndefined();
    });

    it('should throw ScimError 404 if user not found', async () => {
      mockUserService.findByScimId.mockResolvedValueOnce(null);

      await expect(scimService.deleteUser('tenant-1', 'nonexistent')).rejects.toMatchObject({ status: 404 });
    });
  });

  describe('patchUser – deactivation', () => {
    it('should call updateUser with active=false operation', async () => {
      const inactiveUser = { ...mockUser, isActive: false };
      // Use mockImplementation for consistent mock behavior
      (mockUserService.findByScimId as jest.Mock).mockResolvedValue(mockUser);
      (mockUserService.deactivate as jest.Mock).mockResolvedValue(undefined);
      (mockUserService.findById as jest.Mock).mockResolvedValue(inactiveUser);
      mockQuery.mockResolvedValue({ rows: [], rowCount: 1 });

      const result = await scimService.patchUser(
        'tenant-1',
        'scim-user-1',
        [{ op: 'replace', path: 'active', value: false }]
      );

      expect(result.active).toBe(false);
      expect(mockUserService.deactivate).toHaveBeenCalledWith('tenant-1', mockUser.id);
    });
  });
});
