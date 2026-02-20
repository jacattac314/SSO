/**
 * Unit tests for session service.
 * Uses mocked database queries.
 */
jest.mock('../../src/config/database');
jest.mock('../../src/services/audit.service');

import { sessionService } from '../../src/services/session.service';
import * as db from '../../src/config/database';

const mockQuery = db.query as jest.MockedFunction<typeof db.query>;

describe('SessionService', () => {
  const tenantId = 'tenant-uuid-1';
  const userId = 'user-uuid-1';
  const sessionToken = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    it('should insert session and return token', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      const token = await sessionService.create({
        tenantId,
        userId,
        ipAddress: '1.2.3.4',
      });

      expect(typeof token).toBe('string');
      expect(token.length).toBe(64); // 32 bytes hex
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO sso_sessions'),
        expect.arrayContaining([tenantId, userId])
      );
    });
  });

  describe('validate', () => {
    it('should return session if valid', async () => {
      const now = new Date();
      const future = new Date(now.getTime() + 3600 * 1000);
      const mockSession = {
        id: 'session-1',
        tenantId,
        userId,
        idpConfigId: null,
        sessionToken,
        samlNameId: null,
        samlSessionIndex: null,
        samlNameIdFormat: null,
        oidcIdToken: null,
        oidcAccessToken: null,
        oidcRefreshToken: null,
        oidcTokenExp: null,
        createdAt: now,
        lastActivityAt: now,
        expiresAt: future,
        ipAddress: null,
        userAgent: null,
        mfaVerified: false,
        mfaMethod: null,
        expires_at: future,
        last_activity_at: now,
        created_at: now,
      };

      mockQuery
        .mockResolvedValueOnce({ rows: [mockSession], rowCount: 1 })  // SELECT
        .mockResolvedValueOnce({ rows: [], rowCount: 1 });             // UPDATE

      const session = await sessionService.validate(sessionToken);
      expect(session).not.toBeNull();
      expect(session?.userId).toBe(userId);
    });

    it('should return null if session not found', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
      const session = await sessionService.validate('nonexistent-token');
      expect(session).toBeNull();
    });

    it('should terminate and return null for expired session', async () => {
      const past = new Date(Date.now() - 3600 * 1000);
      const mockSession = {
        id: 'session-1',
        tenantId,
        userId,
        lastActivityAt: past,
        expiresAt: past,
        expires_at: past,
        last_activity_at: past,
      };

      mockQuery
        .mockResolvedValueOnce({ rows: [mockSession], rowCount: 1 })  // SELECT
        .mockResolvedValueOnce({ rows: [{ tenant_id: tenantId, user_id: userId }], rowCount: 1 }); // DELETE

      const session = await sessionService.validate(sessionToken);
      expect(session).toBeNull();
    });
  });

  describe('terminate', () => {
    it('should delete session from database', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ tenant_id: tenantId, user_id: userId }],
        rowCount: 1,
      });

      await sessionService.terminate(sessionToken, 'logout');
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM sso_sessions'),
        [sessionToken]
      );
    });
  });

  describe('terminateAllForUser', () => {
    it('should delete all user sessions', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ tenant_id: tenantId }],
        rowCount: 2,
      });

      const count = await sessionService.terminateAllForUser(userId, 'scim_deactivated');
      expect(count).toBe(1); // rows returned = 1 (rowCount mock)
    });
  });
});
