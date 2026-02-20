/**
 * Unit tests for audit service.
 */
jest.mock('../../src/config/database');

import { auditService, AuditEventType } from '../../src/services/audit.service';
import * as db from '../../src/config/database';

const mockQuery = db.query as jest.MockedFunction<typeof db.query>;

describe('AuditService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('log', () => {
    it('should persist an audit event to the database', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditService.log({
        tenantId: 'tenant-1',
        userId: 'user-1',
        actorEmail: 'user@example.com',
        eventType: AuditEventType.SSO_LOGIN_SUCCESS,
        outcome: 'success',
        ipAddress: '1.2.3.4',
        details: { protocol: 'oidc' },
      });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO audit_logs'),
        expect.arrayContaining([
          'tenant-1',
          'user-1',
          'user@example.com',
          AuditEventType.SSO_LOGIN_SUCCESS,
          'success',
        ])
      );
    });

    it('should not throw if database insert fails (non-blocking)', async () => {
      mockQuery.mockRejectedValueOnce(new Error('DB connection lost'));

      await expect(
        auditService.log({
          tenantId: 'tenant-1',
          eventType: AuditEventType.SSO_LOGIN_FAILURE,
          outcome: 'failure',
        })
      ).resolves.toBeUndefined();
    });
  });

  describe('queryLogs', () => {
    it('should query audit logs with filters', async () => {
      const mockLogs = [
        { id: 1, event_type: AuditEventType.SSO_LOGIN_SUCCESS, outcome: 'success' },
      ];
      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '1' }], rowCount: 1 })
        .mockResolvedValueOnce({ rows: mockLogs, rowCount: 1 });

      const result = await auditService.queryLogs({
        tenantId: 'tenant-1',
        eventType: AuditEventType.SSO_LOGIN_SUCCESS,
        limit: 10,
        offset: 0,
      });

      expect(result.total).toBe(1);
      expect(result.rows).toHaveLength(1);
    });
  });

  describe('purgeOldLogs', () => {
    it('should delete logs older than retention period', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 42 });

      const count = await auditService.purgeOldLogs(365);
      expect(count).toBe(42);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM audit_logs'),
        expect.any(Array)
      );
    });
  });
});
