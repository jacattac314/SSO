/**
 * Unit tests for tenant service (role mapping and attribute resolution).
 */
jest.mock('../../src/config/database');
jest.mock('../../src/services/audit.service');
jest.mock('../../src/services/certificate.service');

import { tenantService } from '../../src/services/tenant.service';

describe('TenantService', () => {
  describe('mapGroupsToRoles', () => {
    const mappings = [
      { idpGroupValue: 'LegoraAdmins', legoraRole: 'admin' },
      { idpGroupValue: 'LegoraUsers', legoraRole: 'user' },
      { idpGroupValue: 'LegoraViewers', legoraRole: 'viewer' },
    ];

    it('should map known groups to roles', () => {
      const roles = tenantService.mapGroupsToRoles(['LegoraAdmins'], mappings);
      expect(roles).toContain('admin');
    });

    it('should map multiple groups to multiple roles', () => {
      const roles = tenantService.mapGroupsToRoles(['LegoraAdmins', 'LegoraUsers'], mappings);
      expect(roles).toContain('admin');
      expect(roles).toContain('user');
    });

    it('should default to user role if no mapping found', () => {
      const roles = tenantService.mapGroupsToRoles(['UnknownGroup'], mappings);
      expect(roles).toEqual(['user']);
    });

    it('should return user role for empty groups', () => {
      const roles = tenantService.mapGroupsToRoles([], mappings);
      expect(roles).toEqual(['user']);
    });

    it('should de-duplicate roles', () => {
      const duplicateMappings = [
        { idpGroupValue: 'GroupA', legoraRole: 'admin' },
        { idpGroupValue: 'GroupB', legoraRole: 'admin' },
      ];
      const roles = tenantService.mapGroupsToRoles(['GroupA', 'GroupB'], duplicateMappings);
      expect(roles.filter((r) => r === 'admin')).toHaveLength(1);
    });
  });
});
