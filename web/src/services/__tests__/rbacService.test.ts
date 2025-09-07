/**
 * Tests for RBAC Service
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RBACService, rbacService } from '../rbacService';

// Mock fetch
global.fetch = vi.fn();

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(window, 'localStorage', { value: mockLocalStorage });

describe('RBAC Service', () => {
  let service: RBACService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new RBACService('/api/k8s');
    mockLocalStorage.getItem.mockReturnValue('mock-token');
  });

  describe('Permission Checking', () => {
    it('should check single permission', async () => {
      const mockResponse = {
        status: {
          allowed: true,
          reason: 'RBAC allowed',
        },
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const result = await service.canI({
        resource: 'pods',
        verb: 'get',
        namespace: 'default',
      });

      expect(result.allowed).toBe(true);
      expect(result.reason).toBe('RBAC allowed');
    });

    it('should handle permission denied', async () => {
      const mockResponse = {
        status: {
          allowed: false,
          reason: 'Forbidden',
        },
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const result = await service.canI({
        resource: 'secrets',
        verb: 'list',
        namespace: 'kube-system',
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Forbidden');
    });

    it('should handle API errors', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));

      const result = await service.canI({
        resource: 'pods',
        verb: 'get',
      });

      expect(result.allowed).toBe(false);
      expect(result.evaluationError).toBe('Network error');
    });

    it('should cache permission results', async () => {
      const mockResponse = {
        status: {
          allowed: true,
        },
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      // First call
      const result1 = await service.canI({
        resource: 'pods',
        verb: 'get',
        namespace: 'default',
      });

      // Second call (should use cache)
      const result2 = await service.canI({
        resource: 'pods',
        verb: 'get',
        namespace: 'default',
      });

      expect(result1.allowed).toBe(true);
      expect(result2.allowed).toBe(true);
      expect(fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('Batch Permission Checking', () => {
    it('should check multiple permissions', async () => {
      const mockResponse = {
        status: {
          allowed: true,
        },
      };

      vi.mocked(fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const checks = [
        { resource: 'pods', verb: 'get' },
        { resource: 'services', verb: 'list' },
        { resource: 'deployments', verb: 'create' },
      ];

      const results = await service.canIMultiple(checks);

      expect(results.size).toBe(3);
      expect(Array.from(results.values()).every(r => r.allowed)).toBe(true);
    });
  });

  describe('Resource-Specific Helpers', () => {
    beforeEach(() => {
      const mockResponse = {
        status: { allowed: true },
      };

      vi.mocked(fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);
    });

    it('should check pod permissions', async () => {
      expect(await service.canGetPods('default')).toBe(true);
      expect(await service.canListPods('default')).toBe(true);
    });

    it('should check resource watch permissions', async () => {
      expect(await service.canWatchResources('pods', 'default')).toBe(true);
    });

    it('should check resource modification permissions', async () => {
      expect(await service.canDeleteResource('pods', 'test-pod', 'default')).toBe(true);
      expect(await service.canCreateResource('pods', 'default')).toBe(true);
      expect(await service.canUpdateResource('pods', 'test-pod', 'default')).toBe(true);
    });
  });

  describe('Dashboard-Specific Permissions', () => {
    it('should check dashboard view permissions', async () => {
      const mockResponse = {
        status: { allowed: true },
      };

      vi.mocked(fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const canView = await service.canViewDashboard();
      expect(canView).toBe(true);
    });

    it('should check resource details permissions', async () => {
      const mockResponse = {
        status: { allowed: true },
      };

      vi.mocked(fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const canView = await service.canViewResourceDetails('pods', 'default');
      expect(canView).toBe(true);
    });

    it('should check logs permissions', async () => {
      const mockResponse = {
        status: { allowed: true },
      };

      vi.mocked(fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const canViewLogs = await service.canViewLogs('default');
      expect(canViewLogs).toBe(true);
    });

    it('should check events permissions', async () => {
      const mockResponse = {
        status: { allowed: true },
      };

      vi.mocked(fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const canViewEvents = await service.canViewEvents('default');
      expect(canViewEvents).toBe(true);
    });
  });

  describe('Namespace Access', () => {
    it('should get accessible namespaces for user', async () => {
      // Mock user permissions
      service['userPermissions'].set('test-user', {
        user: 'test-user',
        roles: [],
        permissions: [
          { resource: 'pods', verb: 'get', namespace: 'default' },
          { resource: 'services', verb: 'list', namespace: 'kube-system' },
          { resource: 'deployments', verb: 'create', namespace: '*' },
        ],
        canImpersonate: [],
        effectivePermissions: new Map(),
      });

      const namespaces = await service.getAccessibleNamespaces('test-user');
      
      expect(namespaces).toContain('*');
    });

    it('should get accessible resources for user', async () => {
      service['userPermissions'].set('test-user', {
        user: 'test-user',
        roles: [],
        permissions: [
          { resource: 'pods', verb: 'list' },
          { resource: 'services', verb: 'get' },
          { resource: 'secrets', verb: 'create' },
        ],
        canImpersonate: [],
        effectivePermissions: new Map(),
      });

      const resources = await service.getAccessibleResources('test-user');
      
      expect(resources).toContain('pods');
      expect(resources).toContain('services');
      expect(resources).not.toContain('secrets'); // Only create permission
    });
  });

  describe('UI Permissions', () => {
    it('should get permissions for UI', async () => {
      const mockResponse = {
        status: { allowed: true },
      };

      vi.mocked(fetch).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const permissions = await service.getPermissionsForUI('test-user');

      expect(permissions).toHaveProperty('canView');
      expect(permissions).toHaveProperty('canEdit');
      expect(permissions).toHaveProperty('canDelete');
      expect(permissions).toHaveProperty('canCreate');
      expect(permissions).toHaveProperty('accessibleNamespaces');
      expect(permissions).toHaveProperty('accessibleResources');
    });

    it('should handle permission errors gracefully', async () => {
      vi.mocked(fetch).mockRejectedValue(new Error('API error'));

      const permissions = await service.getPermissionsForUI('test-user');

      expect(permissions.canView).toEqual({});
      expect(permissions.canEdit).toEqual({});
      expect(permissions.canDelete).toEqual({});
      expect(permissions.canCreate).toEqual({});
      expect(permissions.accessibleNamespaces).toEqual([]);
      expect(permissions.accessibleResources).toEqual([]);
    });
  });

  describe('Cache Management', () => {
    it('should clear all caches', () => {
      service['permissionCache'].set('test-key', { allowed: true });
      service['userPermissions'].set('test-user', {
        user: 'test-user',
        roles: [],
        permissions: [],
        canImpersonate: [],
        effectivePermissions: new Map(),
      });

      service.clearCache();

      expect(service['permissionCache'].size).toBe(0);
      expect(service['userPermissions'].size).toBe(0);
    });

    it('should clear user-specific cache', () => {
      service['permissionCache'].set('user:test-user:pods:get:default:*', { allowed: true });
      service['permissionCache'].set('user:other-user:pods:get:default:*', { allowed: true });
      service['userPermissions'].set('test-user', {
        user: 'test-user',
        roles: [],
        permissions: [],
        canImpersonate: [],
        effectivePermissions: new Map(),
      });

      service.clearUserCache('test-user');

      expect(service['userPermissions'].has('test-user')).toBe(false);
      expect(service['permissionCache'].has('user:test-user:pods:get:default:*')).toBe(false);
      expect(service['permissionCache'].has('user:other-user:pods:get:default:*')).toBe(true);
    });
  });

  describe('Default Instance', () => {
    it('should provide default rbacService instance', () => {
      expect(rbacService).toBeInstanceOf(RBACService);
    });
  });

  describe('Private Methods', () => {
    it('should generate cache keys correctly', () => {
      const key1 = service['generateCacheKey']({
        resource: 'pods',
        verb: 'get',
        namespace: 'default',
      }, 'test-user');

      const key2 = service['generateCacheKey']({
        resource: 'pods',
        verb: 'get',
        namespace: 'default',
      });

      expect(key1).toBe('user:test-user:pods:get:default:*');
      expect(key2).toBe('self:pods:get:default:*');
    });

    it('should get token from localStorage', () => {
      const token = service['getToken']();
      expect(token).toBe('mock-token');
      expect(mockLocalStorage.getItem).toHaveBeenCalledWith('auth-token');
    });
  });

  describe('Permission Building', () => {
    it('should build effective permissions map', () => {
      const permissions = [
        { resource: 'pods', verb: 'get', namespace: 'default' },
        { resource: 'pods', verb: 'list', namespace: 'default' },
        { resource: 'services', verb: 'get' },
      ];

      const map = service['buildEffectivePermissionsMap'](permissions);

      expect(map.get('pods:default')).toEqual(new Set(['get', 'list']));
      expect(map.get('services')).toEqual(new Set(['get']));
    });

    it('should compute effective permissions from roles', () => {
      const roles = [
        {
          name: 'pod-reader',
          rules: [
            { resource: 'pods', verb: 'get', namespace: 'default' },
            { resource: 'pods', verb: 'list', namespace: 'default' },
          ],
          metadata: {
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        },
        {
          name: 'service-admin',
          rules: [
            { resource: 'services', verb: 'get' },
            { resource: 'services', verb: 'create' },
          ],
          metadata: {
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        },
      ];

      const permissions = service['computeEffectivePermissions'](roles);

      expect(permissions).toHaveLength(4);
      expect(permissions.some(p => p.resource === 'pods' && p.verb === 'get')).toBe(true);
      expect(permissions.some(p => p.resource === 'services' && p.verb === 'create')).toBe(true);
    });
  });
});