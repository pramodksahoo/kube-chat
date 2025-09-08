/**
 * RBAC Service - Role-Based Access Control implementation
 * Handles permissions, role checking, and access control for Kubernetes resources
 */

export interface Permission {
  resource: string; // e.g., 'pods', 'services', 'deployments'
  verb: string; // e.g., 'get', 'list', 'create', 'update', 'delete', 'watch'
  namespace?: string; // specific namespace or '*' for all
  resourceName?: string; // specific resource name
}

export interface Role {
  name: string;
  namespace?: string; // undefined for ClusterRole
  rules: Permission[];
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
  };
}

export interface RoleBinding {
  name: string;
  namespace?: string;
  roleRef: {
    kind: 'Role' | 'ClusterRole';
    name: string;
  };
  subjects: Array<{
    kind: 'User' | 'Group' | 'ServiceAccount';
    name: string;
    namespace?: string;
  }>;
}

export interface UserPermissions {
  user: string;
  roles: Role[];
  permissions: Permission[];
  canImpersonate: string[];
  effectivePermissions: Map<string, Set<string>>; // resource -> verbs
}

export interface PermissionCheck {
  resource: string;
  verb: string;
  namespace?: string;
  resourceName?: string;
}

export interface AccessReviewResponse {
  allowed: boolean;
  reason?: string;
  evaluationError?: string;
}

// RBAC Service implementation
export class RBACService {
  private userPermissions: Map<string, UserPermissions> = new Map();
  private roleCache: Map<string, Role> = new Map();
  private roleBindingCache: Map<string, RoleBinding> = new Map();
  private permissionCache: Map<string, AccessReviewResponse> = new Map();
  // private _cacheExpiry = 5 * 60 * 1000; // 5 minutes - Available for future cache implementation

  private baseUrl: string;
  
  constructor(baseUrl: string = '/api/v1') {
    this.baseUrl = baseUrl;
  }

  // Permission checking
  async canI(check: PermissionCheck, user?: string): Promise<AccessReviewResponse> {
    try {
      const cacheKey = this.generateCacheKey(check, user);
      const cached = this.permissionCache.get(cacheKey);
      
      if (cached && this.isCacheValid(cacheKey)) {
        return cached;
      }

      // Perform access review via API
      const response = await this.performAccessReview(check, user);
      
      // Cache the result
      this.permissionCache.set(cacheKey, response);
      
      return response;
    } catch (error) {
      return {
        allowed: false,
        reason: 'Access check failed',
        evaluationError: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // Batch permission checking
  async canIMultiple(checks: PermissionCheck[], user?: string): Promise<Map<string, AccessReviewResponse>> {
    const results = new Map<string, AccessReviewResponse>();
    
    // Process checks in parallel
    const promises = checks.map(async (check) => {
      const key = `${check.resource}:${check.verb}:${check.namespace || '*'}:${check.resourceName || '*'}`;
      const result = await this.canI(check, user);
      results.set(key, result);
    });

    await Promise.all(promises);
    return results;
  }

  // Resource-specific permission helpers
  async canGetPods(namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource: 'pods',
      verb: 'get',
      namespace,
    }, user);
    return result.allowed;
  }

  async canListPods(namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource: 'pods',
      verb: 'list',
      namespace,
    }, user);
    return result.allowed;
  }

  async canWatchResources(resource: string, namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource,
      verb: 'watch',
      namespace,
    }, user);
    return result.allowed;
  }

  async canDeleteResource(resource: string, name: string, namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource,
      verb: 'delete',
      namespace,
      resourceName: name,
    }, user);
    return result.allowed;
  }

  async canCreateResource(resource: string, namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource,
      verb: 'create',
      namespace,
    }, user);
    return result.allowed;
  }

  async canUpdateResource(resource: string, name: string, namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource,
      verb: 'update',
      namespace,
      resourceName: name,
    }, user);
    return result.allowed;
  }

  // Dashboard-specific permissions
  async canViewDashboard(user?: string): Promise<boolean> {
    // Check if user can list any resources
    const checks: PermissionCheck[] = [
      { resource: 'pods', verb: 'list' },
      { resource: 'services', verb: 'list' },
      { resource: 'deployments', verb: 'list' },
      { resource: 'configmaps', verb: 'list' },
    ];

    const results = await this.canIMultiple(checks, user);
    return Array.from(results.values()).some(result => result.allowed);
  }

  async canViewResourceDetails(resource: string, namespace?: string, user?: string): Promise<boolean> {
    const getResult = await this.canI({
      resource,
      verb: 'get',
      namespace,
    }, user);

    const describeResult = await this.canI({
      resource,
      verb: 'describe',
      namespace,
    }, user);

    return getResult.allowed || describeResult.allowed;
  }

  async canViewLogs(namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource: 'pods/log',
      verb: 'get',
      namespace,
    }, user);
    return result.allowed;
  }

  async canViewEvents(namespace?: string, user?: string): Promise<boolean> {
    const result = await this.canI({
      resource: 'events',
      verb: 'list',
      namespace,
    }, user);
    return result.allowed;
  }

  // User permissions management
  async getUserPermissions(user: string): Promise<UserPermissions> {
    try {
      const cached = this.userPermissions.get(user);
      if (cached && this.isUserPermissionsCacheValid(user)) {
        return cached;
      }

      // Fetch user's roles and role bindings
      const roleBindings = this.fetchUserRoleBindings(user);
      const roles = this.fetchRolesFromBindings(roleBindings);
      
      // Compute effective permissions
      const permissions = this.computeEffectivePermissions(roles);
      const effectivePermissions = this.buildEffectivePermissionsMap(permissions);

      const userPermissions: UserPermissions = {
        user,
        roles,
        permissions,
        canImpersonate: await this.fetchImpersonationPermissions(user),
        effectivePermissions,
      };

      this.userPermissions.set(user, userPermissions);
      return userPermissions;
    } catch (error) {
      throw new Error(`Failed to get user permissions: ${String(error)}`);
    }
  }

  // Namespace filtering based on permissions
  async getAccessibleNamespaces(user?: string): Promise<string[]> {
    try {
      const userPerms = user ? await this.getUserPermissions(user) : null;
      
      if (!userPerms) {
        // If no user context, assume all namespaces (for development)
        return ['*'];
      }

      const accessibleNamespaces = new Set<string>();

      // Check permissions for each resource type
      for (const permission of userPerms.permissions) {
        if (permission.namespace) {
          if (permission.namespace === '*') {
            accessibleNamespaces.add('*');
            break;
          } else {
            accessibleNamespaces.add(permission.namespace);
          }
        }
      }

      return Array.from(accessibleNamespaces).sort();
    } catch {
      // Log error for debugging - in production use proper logging service
      return [];
    }
  }

  // Resource filtering based on permissions
  async getAccessibleResources(user?: string): Promise<string[]> {
    try {
      const userPerms = user ? await this.getUserPermissions(user) : null;
      
      if (!userPerms) {
        // Default resource list for development
        return ['pods', 'services', 'deployments', 'configmaps', 'secrets'];
      }

      const accessibleResources = new Set<string>();

      for (const permission of userPerms.permissions) {
        if (permission.verb === 'list' || permission.verb === 'get') {
          accessibleResources.add(permission.resource);
        }
      }

      return Array.from(accessibleResources).sort();
    } catch {
      // Log error for debugging - in production use proper logging service
      return [];
    }
  }

  // Permission-aware UI helpers
  async getPermissionsForUI(user?: string): Promise<{
    canView: Record<string, boolean>;
    canEdit: Record<string, boolean>;
    canDelete: Record<string, boolean>;
    canCreate: Record<string, boolean>;
    accessibleNamespaces: string[];
    accessibleResources: string[];
  }> {
    try {
      const commonResources = ['pods', 'services', 'deployments', 'configmaps', 'secrets', 'ingresses'];
      
      const canView: Record<string, boolean> = {};
      const canEdit: Record<string, boolean> = {};
      const canDelete: Record<string, boolean> = {};
      const canCreate: Record<string, boolean> = {};

      // Check permissions for each resource
      for (const resource of commonResources) {
        canView[resource] = await this.canI({ resource, verb: 'list' }, user).then(r => r.allowed);
        canEdit[resource] = await this.canI({ resource, verb: 'update' }, user).then(r => r.allowed);
        canDelete[resource] = await this.canI({ resource, verb: 'delete' }, user).then(r => r.allowed);
        canCreate[resource] = await this.canI({ resource, verb: 'create' }, user).then(r => r.allowed);
      }

      const accessibleNamespaces = await this.getAccessibleNamespaces(user);
      const accessibleResources = await this.getAccessibleResources(user);

      return {
        canView,
        canEdit,
        canDelete,
        canCreate,
        accessibleNamespaces,
        accessibleResources,
      };
    } catch {
      // Log error for debugging - in production use proper logging service
      
      // Return restrictive permissions on error
      return {
        canView: {},
        canEdit: {},
        canDelete: {},
        canCreate: {},
        accessibleNamespaces: [],
        accessibleResources: [],
      };
    }
  }

  // Cache management
  clearCache(): void {
    this.permissionCache.clear();
    this.userPermissions.clear();
    this.roleCache.clear();
    this.roleBindingCache.clear();
  }

  clearUserCache(user: string): void {
    this.userPermissions.delete(user);
    
    // Clear permission cache for this user
    const keysToDelete = Array.from(this.permissionCache.keys())
      .filter(key => key.includes(`user:${user}`));
    
    keysToDelete.forEach(key => this.permissionCache.delete(key));
  }

  // Private methods
  private async performAccessReview(check: PermissionCheck, user?: string): Promise<AccessReviewResponse> {
    const requestBody = {
      apiVersion: 'authorization.k8s.io/v1',
      kind: 'SelfSubjectAccessReview',
      spec: {
        resourceAttributes: {
          namespace: check.namespace,
          verb: check.verb,
          resource: check.resource,
          name: check.resourceName,
        },
      },
    };

    // If user is specified, use SubjectAccessReview instead
    if (user) {
      requestBody.kind = 'SubjectAccessReview';
      (requestBody.spec as any).user = user;
    }

    const response = await fetch(`${this.baseUrl}/apis/authorization.k8s.io/v1/subjectaccessreviews`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.getToken()}`,
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error(`Access review failed: ${response.statusText}`);
    }

    const result = await response.json();
    
    return {
      allowed: result.status?.allowed || false,
      reason: result.status?.reason,
      evaluationError: result.status?.evaluationError,
    };
  }

  private fetchUserRoleBindings(_user: string): RoleBinding[] {
    // This would fetch all RoleBindings and ClusterRoleBindings for the user
    // Implementation would depend on your Kubernetes API setup
    return [];
  }

  private fetchRolesFromBindings(_roleBindings: RoleBinding[]): Role[] {
    // Fetch Role and ClusterRole objects referenced in bindings
    return [];
  }

  private computeEffectivePermissions(roles: Role[]): Permission[] {
    const permissions: Permission[] = [];
    
    for (const role of roles) {
      permissions.push(...role.rules);
    }

    return permissions;
  }

  private buildEffectivePermissionsMap(permissions: Permission[]): Map<string, Set<string>> {
    const map = new Map<string, Set<string>>();

    for (const permission of permissions) {
      const key = permission.namespace ? `${permission.resource}:${permission.namespace}` : permission.resource;
      
      if (!map.has(key)) {
        map.set(key, new Set());
      }
      
      map.get(key)!.add(permission.verb);
    }

    return map;
  }

  private async fetchImpersonationPermissions(user: string): Promise<string[]> {
    // Check if user can impersonate others
    const result = await this.canI({
      resource: 'users',
      verb: 'impersonate',
    }, user);

    return result.allowed ? ['*'] : [];
  }

  private generateCacheKey(check: PermissionCheck, user?: string): string {
    const userPart = user ? `user:${user}` : 'self';
    return `${userPart}:${check.resource}:${check.verb}:${check.namespace || '*'}:${check.resourceName || '*'}`;
  }

  private isCacheValid(_key: string): boolean {
    // Simple cache validity check - in production, you'd track timestamps
    return true;
  }

  private isUserPermissionsCacheValid(_user: string): boolean {
    // Check if user permissions cache is still valid
    return true;
  }

  private getToken(): string {
    // Get authentication token from storage or context
    return localStorage.getItem('auth-token') || '';
  }
}

import API_CONFIG from '@/config/api';

// Default instance
export const rbacService = new RBACService(API_CONFIG.KUBERNETES);

// Permission hook context
import { createContext, useContext } from 'react';

export interface PermissionContextValue {
  permissions: {
    canView: Record<string, boolean>;
    canEdit: Record<string, boolean>;
    canDelete: Record<string, boolean>;
    canCreate: Record<string, boolean>;
    accessibleNamespaces: string[];
    accessibleResources: string[];
  };
  loading: boolean;
  error: string | null;
  user: string | null;
  refreshPermissions: () => Promise<void>;
}

export const PermissionContext = createContext<PermissionContextValue | null>(null);

export function usePermissions() {
  const context = useContext(PermissionContext);
  if (!context) {
    throw new Error('usePermissions must be used within a PermissionProvider');
  }
  return context;
}