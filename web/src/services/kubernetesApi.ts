/**
 * Kubernetes Resource API Client
 * Provides API integration for resource monitoring, status tracking, and real-time updates
 */

export interface ResourceStatus {
  kind: string;
  name: string;
  namespace?: string;
  status: 'Ready' | 'Warning' | 'Error' | 'Unknown';
  lastUpdated: Date;
  metadata: Record<string, any>;
  relationships: ResourceReference[];
}

export interface ResourceReference {
  kind: string;
  name: string;
  namespace?: string;
  relationship: 'owns' | 'references' | 'depends-on';
}

export interface KubernetesEvent {
  name: string;
  namespace: string;
  reason: string;
  message: string;
  type: 'Normal' | 'Warning';
  count: number;
  firstTimestamp: Date;
  lastTimestamp: Date;
  source: {
    component: string;
    host: string;
  };
}

export interface ResourceDescribe {
  yaml: string;
  description: string;
}

export interface ResourceLogsOptions {
  container?: string;
  follow?: boolean;
  tailLines?: number;
}

/**
 * Kubernetes API Client for resource operations
 */
export class KubernetesApiClient {
  private baseUrl: string;
  private token: string;

  constructor(baseUrl: string = '/api/v1', token?: string) {
    this.baseUrl = baseUrl;
    this.token = token || this.getAuthToken();
  }

  private getAuthToken(): string {
    // Extract JWT token from localStorage or context
    const token = localStorage.getItem('authToken');
    if (!token) {
      throw new Error('Authentication token not found');
    }
    return token;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`API request failed: ${response.status} ${error}`);
    }

    return response.json();
  }

  /**
   * List all cluster resources with optional filtering
   */
  async listResources(params?: {
    namespace?: string;
    kind?: string;
    labelSelector?: string;
  }): Promise<{ resources: ResourceStatus[] }> {
    const searchParams = new URLSearchParams();
    if (params?.namespace) searchParams.set('namespace', params.namespace);
    if (params?.kind) searchParams.set('kind', params.kind);
    if (params?.labelSelector) searchParams.set('labelSelector', params.labelSelector);

    const query = searchParams.toString();
    const endpoint = `/resources${query ? `?${query}` : ''}`;

    return this.request<{ resources: ResourceStatus[] }>(endpoint);
  }

  /**
   * Get specific resource details
   */
  async getResource(
    kind: string,
    name: string,
    namespace?: string
  ): Promise<ResourceStatus> {
    const params = new URLSearchParams();
    if (namespace) params.set('namespace', namespace);

    const query = params.toString();
    const endpoint = `/resources/${kind}/${name}${query ? `?${query}` : ''}`;

    return this.request<ResourceStatus>(endpoint);
  }

  /**
   * Get detailed resource description (kubectl describe equivalent)
   */
  async describeResource(
    kind: string,
    name: string,
    namespace?: string
  ): Promise<ResourceDescribe> {
    const params = new URLSearchParams();
    if (namespace) params.set('namespace', namespace);

    const query = params.toString();
    const endpoint = `/resources/${kind}/${name}/describe${query ? `?${query}` : ''}`;

    return this.request<ResourceDescribe>(endpoint);
  }

  /**
   * Get resource logs (for pods and containers)
   */
  async getResourceLogs(
    kind: string,
    name: string,
    namespace?: string,
    options: ResourceLogsOptions = {}
  ): Promise<string> {
    const params = new URLSearchParams();
    if (namespace) params.set('namespace', namespace);
    if (options.container) params.set('container', options.container);
    if (options.follow !== undefined) params.set('follow', options.follow.toString());
    if (options.tailLines !== undefined) params.set('tailLines', options.tailLines.toString());

    const query = params.toString();
    const endpoint = `/resources/${kind}/${name}/logs${query ? `?${query}` : ''}`;

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Log request failed: ${response.status} ${error}`);
    }

    return response.text();
  }

  /**
   * Get resource-related Kubernetes events
   */
  async getResourceEvents(
    kind: string,
    name: string,
    namespace?: string,
    limit: number = 50
  ): Promise<{ events: KubernetesEvent[] }> {
    const params = new URLSearchParams();
    if (namespace) params.set('namespace', namespace);
    params.set('limit', limit.toString());

    const query = params.toString();
    const endpoint = `/resources/${kind}/${name}/events${query ? `?${query}` : ''}`;

    return this.request<{ events: KubernetesEvent[] }>(endpoint);
  }

  /**
   * Calculate resource health status from metadata
   */
  static calculateHealthStatus(resource: any): 'Ready' | 'Warning' | 'Error' | 'Unknown' {
    if (!resource.status) return 'Unknown';

    // Pod status logic
    if (resource.kind === 'Pod') {
      const phase = resource.status.phase;
      const conditions = resource.status.conditions || [];
      
      if (phase === 'Running') {
        const readyCondition = conditions.find((c: any) => c.type === 'Ready');
        return readyCondition?.status === 'True' ? 'Ready' : 'Warning';
      }
      
      if (phase === 'Succeeded') return 'Ready';
      if (phase === 'Failed') return 'Error';
      return 'Warning';
    }

    // Deployment status logic
    if (resource.kind === 'Deployment') {
      const conditions = resource.status.conditions || [];
      const availableCondition = conditions.find((c: any) => c.type === 'Available');
      
      if (availableCondition?.status === 'True') return 'Ready';
      if (availableCondition?.status === 'False') return 'Error';
      return 'Warning';
    }

    // Service status logic
    if (resource.kind === 'Service') {
      if (resource.spec?.type === 'LoadBalancer') {
        const ingress = resource.status?.loadBalancer?.ingress;
        return ingress && ingress.length > 0 ? 'Ready' : 'Warning';
      }
      return 'Ready'; // ClusterIP and NodePort services are typically ready
    }

    // Default logic based on status conditions
    const conditions = resource.status?.conditions || [];
    if (conditions.length === 0) return 'Unknown';

    const readyCondition = conditions.find((c: any) => 
      c.type === 'Ready' || c.type === 'Available'
    );

    if (readyCondition) {
      return readyCondition.status === 'True' ? 'Ready' : 'Error';
    }

    return 'Unknown';
  }
}

/**
 * Resource change detection utility
 */
export class ResourceChangeDetector {
  private previousResources: Map<string, ResourceStatus> = new Map();

  /**
   * Detect changes in resource list and return change notifications
   */
  detectChanges(currentResources: ResourceStatus[]): {
    added: ResourceStatus[];
    updated: ResourceStatus[];
    removed: string[];
  } {
    const changes = {
      added: [] as ResourceStatus[],
      updated: [] as ResourceStatus[],
      removed: [] as string[],
    };

    const currentResourceIds = new Set<string>();

    // Check for added and updated resources
    for (const resource of currentResources) {
      const resourceId = this.getResourceId(resource);
      currentResourceIds.add(resourceId);

      const previous = this.previousResources.get(resourceId);
      if (!previous) {
        changes.added.push(resource);
      } else if (this.hasResourceChanged(previous, resource)) {
        changes.updated.push(resource);
      }
    }

    // Check for removed resources
    for (const [resourceId] of this.previousResources) {
      if (!currentResourceIds.has(resourceId)) {
        changes.removed.push(resourceId);
      }
    }

    // Update previous resources
    this.previousResources.clear();
    for (const resource of currentResources) {
      this.previousResources.set(this.getResourceId(resource), resource);
    }

    return changes;
  }

  private getResourceId(resource: ResourceStatus): string {
    return `${resource.kind}/${resource.namespace || 'default'}/${resource.name}`;
  }

  private hasResourceChanged(previous: ResourceStatus, current: ResourceStatus): boolean {
    return (
      previous.status !== current.status ||
      previous.lastUpdated.getTime() !== current.lastUpdated.getTime() ||
      JSON.stringify(previous.metadata) !== JSON.stringify(current.metadata)
    );
  }
}

// Factory functions for creating instances
export function createKubernetesApiClient(baseUrl?: string, token?: string): KubernetesApiClient {
  return new KubernetesApiClient(baseUrl, token);
}

export function createResourceChangeDetector(): ResourceChangeDetector {
  return new ResourceChangeDetector();
}

// Singleton instances for application use
let _kubernetesApiInstance: KubernetesApiClient | null = null;
let _resourceChangeDetectorInstance: ResourceChangeDetector | null = null;

export const kubernetesApi = {
  get instance() {
    if (!_kubernetesApiInstance) {
      _kubernetesApiInstance = createKubernetesApiClient();
    }
    return _kubernetesApiInstance;
  },
  listResources: (params?: { namespace?: string; kind?: string; labelSelector?: string }) => 
    kubernetesApi.instance.listResources(params),
  getResource: (kind: string, name: string, namespace?: string) => 
    kubernetesApi.instance.getResource(kind, name, namespace),
  describeResource: (kind: string, name: string, namespace?: string) => 
    kubernetesApi.instance.describeResource(kind, name, namespace),
  getResourceLogs: (kind: string, name: string, namespace?: string, options?: ResourceLogsOptions) => 
    kubernetesApi.instance.getResourceLogs(kind, name, namespace, options),
  getResourceEvents: (kind: string, name: string, namespace?: string, limit?: number) => 
    kubernetesApi.instance.getResourceEvents(kind, name, namespace, limit),
};

export const resourceChangeDetector = {
  get instance() {
    if (!_resourceChangeDetectorInstance) {
      _resourceChangeDetectorInstance = createResourceChangeDetector();
    }
    return _resourceChangeDetectorInstance;
  },
  detectChanges: (resources: ResourceStatus[]) => 
    resourceChangeDetector.instance.detectChanges(resources),
};