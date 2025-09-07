/**
 * Tests for Kubernetes API Client
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KubernetesApiClient, ResourceChangeDetector, type ResourceStatus } from '../kubernetesApi';

// Mock fetch
global.fetch = vi.fn();
const mockFetch = vi.mocked(fetch);

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(() => 'test-token'),
  setItem: vi.fn(),
};
Object.defineProperty(window, 'localStorage', {
  value: mockLocalStorage,
  writable: true,
});

describe('KubernetesApiClient', () => {
  let client: KubernetesApiClient;

  beforeEach(() => {
    client = new KubernetesApiClient('/api/v1', 'test-token');
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('listResources', () => {
    it('should fetch resources list successfully', async () => {
      const mockResources = {
        resources: [
          {
            kind: 'Pod',
            name: 'test-pod',
            namespace: 'default',
            status: 'Ready' as const,
            lastUpdated: new Date(),
            metadata: {},
            relationships: [],
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResources,
      } as Response);

      const result = await client.listResources();

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/resources',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test-token',
          }),
        })
      );

      expect(result).toEqual(mockResources);
    });

    it('should include query parameters when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ resources: [] }),
      } as Response);

      await client.listResources({
        namespace: 'default',
        kind: 'Pod',
        labelSelector: 'app=test',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/resources?namespace=default&kind=Pod&labelSelector=app%3Dtest',
        expect.any(Object)
      );
    });

    it('should throw error on failed request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: async () => 'Not found',
      } as Response);

      await expect(client.listResources()).rejects.toThrow(
        'API request failed: 404 Not found'
      );
    });
  });

  describe('getResource', () => {
    it('should fetch specific resource successfully', async () => {
      const mockResource: ResourceStatus = {
        kind: 'Pod',
        name: 'test-pod',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date(),
        metadata: {},
        relationships: [],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResource,
      } as Response);

      const result = await client.getResource('Pod', 'test-pod', 'default');

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/resources/Pod/test-pod?namespace=default',
        expect.any(Object)
      );

      expect(result).toEqual(mockResource);
    });

    it('should handle resource without namespace', async () => {
      const mockResource: ResourceStatus = {
        kind: 'Node',
        name: 'test-node',
        status: 'Ready',
        lastUpdated: new Date(),
        metadata: {},
        relationships: [],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResource,
      } as Response);

      await client.getResource('Node', 'test-node');

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/resources/Node/test-node',
        expect.any(Object)
      );
    });
  });

  describe('describeResource', () => {
    it('should fetch resource description successfully', async () => {
      const mockDescription = {
        yaml: 'apiVersion: v1\nkind: Pod\n...',
        description: 'Pod description',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockDescription,
      } as Response);

      const result = await client.describeResource('Pod', 'test-pod', 'default');

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/resources/Pod/test-pod/describe?namespace=default',
        expect.any(Object)
      );

      expect(result).toEqual(mockDescription);
    });
  });

  describe('getResourceLogs', () => {
    it('should fetch resource logs successfully', async () => {
      const mockLogs = 'Log line 1\nLog line 2\n';

      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => mockLogs,
      } as Response);

      const result = await client.getResourceLogs('Pod', 'test-pod', 'default', {
        container: 'main',
        tailLines: 100,
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/resources/Pod/test-pod/logs?namespace=default&container=main&tailLines=100',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
          }),
        })
      );

      expect(result).toBe(mockLogs);
    });

    it('should throw error on failed log request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        text: async () => 'Forbidden',
      } as Response);

      await expect(
        client.getResourceLogs('Pod', 'test-pod', 'default')
      ).rejects.toThrow('Log request failed: 403 Forbidden');
    });
  });

  describe('getResourceEvents', () => {
    it('should fetch resource events successfully', async () => {
      const mockEvents = {
        events: [
          {
            name: 'test-event',
            namespace: 'default',
            reason: 'Created',
            message: 'Pod created',
            type: 'Normal' as const,
            count: 1,
            firstTimestamp: new Date(),
            lastTimestamp: new Date(),
            source: { component: 'kubelet', host: 'node-1' },
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockEvents,
      } as Response);

      const result = await client.getResourceEvents('Pod', 'test-pod', 'default');

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/resources/Pod/test-pod/events?namespace=default&limit=50',
        expect.any(Object)
      );

      expect(result).toEqual(mockEvents);
    });
  });

  describe('calculateHealthStatus', () => {
    it('should calculate Pod health status correctly', () => {
      // Running Pod with Ready condition
      const runningPod = {
        kind: 'Pod',
        status: {
          phase: 'Running',
          conditions: [{ type: 'Ready', status: 'True' }],
        },
      };
      expect(KubernetesApiClient.calculateHealthStatus(runningPod)).toBe('Ready');

      // Running Pod without Ready condition
      const unreadyPod = {
        kind: 'Pod',
        status: {
          phase: 'Running',
          conditions: [{ type: 'Ready', status: 'False' }],
        },
      };
      expect(KubernetesApiClient.calculateHealthStatus(unreadyPod)).toBe('Warning');

      // Failed Pod
      const failedPod = {
        kind: 'Pod',
        status: { phase: 'Failed' },
      };
      expect(KubernetesApiClient.calculateHealthStatus(failedPod)).toBe('Error');

      // Succeeded Pod
      const succeededPod = {
        kind: 'Pod',
        status: { phase: 'Succeeded' },
      };
      expect(KubernetesApiClient.calculateHealthStatus(succeededPod)).toBe('Ready');
    });

    it('should calculate Deployment health status correctly', () => {
      // Available Deployment
      const availableDeployment = {
        kind: 'Deployment',
        status: {
          conditions: [{ type: 'Available', status: 'True' }],
        },
      };
      expect(KubernetesApiClient.calculateHealthStatus(availableDeployment)).toBe('Ready');

      // Unavailable Deployment
      const unavailableDeployment = {
        kind: 'Deployment',
        status: {
          conditions: [{ type: 'Available', status: 'False' }],
        },
      };
      expect(KubernetesApiClient.calculateHealthStatus(unavailableDeployment)).toBe('Error');
    });

    it('should handle unknown resource status', () => {
      const unknownResource = {
        kind: 'Unknown',
      };
      expect(KubernetesApiClient.calculateHealthStatus(unknownResource)).toBe('Unknown');
    });
  });
});

describe('ResourceChangeDetector', () => {
  let detector: ResourceChangeDetector;

  beforeEach(() => {
    detector = new ResourceChangeDetector();
  });

  it('should detect added resources', () => {
    const resources: ResourceStatus[] = [
      {
        kind: 'Pod',
        name: 'new-pod',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date(),
        metadata: {},
        relationships: [],
      },
    ];

    const changes = detector.detectChanges(resources);

    expect(changes.added).toHaveLength(1);
    expect(changes.added[0].name).toBe('new-pod');
    expect(changes.updated).toHaveLength(0);
    expect(changes.removed).toHaveLength(0);
  });

  it('should detect updated resources', () => {
    const initialResources: ResourceStatus[] = [
      {
        kind: 'Pod',
        name: 'test-pod',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date('2023-01-01'),
        metadata: { version: '1' },
        relationships: [],
      },
    ];

    // First detection
    detector.detectChanges(initialResources);

    // Updated resource
    const updatedResources: ResourceStatus[] = [
      {
        ...initialResources[0],
        status: 'Warning',
        lastUpdated: new Date('2023-01-02'),
      },
    ];

    const changes = detector.detectChanges(updatedResources);

    expect(changes.added).toHaveLength(0);
    expect(changes.updated).toHaveLength(1);
    expect(changes.updated[0].name).toBe('test-pod');
    expect(changes.updated[0].status).toBe('Warning');
    expect(changes.removed).toHaveLength(0);
  });

  it('should detect removed resources', () => {
    const initialResources: ResourceStatus[] = [
      {
        kind: 'Pod',
        name: 'test-pod',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date(),
        metadata: {},
        relationships: [],
      },
    ];

    // First detection
    detector.detectChanges(initialResources);

    // Empty resource list (pod removed)
    const changes = detector.detectChanges([]);

    expect(changes.added).toHaveLength(0);
    expect(changes.updated).toHaveLength(0);
    expect(changes.removed).toHaveLength(1);
    expect(changes.removed[0]).toBe('Pod/default/test-pod');
  });

  it('should handle complex changes', () => {
    const initialResources: ResourceStatus[] = [
      {
        kind: 'Pod',
        name: 'pod-1',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date('2023-01-01'),
        metadata: {},
        relationships: [],
      },
      {
        kind: 'Pod',
        name: 'pod-2',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date('2023-01-01'),
        metadata: {},
        relationships: [],
      },
    ];

    // First detection
    detector.detectChanges(initialResources);

    // Complex changes: pod-1 updated, pod-2 removed, pod-3 added
    const updatedResources: ResourceStatus[] = [
      {
        ...initialResources[0],
        status: 'Warning',
        lastUpdated: new Date('2023-01-02'),
      },
      {
        kind: 'Pod',
        name: 'pod-3',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date('2023-01-02'),
        metadata: {},
        relationships: [],
      },
    ];

    const changes = detector.detectChanges(updatedResources);

    expect(changes.added).toHaveLength(1);
    expect(changes.added[0].name).toBe('pod-3');
    expect(changes.updated).toHaveLength(1);
    expect(changes.updated[0].name).toBe('pod-1');
    expect(changes.removed).toHaveLength(1);
    expect(changes.removed[0]).toBe('Pod/default/pod-2');
  });
});