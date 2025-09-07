/**
 * Tests for ResourceDescribe component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ResourceDescribe } from '../ResourceDescribe';
import { kubernetesApi } from '../../../services/kubernetesApi';
import type { ResourceStatus } from '../../../services/kubernetesApi';

// Mock the kubernetesApi
vi.mock('../../../services/kubernetesApi', () => ({
  kubernetesApi: {
    describeResource: vi.fn(),
  },
}));

// Mock clipboard API
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn(),
  },
});

describe('ResourceDescribe', () => {
  const mockResource: ResourceStatus = {
    kind: 'Pod',
    name: 'test-pod',
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date('2023-01-01T10:00:00Z'),
    metadata: {},
    relationships: [
      {
        kind: 'Service',
        name: 'test-service',
        namespace: 'default',
        relationship: 'owns',
      },
    ],
  };

  const mockDescribeData = {
    yaml: `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  labels:
    app: test
spec:
  containers:
  - name: main
    image: nginx:1.20
    ports:
    - containerPort: 80
status:
  phase: Running
  conditions:
  - type: Ready
    status: "true"
    lastTransitionTime: "2023-01-01T10:00:00Z"`,
    description: `Name:             test-pod
Namespace:        default
Priority:         0
Node:             test-node/10.0.0.1
Start Time:       Mon, 01 Jan 2023 10:00:00 +0000
Labels:           app=test
Status:           Running
IP:               10.244.1.2
Containers:
  main:
    Image:          nginx:1.20
    Port:           80/TCP
    State:          Running
      Started:      Mon, 01 Jan 2023 10:00:00 +0000
    Ready:          True`,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Loading State', () => {
    it('should show loading state initially', () => {
      vi.mocked(kubernetesApi.describeResource).mockImplementation(() => new Promise(() => {}));

      render(<ResourceDescribe resource={mockResource} />);

      expect(screen.getByTestId('resource-describe-loading')).toBeInTheDocument();
      expect(screen.getByText('Loading resource description...')).toBeInTheDocument();
    });
  });

  describe('Success State', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.describeResource).mockResolvedValue(mockDescribeData);
    });

    it('should load and display resource description', async () => {
      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-describe')).toBeInTheDocument();
      });

      expect(kubernetesApi.describeResource).toHaveBeenCalledWith('Pod', 'test-pod', 'default');
    });

    it('should display description section when available', async () => {
      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Description')).toBeInTheDocument();
      });

      expect(screen.getByText(/Name:\s+test-pod/)).toBeInTheDocument();
      expect(screen.getByText(/Namespace:\s+default/)).toBeInTheDocument();
    });

    it('should display YAML section with syntax highlighting', async () => {
      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('YAML Definition')).toBeInTheDocument();
      });

      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
      expect(screen.getByText('in default')).toBeInTheDocument();
    });

    it('should display resource metadata summary', async () => {
      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Resource Information')).toBeInTheDocument();
      });

      expect(screen.getByText('Kind:')).toBeInTheDocument();
      expect(screen.getByText('Name:')).toBeInTheDocument();
      expect(screen.getByText('Namespace:')).toBeInTheDocument();
      expect(screen.getByText('Status:')).toBeInTheDocument();
      expect(screen.getByText('Last Updated:')).toBeInTheDocument();
      expect(screen.getByText('Relationships:')).toBeInTheDocument();
      expect(screen.getByText('1')).toBeInTheDocument(); // Relationships count
    });

    it('should copy YAML to clipboard when copy button is clicked', async () => {
      // eslint-disable-next-line @typescript-eslint/unbound-method
      const mockWriteText = vi.mocked(navigator.clipboard.writeText);

      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Copy YAML')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Copy YAML'));

      expect(mockWriteText).toHaveBeenCalledWith(mockDescribeData.yaml);
    });

    it('should handle resource without namespace', async () => {
      const resourceWithoutNamespace = { ...mockResource, namespace: undefined };
      
      render(<ResourceDescribe resource={resourceWithoutNamespace} />);

      await waitFor(() => {
        expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
      });

      expect(screen.queryByText('in default')).not.toBeInTheDocument();
      expect(screen.queryByText('Namespace:')).not.toBeInTheDocument();
    });

    it('should handle resource without relationships', async () => {
      const resourceWithoutRelationships = { ...mockResource, relationships: [] };
      
      render(<ResourceDescribe resource={resourceWithoutRelationships} />);

      await waitFor(() => {
        expect(screen.getByText('Resource Information')).toBeInTheDocument();
      });

      expect(screen.queryByText('Relationships:')).not.toBeInTheDocument();
    });

    it('should handle description without description text', async () => {
      const dataWithoutDescription = { ...mockDescribeData, description: '' };
      vi.mocked(kubernetesApi.describeResource).mockResolvedValue(dataWithoutDescription);
      
      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('YAML Definition')).toBeInTheDocument();
      });

      expect(screen.queryByText('Description')).not.toBeInTheDocument();
    });
  });

  describe('Error State', () => {
    it('should show error state when API call fails', async () => {
      const errorMessage = 'Failed to fetch resource description';
      vi.mocked(kubernetesApi.describeResource).mockRejectedValue(new Error(errorMessage));

      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-describe-error')).toBeInTheDocument();
      });

      expect(screen.getByText('Failed to load description')).toBeInTheDocument();
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
    });

    it('should handle non-Error exceptions', async () => {
      vi.mocked(kubernetesApi.describeResource).mockRejectedValue('String error');

      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Failed to fetch resource description')).toBeInTheDocument();
      });
    });
  });

  describe('Empty State', () => {
    it('should show empty state when no data is returned', async () => {
      vi.mocked(kubernetesApi.describeResource).mockResolvedValue(null as any);

      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-describe-empty')).toBeInTheDocument();
      });

      expect(screen.getByText('No description available')).toBeInTheDocument();
    });
  });

  describe('YAML Syntax Highlighting', () => {
    it('should apply syntax highlighting to YAML content', async () => {
      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('YAML Definition')).toBeInTheDocument();
      });

      // The YAML content should be rendered with syntax highlighting
      const yamlSection = screen.getByText('YAML Definition').closest('.yaml-section');
      expect(yamlSection).toBeInTheDocument();
    });
  });

  describe('Status Styling', () => {
    it('should apply correct styling for different status values', async () => {
      const readyResource = { ...mockResource, status: 'Ready' as const };
      const { rerender } = render(<ResourceDescribe resource={readyResource} />);

      await waitFor(() => {
        expect(screen.getByText('Resource Information')).toBeInTheDocument();
      });

      expect(screen.getByText('Ready')).toHaveClass('text-green-600');

      const warningResource = { ...mockResource, status: 'Warning' as const };
      rerender(<ResourceDescribe resource={warningResource} />);

      await waitFor(() => {
        expect(screen.getByText('Warning')).toHaveClass('text-yellow-600');
      });

      const errorResource = { ...mockResource, status: 'Error' as const };
      rerender(<ResourceDescribe resource={errorResource} />);

      await waitFor(() => {
        expect(screen.getByText('Error')).toHaveClass('text-red-600');
      });

      const unknownResource = { ...mockResource, status: 'Unknown' as const };
      rerender(<ResourceDescribe resource={unknownResource} />);

      await waitFor(() => {
        expect(screen.getByText('Unknown')).toHaveClass('text-gray-600');
      });
    });
  });

  describe('Custom Props', () => {
    it('should apply custom className', async () => {
      vi.mocked(kubernetesApi.describeResource).mockResolvedValue(mockDescribeData);

      render(<ResourceDescribe resource={mockResource} className="custom-class" />);

      await waitFor(() => {
        const container = screen.getByTestId('resource-describe');
        expect(container).toHaveClass('custom-class');
      });
    });
  });

  describe('API Integration', () => {
    it('should refetch data when resource changes', async () => {
      vi.mocked(kubernetesApi.describeResource).mockResolvedValue(mockDescribeData);

      const { rerender } = render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        expect(kubernetesApi.describeResource).toHaveBeenCalledWith('Pod', 'test-pod', 'default');
      });

      const newResource = { ...mockResource, name: 'new-pod' };
      rerender(<ResourceDescribe resource={newResource} />);

      await waitFor(() => {
        expect(kubernetesApi.describeResource).toHaveBeenCalledWith('Pod', 'new-pod', 'default');
      });

      expect(kubernetesApi.describeResource).toHaveBeenCalledTimes(2);
    });
  });

  describe('Accessibility', () => {
    it('should have proper accessibility attributes', async () => {
      vi.mocked(kubernetesApi.describeResource).mockResolvedValue(mockDescribeData);

      render(<ResourceDescribe resource={mockResource} />);

      await waitFor(() => {
        const copyButton = screen.getByLabelText('Copy YAML to clipboard');
        expect(copyButton).toBeInTheDocument();
        expect(copyButton).toHaveAttribute('aria-label', 'Copy YAML to clipboard');
      });
    });
  });
});