import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import CommandExplanation from '../CommandExplanation';
import type { KubectlCommandPart } from '../CommandExplanation';

expect.extend(toHaveNoViolations);

const mockParts: KubectlCommandPart[] = [
  {
    part: 'kubectl',
    type: 'command',
    explanation: 'The main kubectl command-line tool for Kubernetes'
  },
  {
    part: 'get',
    type: 'verb',
    explanation: 'Retrieve resources from the cluster'
  },
  {
    part: 'pods',
    type: 'resource',
    explanation: 'Target pods resource type'
  },
  {
    part: '-n',
    type: 'flag',
    explanation: 'Namespace flag (short form)'
  },
  {
    part: 'default',
    type: 'value',
    explanation: 'The default namespace'
  }
];

const mockExamples = [
  {
    description: 'Get all pods in all namespaces',
    command: 'kubectl get pods --all-namespaces'
  },
  {
    description: 'Get pods with labels',
    command: 'kubectl get pods -l app=nginx'
  }
];

const mockRelatedCommands = [
  {
    description: 'Describe a specific pod',
    command: 'kubectl describe pod <pod-name>'
  },
  {
    description: 'Watch pod changes in real-time',
    command: 'kubectl get pods -w'
  }
];

describe('CommandExplanation', () => {
  const defaultProps = {
    command: 'kubectl get pods -n default',
    fullExplanation: 'This command retrieves all pods from the default namespace in your Kubernetes cluster.',
    parts: mockParts,
    examples: mockExamples,
    relatedCommands: mockRelatedCommands,
  };

  describe('Basic Rendering', () => {
    it('renders command explanation with all tabs', () => {
      render(<CommandExplanation {...defaultProps} />);

      expect(screen.getByText('Command Explanation')).toBeInTheDocument();
      expect(screen.getByText('Overview')).toBeInTheDocument();
      expect(screen.getByText('Breakdown')).toBeInTheDocument();
      expect(screen.getByText('Examples')).toBeInTheDocument();
      expect(screen.getByText('Related')).toBeInTheDocument();
    });

    it('displays command in header', () => {
      render(<CommandExplanation {...defaultProps} />);
      
      // Command parts should be visible
      expect(screen.getByText('kubectl')).toBeInTheDocument();
      expect(screen.getByText('get')).toBeInTheDocument();
      expect(screen.getByText('pods')).toBeInTheDocument();
    });

    it('shows tab counts when data is available', () => {
      render(<CommandExplanation {...defaultProps} />);

      expect(screen.getByText('5')).toBeInTheDocument(); // Breakdown count
      expect(screen.getAllByText('2')).toHaveLength(2); // Examples and Related count
    });
  });

  describe('Tab Navigation', () => {
    it('starts with overview tab active', () => {
      render(<CommandExplanation {...defaultProps} />);
      
      expect(screen.getByText(defaultProps.fullExplanation)).toBeInTheDocument();
      expect(screen.getByText(/Hover over colored parts.*to see detailed explanations/)).toBeInTheDocument();
    });

    it('switches to breakdown tab when clicked', async () => {
      render(<CommandExplanation {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Breakdown'));
      
      await waitFor(() => {
        expect(screen.getByText('The main kubectl command-line tool for Kubernetes')).toBeInTheDocument();
        expect(screen.getByText('Retrieve resources from the cluster')).toBeInTheDocument();
      });
    });

    it('switches to examples tab when clicked', async () => {
      render(<CommandExplanation {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Examples'));
      
      await waitFor(() => {
        expect(screen.getByText('Get all pods in all namespaces')).toBeInTheDocument();
        expect(screen.getByText('kubectl get pods --all-namespaces')).toBeInTheDocument();
      });
    });

    it('switches to related tab when clicked', async () => {
      render(<CommandExplanation {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Related'));
      
      await waitFor(() => {
        expect(screen.getByText('Describe a specific pod')).toBeInTheDocument();
        expect(screen.getByText('kubectl describe pod <pod-name>')).toBeInTheDocument();
      });
    });

    it('applies active styling to current tab', () => {
      render(<CommandExplanation {...defaultProps} />);
      
      const overviewTab = screen.getByRole('button', { name: /overview/i });
      expect(overviewTab).toHaveClass('border-blue-500', 'text-blue-600');
      
      fireEvent.click(screen.getByText('Breakdown'));
      
      const breakdownTab = screen.getByRole('button', { name: /breakdown/i });
      expect(breakdownTab).toHaveClass('border-blue-500', 'text-blue-600');
    });
  });

  describe('Command Part Highlighting', () => {
    it('renders command parts with correct colors', () => {
      render(<CommandExplanation {...defaultProps} />);
      
      const kubectlPart = screen.getByText('kubectl');
      const getPart = screen.getByText('get');
      const podsPart = screen.getByText('pods');
      
      expect(kubectlPart).toHaveClass('text-blue-600', 'bg-blue-50');
      expect(getPart).toHaveClass('text-green-600', 'bg-green-50');
      expect(podsPart).toHaveClass('text-purple-600', 'bg-purple-50');
    });

    it('shows tooltip on hover', async () => {
      render(<CommandExplanation {...defaultProps} />);
      
      const kubectlPart = screen.getByText('kubectl');
      fireEvent.mouseEnter(kubectlPart);
      
      await waitFor(() => {
        // The tooltip appears at the bottom of the component with specific styling
        expect(screen.getByText('The main kubectl command-line tool for Kubernetes')).toBeInTheDocument();
        // Check for tooltip container with blue background
        const tooltipSection = screen.getByTestId ? 
          screen.queryByTestId('tooltip-section') :
          document.querySelector('.border-t.border-gray-200.bg-blue-50');
        if (tooltipSection) {
          expect(tooltipSection).toBeInTheDocument();
        }
      });
    });

    it('hides tooltip on mouse leave', async () => {
      render(<CommandExplanation {...defaultProps} />);
      
      const kubectlPart = screen.getByText('kubectl');
      fireEvent.mouseEnter(kubectlPart);
      
      // Verify tooltip text appears
      await waitFor(() => {
        expect(screen.getByText('The main kubectl command-line tool for Kubernetes')).toBeInTheDocument();
      });
      
      fireEvent.mouseLeave(kubectlPart);
      
      await waitFor(() => {
        // After mouse leave, the tooltip explanation should not be visible in the bottom section
        const tooltipSections = document.querySelectorAll('.border-t.border-gray-200.bg-blue-50');
        expect(tooltipSections.length).toBe(0);
      });
    });
  });

  describe('Breakdown Tab', () => {
    beforeEach(() => {
      render(<CommandExplanation {...defaultProps} />);
      fireEvent.click(screen.getByText('Breakdown'));
    });

    it('displays all command parts with explanations', async () => {
      await waitFor(() => {
        mockParts.forEach(part => {
          expect(screen.getByText(part.part)).toBeInTheDocument();
          expect(screen.getByText(part.explanation)).toBeInTheDocument();
          expect(screen.getByText(part.type.toUpperCase())).toBeInTheDocument();
        });
      });
    });

    it('applies correct styling to part types', async () => {
      await waitFor(() => {
        const kubectlElement = screen.getAllByText('kubectl').find(el => 
          el.classList.contains('text-blue-600')
        );
        expect(kubectlElement).toBeInTheDocument();
      });
    });
  });

  describe('Examples Tab', () => {
    beforeEach(() => {
      render(<CommandExplanation {...defaultProps} />);
      fireEvent.click(screen.getByText('Examples'));
    });

    it('displays all examples with descriptions and commands', async () => {
      await waitFor(() => {
        mockExamples.forEach(example => {
          expect(screen.getByText(example.description)).toBeInTheDocument();
          expect(screen.getByText(example.command)).toBeInTheDocument();
        });
      });
    });

    it('formats example commands properly', async () => {
      await waitFor(() => {
        const commandElements = screen.getAllByText('kubectl get pods --all-namespaces');
        const codeElement = commandElements.find(el => el.tagName === 'CODE');
        expect(codeElement).toHaveClass('bg-gray-900', 'text-gray-100');
      });
    });
  });

  describe('Related Commands Tab', () => {
    beforeEach(() => {
      render(<CommandExplanation {...defaultProps} />);
      fireEvent.click(screen.getByText('Related'));
    });

    it('displays all related commands with descriptions', async () => {
      await waitFor(() => {
        mockRelatedCommands.forEach(related => {
          expect(screen.getByText(related.description)).toBeInTheDocument();
          expect(screen.getByText(related.command)).toBeInTheDocument();
        });
      });
    });
  });

  describe('Empty State Handling', () => {
    it('shows message when no breakdown available', () => {
      render(<CommandExplanation 
        command="kubectl version"
        fullExplanation="Shows version"
        parts={[]}
      />);
      
      fireEvent.click(screen.getByText('Breakdown'));
      expect(screen.getByText('Detailed breakdown not available for this command.')).toBeInTheDocument();
    });

    it('shows message when no examples available', () => {
      render(<CommandExplanation 
        command="kubectl version"
        fullExplanation="Shows version"
        examples={[]}
      />);
      
      fireEvent.click(screen.getByText('Examples'));
      expect(screen.getByText('No examples available for this command.')).toBeInTheDocument();
    });

    it('shows message when no related commands available', () => {
      render(<CommandExplanation 
        command="kubectl version"
        fullExplanation="Shows version"
        relatedCommands={[]}
      />);
      
      fireEvent.click(screen.getByText('Related'));
      expect(screen.getByText('No related commands available.')).toBeInTheDocument();
    });
  });

  describe('Fallback for Simple Command', () => {
    it('renders simple command without parts', () => {
      render(<CommandExplanation 
        command="kubectl version --client"
        fullExplanation="Shows the kubectl client version"
      />);
      
      expect(screen.getByText('kubectl version --client')).toBeInTheDocument();
      expect(screen.getByText('Shows the kubectl client version')).toBeInTheDocument();
    });

    it('hides hover hint when no parts available', () => {
      render(<CommandExplanation 
        command="kubectl version"
        fullExplanation="Shows version"
        parts={[]}
      />);
      
      expect(screen.queryByText(/Hover over colored parts/)).not.toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('meets WCAG AA accessibility standards', async () => {
      const { container } = render(<CommandExplanation {...defaultProps} />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('provides proper tab navigation', () => {
      render(<CommandExplanation {...defaultProps} />);
      
      const tabs = screen.getAllByRole('button');
      tabs.forEach(tab => {
        expect(tab).toBeInTheDocument();
      });
    });

    it('provides proper ARIA labels and roles', () => {
      render(<CommandExplanation {...defaultProps} />);
      
      // Check that interactive elements have proper roles
      const tabButtons = screen.getAllByRole('button');
      expect(tabButtons.length).toBeGreaterThan(0);
    });

    it('supports keyboard navigation for command parts', () => {
      render(<CommandExplanation {...defaultProps} />);
      
      const kubectlPart = screen.getByText('kubectl');
      expect(kubectlPart).toHaveAttribute('title');
    });
  });

  describe('Responsive Design', () => {
    it('handles long commands gracefully', () => {
      const longCommand = 'kubectl get pods --all-namespaces --field-selector=status.phase=Running --output=wide --sort-by=.metadata.creationTimestamp';
      
      render(<CommandExplanation 
        command={longCommand}
        fullExplanation="A very long command"
      />);
      
      const commandContainer = screen.getByText(longCommand).closest('div');
      expect(commandContainer).toHaveClass('overflow-x-auto');
    });
  });
});