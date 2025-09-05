import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import CommandTranslationPreview from '../CommandTranslationPreview';
import type { CommandTranslation } from '../CommandTranslationPreview';

expect.extend(toHaveNoViolations);

const mockTranslation: CommandTranslation = {
  originalQuery: 'get all pods in default namespace',
  generatedCommand: 'kubectl get pods -n default',
  confidence: 0.85,
  explanation: 'This command lists all pods in the default namespace',
  safetyLevel: 'safe',
  affectedResources: ['pods'],
  requiredPermissions: ['pods.list'],
  alternatives: [
    {
      command: 'kubectl get pods --namespace=default',
      explanation: 'Alternative using --namespace flag',
      confidence: 0.82,
    },
    {
      command: 'kubectl get po -n default',
      explanation: 'Shorter version using pod alias',
      confidence: 0.80,
    },
  ],
};

const mockDestructiveTranslation: CommandTranslation = {
  originalQuery: 'delete all pods',
  generatedCommand: 'kubectl delete pods --all',
  confidence: 0.75,
  explanation: 'This command will delete all pods in the current namespace',
  safetyLevel: 'destructive',
  affectedResources: ['all pods in current namespace'],
  requiredPermissions: ['pods.delete'],
};

describe('CommandTranslationPreview', () => {
  const mockOnApprove = vi.fn();
  const mockOnModify = vi.fn();
  const mockOnSelectAlternative = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Basic Rendering', () => {
    it('renders translation preview with all sections', () => {
      render(
        <CommandTranslationPreview
          translation={mockTranslation}
          onApprove={mockOnApprove}
          onModify={mockOnModify}
        />
      );

      expect(screen.getByText('"get all pods in default namespace"')).toBeInTheDocument();
      expect(screen.getByText('Generated Command')).toBeInTheDocument();
      expect(screen.getByText('What this command will do:')).toBeInTheDocument();
      expect(screen.getByText(mockTranslation.explanation)).toBeInTheDocument();
      expect(screen.getByText('Affected Resources:')).toBeInTheDocument();
      expect(screen.getByText('Required Permissions:')).toBeInTheDocument();
    });

    it('displays confidence level correctly', () => {
      render(<CommandTranslationPreview translation={mockTranslation} />);
      
      expect(screen.getByText('Good Confidence (85%)')).toBeInTheDocument();
    });

    it('shows safety indicator with correct level', () => {
      render(<CommandTranslationPreview translation={mockTranslation} />);
      
      // Safety indicator should be present (tested via its container or text)
      const safetyElements = screen.getAllByText(/safe/i);
      expect(safetyElements.length).toBeGreaterThan(0);
    });
  });

  describe('Confidence Levels', () => {
    it('displays high confidence correctly', () => {
      const highConfidenceTranslation = { ...mockTranslation, confidence: 0.95 };
      render(<CommandTranslationPreview translation={highConfidenceTranslation} />);
      
      expect(screen.getByText('High Confidence (95%)')).toBeInTheDocument();
    });

    it('displays low confidence with warning', () => {
      const lowConfidenceTranslation = { ...mockTranslation, confidence: 0.45 };
      render(<CommandTranslationPreview translation={lowConfidenceTranslation} />);
      
      expect(screen.getByText('Low Confidence (45%)')).toBeInTheDocument();
      expect(screen.getByText('Review carefully - confidence below 70%')).toBeInTheDocument();
    });

    it('applies correct styling for different confidence levels', () => {
      const { rerender } = render(<CommandTranslationPreview translation={mockTranslation} />);
      
      let confidenceBadge = screen.getByText('Good Confidence (85%)');
      expect(confidenceBadge).toHaveClass('text-safe-600');

      const lowConfidenceTranslation = { ...mockTranslation, confidence: 0.3 };
      rerender(<CommandTranslationPreview translation={lowConfidenceTranslation} />);
      
      confidenceBadge = screen.getByText('Low Confidence (30%)');
      expect(confidenceBadge).toHaveClass('text-destructive-600');
    });
  });

  describe('Safety Levels', () => {
    it('renders destructive commands with appropriate styling', () => {
      render(<CommandTranslationPreview translation={mockDestructiveTranslation} />);
      
      const executeButton = screen.getByText('Execute Command');
      expect(executeButton).toHaveClass('bg-destructive-600');
    });

    it('shows warning for low confidence destructive commands', () => {
      const lowConfidenceDestructive = { ...mockDestructiveTranslation, confidence: 0.4 };
      render(<CommandTranslationPreview translation={lowConfidenceDestructive} />);
      
      expect(screen.getByText('Review carefully - confidence below 70%')).toBeInTheDocument();
    });
  });

  describe('Alternative Suggestions', () => {
    it('displays alternative commands when available', () => {
      render(
        <CommandTranslationPreview 
          translation={mockTranslation}
          showAlternatives={true}
        />
      );

      expect(screen.getByText('Alternative Commands:')).toBeInTheDocument();
      expect(screen.getByText('kubectl get pods --namespace=default')).toBeInTheDocument();
      expect(screen.getByText('kubectl get po -n default')).toBeInTheDocument();
    });

    it('hides alternatives when showAlternatives is false', () => {
      render(
        <CommandTranslationPreview 
          translation={mockTranslation}
          showAlternatives={false}
        />
      );

      expect(screen.queryByText('Alternative Commands:')).not.toBeInTheDocument();
    });

    it('calls onSelectAlternative when alternative is selected', async () => {
      render(
        <CommandTranslationPreview 
          translation={mockTranslation}
          onSelectAlternative={mockOnSelectAlternative}
          showAlternatives={true}
        />
      );

      const useThisButtons = screen.getAllByText('Use This');
      fireEvent.click(useThisButtons[0]);

      expect(mockOnSelectAlternative).toHaveBeenCalledWith({
        command: 'kubectl get pods --namespace=default',
        explanation: 'Alternative using --namespace flag',
        confidence: 0.82,
      });
    });
  });

  describe('Action Buttons', () => {
    it('calls onApprove when Execute Command is clicked', () => {
      render(
        <CommandTranslationPreview
          translation={mockTranslation}
          onApprove={mockOnApprove}
        />
      );

      fireEvent.click(screen.getByText('Execute Command'));
      expect(mockOnApprove).toHaveBeenCalledWith(mockTranslation.generatedCommand);
    });

    it('calls onModify when Modify is clicked', () => {
      render(
        <CommandTranslationPreview
          translation={mockTranslation}
          onModify={mockOnModify}
        />
      );

      fireEvent.click(screen.getByText('Modify'));
      expect(mockOnModify).toHaveBeenCalledWith(mockTranslation.generatedCommand);
    });

    it('disables buttons when loading', () => {
      render(
        <CommandTranslationPreview
          translation={mockTranslation}
          isLoading={true}
        />
      );

      expect(screen.getByText('Processing...')).toBeDisabled();
      expect(screen.getByText('Modify')).toBeDisabled();
    });
  });

  describe('Resource and Permission Display', () => {
    it('renders affected resources list', () => {
      render(<CommandTranslationPreview translation={mockTranslation} />);
      
      expect(screen.getByText('Affected Resources:')).toBeInTheDocument();
      expect(screen.getByText('pods')).toBeInTheDocument();
    });

    it('renders required permissions', () => {
      render(<CommandTranslationPreview translation={mockTranslation} />);
      
      expect(screen.getByText('Required Permissions:')).toBeInTheDocument();
      expect(screen.getByText('pods.list')).toBeInTheDocument();
    });

    it('hides sections when data is not available', () => {
      const minimalTranslation = {
        originalQuery: 'test',
        generatedCommand: 'kubectl version',
        confidence: 0.9,
        explanation: 'Shows kubectl version',
        safetyLevel: 'safe' as const,
      };

      render(<CommandTranslationPreview translation={minimalTranslation} />);
      
      expect(screen.queryByText('Affected Resources:')).not.toBeInTheDocument();
      expect(screen.queryByText('Required Permissions:')).not.toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('meets WCAG AA accessibility standards', async () => {
      const { container } = render(
        <CommandTranslationPreview translation={mockTranslation} />
      );
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('provides proper button accessibility', () => {
      render(
        <CommandTranslationPreview
          translation={mockTranslation}
          onApprove={mockOnApprove}
          onModify={mockOnModify}
        />
      );

      const executeButton = screen.getByRole('button', { name: /execute command/i });
      const modifyButton = screen.getByRole('button', { name: /modify/i });

      expect(executeButton).toBeInTheDocument();
      expect(modifyButton).toBeInTheDocument();
    });

    it('provides keyboard navigation support', () => {
      render(
        <CommandTranslationPreview
          translation={mockTranslation}
          onApprove={mockOnApprove}
        />
      );

      const executeButton = screen.getByText('Execute Command');
      executeButton.focus();
      
      fireEvent.keyDown(executeButton, { key: 'Enter', code: 'Enter' });
      // Button click should be triggered by Enter key through default behavior
    });
  });

  describe('Edge Cases', () => {
    it('handles missing alternatives gracefully', () => {
      const translationWithoutAlternatives = {
        ...mockTranslation,
        alternatives: undefined,
      };

      render(
        <CommandTranslationPreview 
          translation={translationWithoutAlternatives}
          showAlternatives={true}
        />
      );

      expect(screen.queryByText('Alternative Commands:')).not.toBeInTheDocument();
    });

    it('handles empty alternatives array', () => {
      const translationWithEmptyAlternatives = {
        ...mockTranslation,
        alternatives: [],
      };

      render(
        <CommandTranslationPreview 
          translation={translationWithEmptyAlternatives}
          showAlternatives={true}
        />
      );

      expect(screen.queryByText('Alternative Commands:')).not.toBeInTheDocument();
    });

    it('renders without optional props', () => {
      render(<CommandTranslationPreview translation={mockTranslation} />);
      
      // Should render without throwing errors
      expect(screen.getByText('Generated Command')).toBeInTheDocument();
    });
  });
});