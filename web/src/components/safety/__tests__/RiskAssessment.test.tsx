import { render, screen } from '@testing-library/react';
import RiskAssessment from '../RiskAssessment';
import type { RiskAssessmentData } from '../RiskAssessment';

describe('RiskAssessment Component', () => {
  const mockRiskData: RiskAssessmentData = {
    level: 'caution',
    command: 'kubectl apply -f deployment.yaml',
    affectedResources: ['deployment/nginx', 'service/nginx-service'],
    risks: ['May cause service interruption', 'Pod restart required'],
    recommendations: ['Backup current deployment', 'Run in maintenance window'],
    executionTime: '~2 minutes',
  };

  describe('Compact Variant', () => {
    test('renders compact variant correctly', () => {
      render(<RiskAssessment data={{ level: 'safe' }} variant="compact" />);
      
      expect(screen.getByText('This operation is safe and will not modify your cluster state.')).toBeInTheDocument();
      
      // Should not show detailed sections in compact mode
      expect(screen.queryByText('Generated Command:')).not.toBeInTheDocument();
      expect(screen.queryByText('Affected Resources:')).not.toBeInTheDocument();
    });

    test('shows safety indicator in compact mode', () => {
      const { container } = render(
        <RiskAssessment data={{ level: 'destructive' }} variant="compact" />
      );
      
      // Should contain safety indicator
      const safetyIndicator = container.querySelector('[role="img"]');
      expect(safetyIndicator).toBeInTheDocument();
    });

    test('applies custom className to compact variant', () => {
      const { container } = render(
        <RiskAssessment 
          data={{ level: 'safe' }} 
          variant="compact" 
          className="custom-class" 
        />
      );
      
      expect(container.firstChild).toHaveClass('custom-class');
    });
  });

  describe('Detailed Variant', () => {
    test('renders detailed variant with all sections', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      // Check for all main sections
      expect(screen.getByText('Generated Command:')).toBeInTheDocument();
      expect(screen.getByText('Affected Resources:')).toBeInTheDocument();
      expect(screen.getByText('Potential Risks:')).toBeInTheDocument();
      expect(screen.getByText('Recommendations:')).toBeInTheDocument();
      expect(screen.getByText('Est. execution: ~2 minutes')).toBeInTheDocument();
    });

    test('displays command in code block', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      const codeElement = screen.getByText('kubectl apply -f deployment.yaml');
      expect(codeElement).toBeInTheDocument();
      expect(codeElement.closest('code')).toBeInTheDocument();
    });

    test('renders affected resources list', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      expect(screen.getByText('deployment/nginx')).toBeInTheDocument();
      expect(screen.getByText('service/nginx-service')).toBeInTheDocument();
    });

    test('renders risks with warning icons', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      expect(screen.getByText('May cause service interruption')).toBeInTheDocument();
      expect(screen.getByText('Pod restart required')).toBeInTheDocument();
      
      // Check for warning icon SVGs
      const riskItems = screen.getAllByText(/May cause|Pod restart/);
      riskItems.forEach(item => {
        const listItem = item.closest('li');
        expect(listItem).toHaveClass('text-red-700');
      });
    });

    test('renders recommendations with info icons', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      expect(screen.getByText('Backup current deployment')).toBeInTheDocument();
      expect(screen.getByText('Run in maintenance window')).toBeInTheDocument();
      
      // Check for info icon styling
      const recommendationItems = screen.getAllByText(/Backup|Run in maintenance/);
      recommendationItems.forEach(item => {
        const listItem = item.closest('li');
        expect(listItem).toHaveClass('text-blue-700');
      });
    });
  });

  describe('Safety Level Descriptions', () => {
    test('shows correct description for safe level', () => {
      render(<RiskAssessment data={{ level: 'safe' }} />);
      expect(screen.getByText('This operation is safe and will not modify your cluster state.')).toBeInTheDocument();
    });

    test('shows correct description for caution level', () => {
      render(<RiskAssessment data={{ level: 'caution' }} />);
      expect(screen.getByText('This operation requires attention and may modify cluster resources.')).toBeInTheDocument();
    });

    test('shows correct description for destructive level', () => {
      render(<RiskAssessment data={{ level: 'destructive' }} />);
      expect(screen.getByText('This operation is destructive and may cause irreversible changes.')).toBeInTheDocument();
    });

    test('shows correct description for info level', () => {
      render(<RiskAssessment data={{ level: 'info' }} />);
      expect(screen.getByText('This is an informational operation.')).toBeInTheDocument();
    });

    test('shows correct description for disabled level', () => {
      render(<RiskAssessment data={{ level: 'disabled' }} />);
      expect(screen.getByText('This operation is not available.')).toBeInTheDocument();
    });

    test('shows fallback description for unknown level', () => {
      // @ts-expect-error Testing invalid input
      render(<RiskAssessment data={{ level: 'unknown' }} />);
      expect(screen.getByText('Risk level unknown.')).toBeInTheDocument();
    });
  });

  describe('Conditional Rendering', () => {
    test('hides command section when no command provided', () => {
      const dataWithoutCommand = { ...mockRiskData };
      delete dataWithoutCommand.command;
      
      render(<RiskAssessment data={dataWithoutCommand} variant="detailed" />);
      expect(screen.queryByText('Generated Command:')).not.toBeInTheDocument();
    });

    test('hides affected resources section when empty', () => {
      const dataWithoutResources = { ...mockRiskData, affectedResources: [] };
      
      render(<RiskAssessment data={dataWithoutResources} variant="detailed" />);
      expect(screen.queryByText('Affected Resources:')).not.toBeInTheDocument();
    });

    test('hides risks section when empty', () => {
      const dataWithoutRisks = { ...mockRiskData, risks: [] };
      
      render(<RiskAssessment data={dataWithoutRisks} variant="detailed" />);
      expect(screen.queryByText('Potential Risks:')).not.toBeInTheDocument();
    });

    test('hides recommendations section when empty', () => {
      const dataWithoutRecommendations = { ...mockRiskData, recommendations: [] };
      
      render(<RiskAssessment data={dataWithoutRecommendations} variant="detailed" />);
      expect(screen.queryByText('Recommendations:')).not.toBeInTheDocument();
    });

    test('hides execution time when not provided', () => {
      const dataWithoutTime = { ...mockRiskData };
      delete dataWithoutTime.executionTime;
      
      render(<RiskAssessment data={dataWithoutTime} variant="detailed" />);
      expect(screen.queryByText(/Est. execution:/)).not.toBeInTheDocument();
    });
  });

  describe('Safety Indicator Integration', () => {
    test('renders safety indicator badge in header', () => {
      const { container } = render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      // Should have a safety indicator with badge variant
      const badge = container.querySelector('[role="status"]');
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveClass('rounded-full');
    });

    test('renders safety indicator with background in description', () => {
      const { container } = render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      // Should have background variant safety indicator
      const backgroundIndicators = container.querySelectorAll('[role="status"]');
      expect(backgroundIndicators.length).toBeGreaterThan(0);
    });
  });

  describe('Accessibility', () => {
    test('provides proper semantic structure', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      // Check for proper heading structure
      expect(screen.getByRole('heading', { level: 4, name: 'Generated Command:' })).toBeInTheDocument();
      expect(screen.getByRole('heading', { level: 4, name: 'Affected Resources:' })).toBeInTheDocument();
      expect(screen.getByRole('heading', { level: 4, name: 'Potential Risks:' })).toBeInTheDocument();
      expect(screen.getByRole('heading', { level: 4, name: 'Recommendations:' })).toBeInTheDocument();
    });

    test('provides proper list structure for resources', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      const resourcesLists = screen.getAllByRole('list');
      expect(resourcesLists.length).toBeGreaterThan(0);
      
      const resourceItems = screen.getAllByRole('listitem');
      expect(resourceItems.length).toBeGreaterThanOrEqual(mockRiskData.affectedResources!.length);
    });

    test('ensures proper color contrast classes', () => {
      render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      // Risk items should have high contrast
      const riskText = screen.getByText('May cause service interruption');
      const riskItem = riskText.closest('li');
      expect(riskItem).toHaveClass('text-red-700');
      
      // Recommendation items should have sufficient contrast
      const recommendationText = screen.getByText('Backup current deployment');
      const recommendationItem = recommendationText.closest('li');
      expect(recommendationItem).toHaveClass('text-blue-700');
    });
  });

  describe('Responsive Design', () => {
    test('command block handles overflow correctly', () => {
      const longCommand = 'kubectl apply -f very-long-deployment-file-name-that-might-overflow.yaml --namespace production-environment';
      const dataWithLongCommand = { ...mockRiskData, command: longCommand };
      
      render(<RiskAssessment data={dataWithLongCommand} variant="detailed" />);
      
      const codeBlock = screen.getByText(longCommand).closest('div');
      expect(codeBlock).toHaveClass('overflow-x-auto');
    });

    test('applies proper spacing classes', () => {
      const { container } = render(<RiskAssessment data={mockRiskData} variant="detailed" />);
      
      const mainContainer = container.firstChild;
      expect(mainContainer).toHaveClass('space-y-4');
    });
  });

  describe('Error Handling', () => {
    test('handles empty data gracefully', () => {
      render(<RiskAssessment data={{ level: 'safe' }} variant="detailed" />);
      
      // Should still render the risk description
      expect(screen.getByText('This operation is safe and will not modify your cluster state.')).toBeInTheDocument();
      
      // Should not crash when optional fields are missing
      expect(screen.queryByText('Generated Command:')).not.toBeInTheDocument();
    });

    test('handles malformed arrays gracefully', () => {
      const malformedData = {
        level: 'caution' as const,
        affectedResources: undefined,
        risks: undefined,
        recommendations: [],
      };
      
      expect(() => {
        render(<RiskAssessment data={malformedData} variant="detailed" />);
      }).not.toThrow();
    });
  });
});