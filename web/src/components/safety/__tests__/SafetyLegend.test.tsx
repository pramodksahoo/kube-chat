import { render, screen } from '@testing-library/react';
import SafetyLegend from '../SafetyLegend';

describe('SafetyLegend Component', () => {
  describe('Basic Rendering', () => {
    test('renders with default props', () => {
      render(<SafetyLegend />);
      
      expect(screen.getByRole('region')).toBeInTheDocument();
      expect(screen.getByText('Command Safety Levels')).toBeInTheDocument();
      expect(screen.getByText('Visual indicators to help you understand operation risk levels')).toBeInTheDocument();
    });

    test('applies custom className', () => {
      const { container } = render(<SafetyLegend className="custom-legend" />);
      expect(container.firstChild).toHaveClass('custom-legend');
    });

    test('has proper ARIA labeling', () => {
      render(<SafetyLegend />);
      const region = screen.getByRole('region');
      expect(region).toHaveAttribute('aria-labelledby', 'safety-legend-title');
    });
  });

  describe('Safety Levels Content', () => {
    test('displays all safety levels', () => {
      render(<SafetyLegend />);
      
      expect(screen.getByText('Safe Operations')).toBeInTheDocument();
      expect(screen.getByText('Caution Required')).toBeInTheDocument();
      expect(screen.getByText('Destructive Operations')).toBeInTheDocument();
      expect(screen.getByText('Informational')).toBeInTheDocument();
      expect(screen.getByText('Disabled')).toBeInTheDocument();
    });

    test('shows safety level identifiers', () => {
      render(<SafetyLegend />);
      
      expect(screen.getByText('safe')).toBeInTheDocument();
      expect(screen.getByText('caution')).toBeInTheDocument();
      expect(screen.getByText('destructive')).toBeInTheDocument();
      expect(screen.getByText('info')).toBeInTheDocument();
      expect(screen.getByText('disabled')).toBeInTheDocument();
    });

    test('displays descriptions when showDescriptions is true', () => {
      render(<SafetyLegend showDescriptions={true} />);
      
      expect(screen.getByText('Read operations and informational commands that do not modify cluster state.')).toBeInTheDocument();
      expect(screen.getByText('Operations that may modify resources and require attention.')).toBeInTheDocument();
      expect(screen.getByText('Operations that may cause irreversible changes or data loss.')).toBeInTheDocument();
    });

    test('hides descriptions when showDescriptions is false', () => {
      render(<SafetyLegend showDescriptions={false} />);
      
      expect(screen.queryByText('Read operations and informational commands that do not modify cluster state.')).not.toBeInTheDocument();
      expect(screen.queryByText('Operations that may modify resources and require attention.')).not.toBeInTheDocument();
    });
  });

  describe('Command Examples', () => {
    test('displays command examples when showDescriptions is true', () => {
      render(<SafetyLegend showDescriptions={true} />);
      
      // Safe operations examples
      expect(screen.getByText('kubectl get')).toBeInTheDocument();
      expect(screen.getByText('kubectl describe')).toBeInTheDocument();
      expect(screen.getByText('kubectl logs')).toBeInTheDocument();
      
      // Caution operations examples
      expect(screen.getByText('kubectl apply')).toBeInTheDocument();
      expect(screen.getByText('kubectl patch')).toBeInTheDocument();
      expect(screen.getByText('kubectl scale')).toBeInTheDocument();
      
      // Destructive operations examples
      expect(screen.getByText('kubectl delete')).toBeInTheDocument();
      expect(screen.getByText('kubectl rollback')).toBeInTheDocument();
      expect(screen.getByText('kubectl drain')).toBeInTheDocument();
    });

    test('formats command examples as code', () => {
      render(<SafetyLegend showDescriptions={true} />);
      
      const kubectlGet = screen.getByText('kubectl get');
      expect(kubectlGet).toHaveClass('font-mono');
      expect(kubectlGet.closest('code')).toBeInTheDocument();
    });

    test('hides examples when showDescriptions is false', () => {
      render(<SafetyLegend showDescriptions={false} />);
      
      expect(screen.queryByText('kubectl get')).not.toBeInTheDocument();
      expect(screen.queryByText('kubectl apply')).not.toBeInTheDocument();
      expect(screen.queryByText('kubectl delete')).not.toBeInTheDocument();
    });
  });

  describe('Layout Variants', () => {
    test('renders horizontal layout by default', () => {
      const { container } = render(<SafetyLegend />);
      const itemsContainer = container.querySelector('.grid');
      expect(itemsContainer).toHaveClass('grid-cols-1', 'sm:grid-cols-2', 'lg:grid-cols-3');
    });

    test('renders vertical layout when specified', () => {
      const { container } = render(<SafetyLegend variant="vertical" />);
      const itemsContainer = container.querySelector('.space-y-3');
      expect(itemsContainer).toBeInTheDocument();
      
      // Should not have grid classes for vertical layout
      expect(container.querySelector('.grid')).not.toBeInTheDocument();
    });

    test('applies proper spacing for vertical layout', () => {
      render(<SafetyLegend variant="vertical" />);
      
      // Check for border styling in vertical layout
      const safeItem = screen.getByText('Safe Operations').closest('.safety-legend-item');
      expect(safeItem).toHaveClass('border-b', 'border-gray-100');
    });
  });

  describe('Safety Indicators Integration', () => {
    test('renders safety indicator badges for each level', () => {
      const { container } = render(<SafetyLegend />);
      
      // Should have 5 safety indicator badges (one for each level)
      const badges = container.querySelectorAll('[role="status"]');
      expect(badges).toHaveLength(5);
    });

    test('safety indicators have proper styling', () => {
      const { container } = render(<SafetyLegend />);
      
      const badges = container.querySelectorAll('[role="status"]');
      badges.forEach(badge => {
        expect(badge).toHaveClass('rounded-full');
      });
    });
  });

  describe('Footer Information', () => {
    test('displays compliance and logging notice', () => {
      render(<SafetyLegend />);
      
      expect(screen.getByText('All operations are logged for security and compliance. High-risk commands require additional confirmation.')).toBeInTheDocument();
    });

    test('includes info icon in footer', () => {
      const { container } = render(<SafetyLegend />);
      
      // Look for SVG in the footer area
      const svgs = container.querySelectorAll('svg');
      expect(svgs.length).toBeGreaterThan(0);
    });

    test('footer has proper styling', () => {
      const { container } = render(<SafetyLegend />);
      
      const footer = container.querySelector('.bg-gray-50');
      expect(footer).toBeInTheDocument();
      expect(footer).toHaveClass('bg-gray-50');
    });
  });

  describe('Accessibility', () => {
    test('provides proper semantic structure', () => {
      render(<SafetyLegend />);
      
      // Main heading
      const mainHeading = screen.getByRole('heading', { level: 3 });
      expect(mainHeading).toHaveTextContent('Command Safety Levels');
      
      // Section headings for each safety level
      const levelHeadings = screen.getAllByRole('heading', { level: 4 });
      expect(levelHeadings).toHaveLength(5);
    });

    test('safety level identifiers have proper ARIA labels', () => {
      render(<SafetyLegend />);
      
      const safeIdentifier = screen.getByText('safe');
      expect(safeIdentifier).toHaveAttribute('aria-label', 'Safety level: safe');
    });

    test('maintains focus order and keyboard accessibility', () => {
      render(<SafetyLegend />);
      
      // The legend should be focusable as a region
      const region = screen.getByRole('region');
      expect(region).toBeInTheDocument();
      
      // Safety indicators should have proper accessibility attributes
      const { container } = render(<SafetyLegend />);
      const badges = container.querySelectorAll('[role="status"]');
      badges.forEach(badge => {
        expect(badge).toHaveAttribute('aria-label');
      });
    });
  });

  describe('Responsive Design', () => {
    test('applies responsive grid classes', () => {
      const { container } = render(<SafetyLegend variant="horizontal" />);
      
      const gridContainer = container.querySelector('.grid');
      expect(gridContainer).toHaveClass('grid-cols-1', 'sm:grid-cols-2', 'lg:grid-cols-3');
    });

    test('handles text wrapping in compact spaces', () => {
      render(<SafetyLegend />);
      
      // Description text should have proper line height
      const description = screen.getByText('Read operations and informational commands that do not modify cluster state.');
      expect(description).toHaveClass('leading-relaxed');
    });
  });

  describe('Content Accuracy', () => {
    test('displays correct safety color associations', () => {
      render(<SafetyLegend showDescriptions={true} />);
      
      // Verify each safety level has its corresponding content
      const safeSection = screen.getByText('Safe Operations');
      expect(safeSection).toBeInTheDocument();
      
      const safeDescription = screen.getByText('Read operations and informational commands that do not modify cluster state.');
      expect(safeDescription).toBeInTheDocument();
      
      const cautionSection = screen.getByText('Caution Required');
      expect(cautionSection).toBeInTheDocument();
      
      const destructiveSection = screen.getByText('Destructive Operations');
      expect(destructiveSection).toBeInTheDocument();
    });

    test('example commands are contextually appropriate', () => {
      render(<SafetyLegend showDescriptions={true} />);
      
      // Safe commands should be read-only
      const safeExamples = ['kubectl get', 'kubectl describe', 'kubectl logs'];
      safeExamples.forEach(cmd => {
        expect(screen.getByText(cmd)).toBeInTheDocument();
      });
      
      // Destructive commands should be dangerous
      const destructiveExamples = ['kubectl delete', 'kubectl rollback', 'kubectl drain'];
      destructiveExamples.forEach(cmd => {
        expect(screen.getByText(cmd)).toBeInTheDocument();
      });
    });
  });

  describe('Visual Design', () => {
    test('applies proper card styling', () => {
      const { container } = render(<SafetyLegend />);
      
      const legend = container.firstChild;
      expect(legend).toHaveClass('safety-legend', 'rounded-lg', 'border', 'border-gray-200', 'bg-white', 'shadow-sm');
    });

    test('has consistent spacing throughout', () => {
      const { container } = render(<SafetyLegend variant="vertical" />);
      
      const itemsContainer = container.querySelector('.p-4.space-y-3');
      expect(itemsContainer).toBeInTheDocument();
    });

    test('header has proper visual separation', () => {
      const { container } = render(<SafetyLegend />);
      
      const header = container.querySelector('.p-4.border-b.border-gray-200');
      expect(header).toBeInTheDocument();
    });
  });
});