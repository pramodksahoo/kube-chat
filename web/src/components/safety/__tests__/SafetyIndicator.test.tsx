import { render, screen } from '@testing-library/react';
import SafetyIndicator from '../SafetyIndicator';
import type { SafetyLevel } from '../SafetyIndicator';

describe('SafetyIndicator Component', () => {
  const safetyLevels: SafetyLevel[] = ['safe', 'caution', 'destructive', 'info', 'disabled'];

  describe('Basic Rendering', () => {
    test('renders with default props', () => {
      render(<SafetyIndicator level="safe" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toBeInTheDocument();
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: Safe Operation');
    });

    test('applies custom className', () => {
      render(<SafetyIndicator level="safe" className="custom-class" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('custom-class');
    });

    test('renders children content', () => {
      render(
        <SafetyIndicator level="caution">
          <div>Child content</div>
        </SafetyIndicator>
      );
      expect(screen.getByText('Child content')).toBeInTheDocument();
    });
  });

  describe('Safety Levels', () => {
    test.each(safetyLevels)('renders %s level correctly', (level) => {
      render(<SafetyIndicator level={level} showText={true} />);
      const indicator = screen.getByRole('status');
      expect(indicator).toBeInTheDocument();
      
      // Check ARIA label contains "Safety level:"
      expect(indicator).toHaveAttribute('aria-label', expect.stringContaining('Safety level:'));
    });

    test('displays correct text for each safety level', () => {
      const expectedTexts = {
        safe: 'Safe Operation',
        caution: 'Caution Required',
        destructive: 'Destructive Operation',
        info: 'Information',
        disabled: 'Disabled',
      };

      safetyLevels.forEach(level => {
        const { unmount } = render(<SafetyIndicator level={level} showText={true} />);
        expect(screen.getByText(expectedTexts[level])).toBeInTheDocument();
        unmount();
      });
    });
  });

  describe('Variants', () => {
    test('renders border variant correctly', () => {
      render(<SafetyIndicator level="safe" variant="border" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('border-l-4');
    });

    test('renders background variant correctly', () => {
      render(<SafetyIndicator level="caution" variant="background" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('bg-amber-50', 'border', 'border-amber-200');
    });

    test('renders icon variant correctly', () => {
      render(<SafetyIndicator level="destructive" variant="icon" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: Destructive Operation');
    });

    test('renders badge variant correctly', () => {
      render(<SafetyIndicator level="info" variant="badge" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('rounded-full', 'bg-[#0ea5e9]', 'text-white');
    });
  });

  describe('Sizes', () => {
    test('renders small size correctly', () => {
      render(<SafetyIndicator level="safe" size="sm" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('px-2', 'py-1', 'text-xs');
    });

    test('renders medium size correctly', () => {
      render(<SafetyIndicator level="safe" size="md" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('px-3', 'py-2', 'text-sm');
    });

    test('renders large size correctly', () => {
      render(<SafetyIndicator level="safe" size="lg" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('px-4', 'py-3', 'text-base');
    });
  });

  describe('Text Display', () => {
    test('shows text when showText is true', () => {
      render(<SafetyIndicator level="safe" showText={true} />);
      expect(screen.getByText('Safe Operation')).toBeInTheDocument();
    });

    test('hides text when showText is false', () => {
      render(<SafetyIndicator level="safe" showText={false} />);
      expect(screen.queryByText('Safe Operation')).not.toBeInTheDocument();
    });

    test('displays icon and text together in icon variant', () => {
      render(<SafetyIndicator level="caution" variant="icon" showText={true} />);
      const indicator = screen.getByRole('img');
      expect(indicator).toBeInTheDocument();
      expect(screen.getByText('Caution Required')).toBeInTheDocument();
    });
  });

  describe('Safety Colors', () => {
    test('applies correct color classes for safe level', () => {
      render(<SafetyIndicator level="safe" variant="background" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('bg-emerald-50', 'border-emerald-200', 'text-emerald-800');
    });

    test('applies correct color classes for caution level', () => {
      render(<SafetyIndicator level="caution" variant="background" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('bg-amber-50', 'border-amber-200', 'text-amber-800');
    });

    test('applies correct color classes for destructive level', () => {
      render(<SafetyIndicator level="destructive" variant="background" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('bg-red-50', 'border-red-200', 'text-red-800');
    });

    test('applies correct color classes for info level', () => {
      render(<SafetyIndicator level="info" variant="background" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('bg-blue-50', 'border-blue-200', 'text-blue-800');
    });

    test('applies correct color classes for disabled level', () => {
      render(<SafetyIndicator level="disabled" variant="background" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('bg-gray-50', 'border-gray-200', 'text-gray-600');
    });
  });

  describe('Accessibility', () => {
    test('provides proper ARIA labels', () => {
      render(<SafetyIndicator level="destructive" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: Destructive Operation');
    });

    test('renders accessible alternative when requested', () => {
      render(<SafetyIndicator level="safe" useAccessibleAlternative={true} />);
      // The accessible alternative should be present
      const container = screen.getByRole('img');
      expect(container).toHaveAttribute('aria-label', 'Safety level: SAFE');
    });

    test('combines accessible alternative with text', () => {
      render(
        <SafetyIndicator 
          level="caution" 
          useAccessibleAlternative={true} 
          showText={true} 
        />
      );
      expect(screen.getByText('Caution Required')).toBeInTheDocument();
    });

    test('supports different accessibility variants', () => {
      const { rerender } = render(
        <SafetyIndicator 
          level="info" 
          useAccessibleAlternative={true} 
          accessibilityVariant="text" 
        />
      );
      expect(screen.getByText('INFO')).toBeInTheDocument();

      rerender(
        <SafetyIndicator 
          level="info" 
          useAccessibleAlternative={true} 
          accessibilityVariant="symbol" 
        />
      );
      expect(screen.getByText('ℹ')).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    test('handles unknown safety level gracefully', () => {
      // @ts-expect-error Testing invalid input
      render(<SafetyIndicator level="unknown" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: Unknown');
    });

    test('provides fallback styles for unknown levels', () => {
      // @ts-expect-error Testing invalid input
      render(<SafetyIndicator level="invalid" variant="background" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('bg-gray-50', 'border-gray-200', 'text-gray-700');
    });
  });

  describe('Badge Variant Specific Tests', () => {
    test('badge variant shows level text in uppercase', () => {
      render(<SafetyIndicator level="safe" variant="badge" />);
      expect(screen.getByText('SAFE')).toBeInTheDocument();
    });

    test('badge variant shows full text when showText is true', () => {
      render(<SafetyIndicator level="safe" variant="badge" showText={true} />);
      expect(screen.getByText('Safe Operation')).toBeInTheDocument();
    });
  });

  describe('Integration with Icons', () => {
    test('renders appropriate SVG icons', () => {
      const { container } = render(<SafetyIndicator level="safe" variant="icon" />);
      const svgElement = container.querySelector('svg');
      expect(svgElement).toBeInTheDocument();
    });

    test('icon variant maintains proper structure', () => {
      render(<SafetyIndicator level="caution" variant="icon" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toBeInTheDocument();
      
      // Check for SVG warning icon (triangle with exclamation)
      const svg = indicator.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });
  });
});