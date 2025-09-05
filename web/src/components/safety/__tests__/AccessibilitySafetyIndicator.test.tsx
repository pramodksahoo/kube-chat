import { render, screen } from '@testing-library/react';
import AccessibilitySafetyIndicator from '../AccessibilitySafetyIndicator';
import type { SafetyLevel } from '../SafetyIndicator';

describe('AccessibilitySafetyIndicator Component', () => {
  const safetyLevels: SafetyLevel[] = ['safe', 'caution', 'destructive', 'info', 'disabled'];

  describe('Symbol Variant', () => {
    test('renders correct symbols for each safety level', () => {
      const expectedSymbols = {
        safe: '✓',
        caution: '⚠',
        destructive: '✗',
        info: 'ℹ',
        disabled: '⊘',
      };

      safetyLevels.forEach(level => {
        const { unmount } = render(
          <AccessibilitySafetyIndicator level={level} variant="symbol" />
        );
        expect(screen.getByText(expectedSymbols[level])).toBeInTheDocument();
        unmount();
      });
    });

    test('provides proper ARIA labels for symbols', () => {
      render(<AccessibilitySafetyIndicator level="safe" variant="symbol" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: SAFE');
      expect(indicator).toHaveAttribute('title', 'Safety level: SAFE');
    });

    test('applies font-mono class for symbols', () => {
      render(<AccessibilitySafetyIndicator level="caution" variant="symbol" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveClass('font-mono', 'font-bold');
    });
  });

  describe('Text Variant', () => {
    test('renders correct text labels for each safety level', () => {
      const expectedTexts = {
        safe: 'SAFE',
        caution: 'CAUTION',
        destructive: 'DANGER',
        info: 'INFO',
        disabled: 'DISABLED',
      };

      safetyLevels.forEach(level => {
        const { unmount } = render(
          <AccessibilitySafetyIndicator level={level} variant="text" />
        );
        expect(screen.getByText(expectedTexts[level])).toBeInTheDocument();
        unmount();
      });
    });

    test('applies proper styling to text variant', () => {
      render(<AccessibilitySafetyIndicator level="info" variant="text" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('font-mono', 'font-bold', 'uppercase', 'tracking-wide', 'border', 'rounded');
    });

    test('provides ARIA label for text variant', () => {
      render(<AccessibilitySafetyIndicator level="destructive" variant="text" />);
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: DANGER');
    });
  });

  describe('Pattern Variant', () => {
    test('renders pattern variant with correct background', () => {
      render(<AccessibilitySafetyIndicator level="safe" variant="pattern" />);
      const indicator = screen.getByRole('img');
      
      expect(indicator.style.background).toContain('#059669');
      expect(indicator.style.backgroundSize).toBe('8px 8px');
    });

    test('provides screen reader content for patterns', () => {
      render(<AccessibilitySafetyIndicator level="caution" variant="pattern" />);
      expect(screen.getByText('CAUTION')).toHaveClass('sr-only');
    });

    test('applies proper styling to pattern variant', () => {
      render(<AccessibilitySafetyIndicator level="disabled" variant="pattern" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveClass('border-2', 'border-gray-300', 'rounded');
    });

    test('renders different patterns for different safety levels', () => {
      const levels: Array<{ level: SafetyLevel; color: string }> = [
        { level: 'safe', color: '#059669' },
        { level: 'caution', color: '#d97706' },
        { level: 'destructive', color: '#dc2626' },
        { level: 'info', color: '#0ea5e9' },
        { level: 'disabled', color: '#64748b' },
      ];

      levels.forEach(({ level, color }) => {
        const { unmount } = render(
          <AccessibilitySafetyIndicator level={level} variant="pattern" />
        );
        const indicator = screen.getByRole('img');
        expect(indicator.style.background).toContain(color);
        unmount();
      });
    });
  });

  describe('Icon Variant (Enhanced)', () => {
    test('renders enhanced icons with additional visual elements', () => {
      render(<AccessibilitySafetyIndicator level="safe" variant="icon" />);
      const indicator = screen.getByRole('img');
      
      // Should contain SVG element
      const svg = indicator.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });

    test('provides proper accessibility attributes for icons', () => {
      render(<AccessibilitySafetyIndicator level="destructive" variant="icon" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: DANGER');
      expect(indicator).toHaveAttribute('title', 'Safety level: DANGER');
      
      // Should have screen reader text
      expect(screen.getByText('DANGER')).toHaveClass('sr-only');
    });

    test('renders different enhanced icons for different levels', () => {
      safetyLevels.forEach(level => {
        const { unmount, container } = render(
          <AccessibilitySafetyIndicator level={level} variant="icon" />
        );
        
        const svg = container.querySelector('svg');
        expect(svg).toBeInTheDocument();
        unmount();
      });
    });
  });

  describe('Size Variants', () => {
    test('applies correct classes for small size', () => {
      render(<AccessibilitySafetyIndicator level="safe" variant="symbol" size="sm" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveClass('w-4', 'h-4', 'text-xs');
    });

    test('applies correct classes for medium size', () => {
      render(<AccessibilitySafetyIndicator level="safe" variant="symbol" size="md" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveClass('w-5', 'h-5', 'text-sm');
    });

    test('applies correct classes for large size', () => {
      render(<AccessibilitySafetyIndicator level="safe" variant="symbol" size="lg" />);
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveClass('w-6', 'h-6', 'text-base');
    });

    test('applies correct padding for text sizes', () => {
      const { rerender } = render(
        <AccessibilitySafetyIndicator level="safe" variant="text" size="sm" />
      );
      expect(screen.getByRole('status')).toHaveClass('text-xs', 'px-1', 'py-0.5');

      rerender(<AccessibilitySafetyIndicator level="safe" variant="text" size="md" />);
      expect(screen.getByRole('status')).toHaveClass('text-sm', 'px-2', 'py-1');

      rerender(<AccessibilitySafetyIndicator level="safe" variant="text" size="lg" />);
      expect(screen.getByRole('status')).toHaveClass('text-base', 'px-3', 'py-1');
    });
  });

  describe('Accessibility Features', () => {
    test('provides multiple methods of conveying safety level', () => {
      // Symbol variant provides visual symbol + ARIA label
      const { unmount: unmountSymbol } = render(
        <AccessibilitySafetyIndicator level="caution" variant="symbol" />
      );
      expect(screen.getByText('⚠')).toBeInTheDocument();
      expect(screen.getByRole('img')).toHaveAttribute('aria-label', 'Safety level: CAUTION');
      unmountSymbol();

      // Text variant provides readable text
      const { unmount: unmountText } = render(
        <AccessibilitySafetyIndicator level="caution" variant="text" />
      );
      expect(screen.getByText('CAUTION')).toBeInTheDocument();
      unmountText();

      // Pattern variant provides visual pattern + screen reader text
      render(<AccessibilitySafetyIndicator level="caution" variant="pattern" />);
      expect(screen.getByText('CAUTION')).toHaveClass('sr-only');
    });

    test('maintains high contrast styling', () => {
      render(<AccessibilitySafetyIndicator level="destructive" variant="text" />);
      const indicator = screen.getByRole('status');
      
      // Should have border for contrast
      expect(indicator).toHaveClass('border', 'rounded');
    });

    test('supports keyboard navigation attributes', () => {
      render(<AccessibilitySafetyIndicator level="info" variant="icon" />);
      const indicator = screen.getByRole('img');
      
      // Should be focusable and have proper labeling
      expect(indicator).toHaveAttribute('aria-label');
      expect(indicator).toHaveAttribute('title');
    });
  });

  describe('Error Handling', () => {
    test('handles unknown safety level gracefully', () => {
      // @ts-expect-error Testing invalid input
      render(<AccessibilitySafetyIndicator level="unknown" variant="symbol" />);
      expect(screen.getByText('?')).toBeInTheDocument();
    });

    test('handles unknown level in text variant', () => {
      render(<AccessibilitySafetyIndicator level={"invalid" as any} variant="text" />);
      expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
    });

    test('provides fallback pattern for unknown levels', () => {
      render(
        <AccessibilitySafetyIndicator level={"invalid" as any} variant="pattern" />
      );
      
      const indicator = screen.getByRole('img');
      expect(indicator.style.background).toContain('#6b7280');
    });
  });

  describe('Custom Styling', () => {
    test('applies custom className', () => {
      render(
        <AccessibilitySafetyIndicator 
          level="safe" 
          variant="symbol" 
          className="custom-class" 
        />
      );
      const indicator = screen.getByRole('img');
      expect(indicator).toHaveClass('custom-class');
    });

    test('combines custom className with default classes', () => {
      render(
        <AccessibilitySafetyIndicator 
          level="caution" 
          variant="text" 
          className="extra-padding" 
        />
      );
      const indicator = screen.getByRole('status');
      expect(indicator).toHaveClass('extra-padding', 'font-mono', 'font-bold');
    });
  });

  describe('Performance', () => {
    test('renders efficiently without unnecessary re-renders', () => {
      const { rerender } = render(
        <AccessibilitySafetyIndicator level="safe" variant="icon" />
      );
      
      // Change only size prop
      rerender(<AccessibilitySafetyIndicator level="safe" variant="icon" size="lg" />);
      
      // Should still be in document and accessible
      const indicator = screen.getByRole('img');
      expect(indicator).toBeInTheDocument();
      expect(indicator).toHaveAttribute('aria-label', 'Safety level: SAFE');
    });
  });
});