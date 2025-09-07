/**
 * Tests for ResourceStatusIndicator component
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ResourceStatusIndicator } from '../ResourceStatusIndicator';

describe('ResourceStatusIndicator', () => {
  describe('Ready Status', () => {
    it('should render Ready status with full label and icon', () => {
      render(<ResourceStatusIndicator status="Ready" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toBeInTheDocument();
      expect(indicator).toHaveAttribute('aria-label', 'Status: Ready');
      
      expect(screen.getByText('✓')).toBeInTheDocument();
      expect(screen.getByText('Ready')).toBeInTheDocument();
    });

    it('should apply correct styling for Ready status', () => {
      render(<ResourceStatusIndicator status="Ready" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveClass('text-green-700', 'bg-green-100', 'border-green-200');
    });
  });

  describe('Warning Status', () => {
    it('should render Warning status with full label and icon', () => {
      render(<ResourceStatusIndicator status="Warning" />);

      const indicator = screen.getByTestId('status-indicator-warning');
      expect(indicator).toBeInTheDocument();
      expect(indicator).toHaveAttribute('aria-label', 'Status: Warning');
      
      expect(screen.getByText('⚠')).toBeInTheDocument();
      expect(screen.getByText('Warning')).toBeInTheDocument();
    });

    it('should apply correct styling for Warning status', () => {
      render(<ResourceStatusIndicator status="Warning" />);

      const indicator = screen.getByTestId('status-indicator-warning');
      expect(indicator).toHaveClass('text-yellow-700', 'bg-yellow-100', 'border-yellow-200');
    });
  });

  describe('Error Status', () => {
    it('should render Error status with full label and icon', () => {
      render(<ResourceStatusIndicator status="Error" />);

      const indicator = screen.getByTestId('status-indicator-error');
      expect(indicator).toBeInTheDocument();
      expect(indicator).toHaveAttribute('aria-label', 'Status: Error');
      
      expect(screen.getByText('✗')).toBeInTheDocument();
      expect(screen.getByText('Error')).toBeInTheDocument();
    });

    it('should apply correct styling for Error status', () => {
      render(<ResourceStatusIndicator status="Error" />);

      const indicator = screen.getByTestId('status-indicator-error');
      expect(indicator).toHaveClass('text-red-700', 'bg-red-100', 'border-red-200');
    });
  });

  describe('Unknown Status', () => {
    it('should render Unknown status with full label and icon', () => {
      render(<ResourceStatusIndicator status="Unknown" />);

      const indicator = screen.getByTestId('status-indicator-unknown');
      expect(indicator).toBeInTheDocument();
      expect(indicator).toHaveAttribute('aria-label', 'Status: Unknown');
      
      expect(screen.getByText('?')).toBeInTheDocument();
      expect(screen.getByText('Unknown')).toBeInTheDocument();
    });

    it('should apply correct styling for Unknown status', () => {
      render(<ResourceStatusIndicator status="Unknown" />);

      const indicator = screen.getByTestId('status-indicator-unknown');
      expect(indicator).toHaveClass('text-gray-700', 'bg-gray-100', 'border-gray-200');
    });
  });

  describe('Size Variations', () => {
    it('should render small size correctly', () => {
      render(<ResourceStatusIndicator status="Ready" size="sm" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveClass('text-xs', 'px-2', 'py-1');
    });

    it('should render medium size correctly (default)', () => {
      render(<ResourceStatusIndicator status="Ready" size="md" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveClass('text-sm', 'px-3', 'py-1.5');
    });

    it('should render large size correctly', () => {
      render(<ResourceStatusIndicator status="Ready" size="lg" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveClass('text-base', 'px-4', 'py-2');
    });

    it('should use medium size by default', () => {
      render(<ResourceStatusIndicator status="Ready" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveClass('text-sm', 'px-3', 'py-1.5');
    });
  });

  describe('Display Options', () => {
    it('should show only icon when showLabel=false and showIcon=true', () => {
      render(<ResourceStatusIndicator status="Ready" showLabel={false} showIcon={true} />);

      const indicator = screen.getByTestId('status-icon-ready');
      expect(indicator).toBeInTheDocument();
      
      expect(screen.getByText('✓')).toBeInTheDocument();
      expect(screen.queryByText('Ready')).not.toBeInTheDocument();
    });

    it('should show only dot when showLabel=false and showIcon=false', () => {
      render(<ResourceStatusIndicator status="Ready" showLabel={false} showIcon={false} />);

      const dot = screen.getByTestId('status-dot-ready');
      expect(dot).toBeInTheDocument();
      expect(dot).toHaveClass('bg-green-500');
      
      expect(screen.queryByText('✓')).not.toBeInTheDocument();
      expect(screen.queryByText('Ready')).not.toBeInTheDocument();
    });

    it('should show label without icon when showIcon=false', () => {
      render(<ResourceStatusIndicator status="Ready" showIcon={false} />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toBeInTheDocument();
      
      expect(screen.queryByText('✓')).not.toBeInTheDocument();
      expect(screen.getByText('Ready')).toBeInTheDocument();
    });

    it('should show both label and icon by default', () => {
      render(<ResourceStatusIndicator status="Ready" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toBeInTheDocument();
      
      expect(screen.getByText('✓')).toBeInTheDocument();
      expect(screen.getByText('Ready')).toBeInTheDocument();
    });
  });

  describe('Pulse Animation', () => {
    it('should apply pulse animation when pulse=true', () => {
      render(<ResourceStatusIndicator status="Ready" pulse={true} />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveClass('animate-pulse');
    });

    it('should not apply pulse animation by default', () => {
      render(<ResourceStatusIndicator status="Ready" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).not.toHaveClass('animate-pulse');
    });

    it('should apply pulse to dot indicator', () => {
      render(<ResourceStatusIndicator status="Ready" showLabel={false} showIcon={false} pulse={true} />);

      const dot = screen.getByTestId('status-dot-ready');
      expect(dot).toHaveClass('animate-pulse');
    });

    it('should apply pulse to icon indicator', () => {
      render(<ResourceStatusIndicator status="Ready" showLabel={false} showIcon={true} pulse={true} />);

      const indicator = screen.getByTestId('status-icon-ready');
      expect(indicator).toHaveClass('animate-pulse');
    });
  });

  describe('Custom Styling', () => {
    it('should apply custom className', () => {
      render(<ResourceStatusIndicator status="Ready" className="custom-class" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveClass('custom-class');
    });

    it('should apply custom className to dot indicator', () => {
      render(<ResourceStatusIndicator status="Ready" showLabel={false} showIcon={false} className="custom-class" />);

      const dot = screen.getByTestId('status-dot-ready');
      expect(dot).toHaveClass('custom-class');
    });
  });

  describe('Accessibility', () => {
    it('should have proper role and aria-label for full indicator', () => {
      render(<ResourceStatusIndicator status="Ready" />);

      const indicator = screen.getByTestId('status-indicator-ready');
      expect(indicator).toHaveAttribute('role', 'img');
      expect(indicator).toHaveAttribute('aria-label', 'Status: Ready');
    });

    it('should have proper role and aria-label for icon-only indicator', () => {
      render(<ResourceStatusIndicator status="Warning" showLabel={false} />);

      const indicator = screen.getByTestId('status-icon-warning');
      expect(indicator).toHaveAttribute('role', 'img');
      expect(indicator).toHaveAttribute('aria-label', 'Status: Warning');
    });

    it('should have proper role and aria-label for dot indicator', () => {
      render(<ResourceStatusIndicator status="Error" showLabel={false} showIcon={false} />);

      const dot = screen.getByTestId('status-dot-error');
      expect(dot).toHaveAttribute('role', 'img');
      expect(dot).toHaveAttribute('aria-label', 'Status: Error');
    });

    it('should mark icons as aria-hidden', () => {
      render(<ResourceStatusIndicator status="Ready" />);

      const icon = screen.getByText('✓');
      expect(icon).toHaveAttribute('aria-hidden', 'true');
    });
  });

  describe('Dot Size Variations', () => {
    it('should render correct dot size for small', () => {
      render(<ResourceStatusIndicator status="Ready" size="sm" showLabel={false} showIcon={false} />);

      const dot = screen.getByTestId('status-dot-ready');
      expect(dot).toHaveClass('w-2', 'h-2');
    });

    it('should render correct dot size for medium', () => {
      render(<ResourceStatusIndicator status="Ready" size="md" showLabel={false} showIcon={false} />);

      const dot = screen.getByTestId('status-dot-ready');
      expect(dot).toHaveClass('w-3', 'h-3');
    });

    it('should render correct dot size for large', () => {
      render(<ResourceStatusIndicator status="Ready" size="lg" showLabel={false} showIcon={false} />);

      const dot = screen.getByTestId('status-dot-ready');
      expect(dot).toHaveClass('w-4', 'h-4');
    });
  });

  describe('All Status Dot Colors', () => {
    it('should use correct dot colors for all statuses', () => {
      const { rerender } = render(<ResourceStatusIndicator status="Ready" showLabel={false} showIcon={false} />);
      expect(screen.getByTestId('status-dot-ready')).toHaveClass('bg-green-500');

      rerender(<ResourceStatusIndicator status="Warning" showLabel={false} showIcon={false} />);
      expect(screen.getByTestId('status-dot-warning')).toHaveClass('bg-yellow-500');

      rerender(<ResourceStatusIndicator status="Error" showLabel={false} showIcon={false} />);
      expect(screen.getByTestId('status-dot-error')).toHaveClass('bg-red-500');

      rerender(<ResourceStatusIndicator status="Unknown" showLabel={false} showIcon={false} />);
      expect(screen.getByTestId('status-dot-unknown')).toHaveClass('bg-gray-500');
    });
  });
});