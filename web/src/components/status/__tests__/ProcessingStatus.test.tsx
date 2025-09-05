import { render, screen } from '@testing-library/react';
import ProcessingStatus from '../ProcessingStatus';
import type { ProcessingState } from '../ProcessingStatus';

describe('ProcessingStatus Component', () => {
  const processingStates: ProcessingState[] = ['idle', 'processing', 'executing', 'completed', 'failed'];

  test('renders with default props', () => {
    render(<ProcessingStatus state="processing" />);
    const status = screen.getByRole('status');
    expect(status).toBeInTheDocument();
  });

  test.each(processingStates)('renders %s state correctly', (state) => {
    render(<ProcessingStatus state={state} />);
    const status = screen.getByRole('status');
    expect(status).toBeInTheDocument();
  });

  test('shows progress when provided', () => {
    render(<ProcessingStatus state="executing" progress={50} showProgress={true} />);
    expect(screen.getByText('(50%)')).toBeInTheDocument();
  });

  test('applies custom className', () => {
    render(<ProcessingStatus state="processing" className="custom-class" />);
    const status = screen.getByRole('status');
    expect(status).toHaveClass('custom-class');
  });
});