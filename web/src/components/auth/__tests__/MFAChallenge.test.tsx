import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MFAChallenge } from '../MFAChallenge';
import type { MFAChallenge as MFAChallengeType } from '../../../types/auth';

const mockMFAChallenge: MFAChallengeType = {
  id: 'mfa-123',
  type: 'totp',
  message: 'Enter your 6-digit authentication code',
  qrCode: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAGA',
  expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes from now
};

const mockProps = {
  challenge: mockMFAChallenge,
  isLoading: false,
  error: null,
  onSubmit: jest.fn(),
  onCancel: jest.fn(),
};

describe('MFAChallenge', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('renders TOTP challenge correctly', () => {
    render(<MFAChallenge {...mockProps} />);
    
    expect(screen.getByRole('heading', { name: /multi-factor authentication/i })).toBeInTheDocument();
    expect(screen.getByText(/enter your 6-digit authentication code/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/authentication code/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /verify/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
  });

  it('renders SMS challenge correctly', () => {
    const smsChallenge: MFAChallengeType = {
      ...mockMFAChallenge,
      type: 'sms',
      phoneNumber: '+1234567890',
      message: 'Enter the code sent to your phone',
    };

    render(<MFAChallenge {...mockProps} challenge={smsChallenge} />);
    
    expect(screen.getByText(/enter the code sent to your phone/i)).toBeInTheDocument();
    expect(screen.getByText(/code sent to.*1234567890/i)).toBeInTheDocument();
  });

  it('renders push notification challenge correctly', () => {
    const pushChallenge: MFAChallengeType = {
      ...mockMFAChallenge,
      type: 'push',
      message: 'Check your mobile device for a push notification',
    };

    render(<MFAChallenge {...mockProps} challenge={pushChallenge} />);
    
    expect(screen.getByText(/check your mobile device for a push notification/i)).toBeInTheDocument();
    expect(screen.getByText(/waiting for approval/i)).toBeInTheDocument();
  });

  it('displays QR code when provided', () => {
    render(<MFAChallenge {...mockProps} />);
    
    const qrCode = screen.getByRole('img', { name: /qr code for authentication setup/i });
    expect(qrCode).toBeInTheDocument();
    expect(qrCode).toHaveAttribute('src', mockMFAChallenge.qrCode);
  });

  it('submits TOTP code correctly', async () => {
    const user = userEvent.setup();
    render(<MFAChallenge {...mockProps} />);
    
    const codeInput = screen.getByLabelText(/authentication code/i);
    const submitButton = screen.getByRole('button', { name: /verify/i });
    
    await user.type(codeInput, '123456');
    await user.click(submitButton);
    
    expect(mockProps.onSubmit).toHaveBeenCalledWith({
      challengeId: 'mfa-123',
      code: '123456',
    });
  });

  it('validates TOTP code format', async () => {
    const user = userEvent.setup();
    render(<MFAChallenge {...mockProps} />);
    
    const codeInput = screen.getByLabelText(/authentication code/i);
    const submitButton = screen.getByRole('button', { name: /verify/i });
    
    // Try with invalid code
    await user.type(codeInput, '123');
    await user.click(submitButton);
    
    expect(screen.getByText(/please enter a 6-digit code/i)).toBeInTheDocument();
    expect(mockProps.onSubmit).not.toHaveBeenCalled();
  });

  it('shows loading state during submission', () => {
    render(<MFAChallenge {...mockProps} isLoading={true} />);
    
    const submitButton = screen.getByRole('button', { name: /verifying/i });
    expect(submitButton).toBeDisabled();
    expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
  });

  it('displays error message when error occurs', () => {
    const error = 'Invalid authentication code';
    render(<MFAChallenge {...mockProps} error={error} />);
    
    expect(screen.getByText(error)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('calls onCancel when cancel button is clicked', async () => {
    const user = userEvent.setup();
    render(<MFAChallenge {...mockProps} />);
    
    await user.click(screen.getByRole('button', { name: /cancel/i }));
    
    expect(mockProps.onCancel).toHaveBeenCalled();
  });

  it('shows countdown timer', () => {
    render(<MFAChallenge {...mockProps} />);
    
    expect(screen.getByText(/expires in.*5:00/i)).toBeInTheDocument();
  });

  it('updates countdown timer', () => {
    render(<MFAChallenge {...mockProps} />);
    
    // Advance time by 1 minute
    jest.advanceTimersByTime(60000);
    
    expect(screen.getByText(/expires in.*4:00/i)).toBeInTheDocument();
  });

  it('shows expired state when challenge expires', () => {
    const expiredChallenge: MFAChallengeType = {
      ...mockMFAChallenge,
      expiresAt: new Date(Date.now() - 1000), // 1 second ago
    };

    render(<MFAChallenge {...mockProps} challenge={expiredChallenge} />);
    
    expect(screen.getByText(/challenge has expired/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /verify/i })).toBeDisabled();
  });

  it('handles keyboard input for TOTP code', async () => {
    const user = userEvent.setup();
    render(<MFAChallenge {...mockProps} />);
    
    const codeInput = screen.getByLabelText(/authentication code/i);
    
    await user.type(codeInput, '123456');
    await user.keyboard('{Enter}');
    
    expect(mockProps.onSubmit).toHaveBeenCalledWith({
      challengeId: 'mfa-123',
      code: '123456',
    });
  });

  it('has proper accessibility attributes', () => {
    render(<MFAChallenge {...mockProps} />);
    
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-labelledby');
    expect(dialog).toHaveAttribute('aria-describedby');
    
    const codeInput = screen.getByLabelText(/authentication code/i);
    expect(codeInput).toHaveAttribute('aria-required', 'true');
    expect(codeInput).toHaveAttribute('autocomplete', 'one-time-code');
  });

  it('focuses on code input when mounted', () => {
    render(<MFAChallenge {...mockProps} />);
    
    const codeInput = screen.getByLabelText(/authentication code/i);
    expect(codeInput).toHaveFocus();
  });

  it('supports auto-completion hint for OTP', () => {
    render(<MFAChallenge {...mockProps} />);
    
    const codeInput = screen.getByLabelText(/authentication code/i);
    expect(codeInput).toHaveAttribute('autocomplete', 'one-time-code');
  });
});