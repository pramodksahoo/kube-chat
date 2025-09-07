import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LoginPage } from '../LoginPage';

// Mock the authentication hook
const mockLogin = jest.fn();
const mockClearError = jest.fn();

jest.mock('../../../hooks/useAuthentication', () => ({
  useAuthentication: () => ({
    login: mockLogin,
    isLoading: false,
    error: null,
    clearError: mockClearError,
  }),
}));

describe('LoginPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders login page with provider options', () => {
    render(<LoginPage />);
    
    expect(screen.getByRole('heading', { name: /welcome to kubechat/i })).toBeInTheDocument();
    expect(screen.getByText(/secure kubernetes management/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /oidc provider/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /saml provider/i })).toBeInTheDocument();
  });

  it('switches to OIDC login form when OIDC provider is selected', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    
    await user.click(screen.getByRole('button', { name: /oidc provider/i }));
    
    expect(screen.getByText(/oidc authentication/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/provider identifier/i)).toBeInTheDocument();
  });

  it('switches to SAML login form when SAML provider is selected', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    
    await user.click(screen.getByRole('button', { name: /saml provider/i }));
    
    expect(screen.getByText(/saml single sign-on/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/provider identifier/i)).toBeInTheDocument();
  });

  it('shows loading state during authentication', () => {
    jest.mocked(require('../../../hooks/useAuthentication').useAuthentication).mockReturnValue({
      login: mockLogin,
      isLoading: true,
      error: null,
      clearError: mockClearError,
    });

    render(<LoginPage />);
    
    expect(screen.getByText(/signing in/i)).toBeInTheDocument();
  });

  it('displays authentication error when present', () => {
    const mockError = {
      code: 'LOGIN_FAILED',
      message: 'Invalid credentials',
      timestamp: '2024-01-01T10:00:00Z',
      retryable: true,
    };

    jest.mocked(require('../../../hooks/useAuthentication').useAuthentication).mockReturnValue({
      login: mockLogin,
      isLoading: false,
      error: mockError,
      clearError: mockClearError,
    });

    render(<LoginPage />);
    
    expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /dismiss/i })).toBeInTheDocument();
  });

  it('clears error when dismiss button is clicked', async () => {
    const user = userEvent.setup();
    const mockError = {
      code: 'LOGIN_FAILED',
      message: 'Invalid credentials',
      timestamp: '2024-01-01T10:00:00Z',
      retryable: true,
    };

    jest.mocked(require('../../../hooks/useAuthentication').useAuthentication).mockReturnValue({
      login: mockLogin,
      isLoading: false,
      error: mockError,
      clearError: mockClearError,
    });

    render(<LoginPage />);
    
    await user.click(screen.getByRole('button', { name: /dismiss/i }));
    
    expect(mockClearError).toHaveBeenCalled();
  });

  it('shows back button when a provider is selected', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    
    await user.click(screen.getByRole('button', { name: /oidc provider/i }));
    
    expect(screen.getByRole('button', { name: /back to provider selection/i })).toBeInTheDocument();
  });

  it('returns to provider selection when back button is clicked', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    
    // Select OIDC provider
    await user.click(screen.getByRole('button', { name: /oidc provider/i }));
    expect(screen.getByText(/oidc authentication/i)).toBeInTheDocument();
    
    // Click back button
    await user.click(screen.getByRole('button', { name: /back to provider selection/i }));
    
    // Should be back to provider selection
    expect(screen.getByRole('button', { name: /oidc provider/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /saml provider/i })).toBeInTheDocument();
  });

  it('has proper accessibility attributes', () => {
    render(<LoginPage />);
    
    const main = screen.getByRole('main');
    expect(main).toHaveAttribute('aria-label', 'Authentication');
    
    const heading = screen.getByRole('heading', { name: /welcome to kubechat/i });
    expect(heading).toBeInTheDocument();
  });

  it('handles keyboard navigation properly', async () => {
    const user = userEvent.setup();
    render(<LoginPage />);
    
    const oidcButton = screen.getByRole('button', { name: /oidc provider/i });
    const samlButton = screen.getByRole('button', { name: /saml provider/i });
    
    // Tab to first button
    await user.tab();
    expect(oidcButton).toHaveFocus();
    
    // Tab to second button
    await user.tab();
    expect(samlButton).toHaveFocus();
    
    // Enter should activate the button
    await user.keyboard('{Enter}');
    expect(screen.getByText(/saml single sign-on/i)).toBeInTheDocument();
  });
});