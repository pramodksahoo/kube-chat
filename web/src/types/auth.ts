// Authentication Types

interface AuthenticationState {
  isAuthenticated: boolean;
  user: User | null;
  token: string | null;
  tokenExpiry: Date | null;
  provider: 'oidc' | 'saml' | null;
  mfaRequired: boolean;
  sessionId: string | null;
}

interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  groups: string[];
  preferences: UserPreferences;
}

interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  language: string;
  timezone: string;
  dashboardLayout: DashboardLayout;
  notifications: NotificationSettings;
}

interface DashboardLayout {
  sidebar: {
    collapsed: boolean;
    width: number;
  };
  panels: {
    chat: {
      visible: boolean;
      position: 'left' | 'center' | 'right';
    };
    resources: {
      visible: boolean;
      position: 'left' | 'center' | 'right';
    };
    commands: {
      visible: boolean;
      position: 'top' | 'bottom';
    };
  };
}

interface NotificationSettings {
  enabled: boolean;
  email: boolean;
  push: boolean;
  sound: boolean;
  sessionWarnings: boolean;
  commandResults: boolean;
  systemAlerts: boolean;
}

interface SessionInfo {
  id: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivity: Date;
  ipAddress: string;
  userAgent: string;
}

interface OIDCProvider {
  name: string;
  issuer: string;
  clientId: string;
  scopes: string[];
  redirectUri: string;
}

interface SAMLProvider {
  name: string;
  ssoUrl: string;
  certificate: string;
  entityId: string;
}

// MFA Types
interface MFAChallenge {
  id: string;
  type: 'totp' | 'sms' | 'push' | 'email';
  message: string;
  qrCode?: string;
  phoneNumber?: string;
  email?: string;
  expiresAt: Date;
}

interface MFAResponse {
  challengeId: string;
  code?: string;
  approved?: boolean;
}

// Authentication Error Types
interface AuthError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp: string;
  retryable: boolean;
}

// Login Form Types
interface LoginFormData {
  provider: string;
  remember: boolean;
}

interface OIDCLoginData extends LoginFormData {
  provider: 'oidc';
  providerId: string;
}

interface SAMLLoginData extends LoginFormData {
  provider: 'saml';
  providerId: string;
}

// Session Events
type SessionEvent = 
  | 'session_started'
  | 'session_renewed' 
  | 'session_warning'
  | 'session_expired'
  | 'session_ended';

interface SessionEventData {
  event: SessionEvent;
  sessionId: string;
  userId: string;
  timestamp: Date;
  data?: Record<string, unknown>;
}

// Rate Limiting State
interface RateLimitingState {
  attempts: number;
  lastAttempt: Date | null;
  lockoutUntil: Date | null;
}

// Auth Store State
interface AuthStoreState extends AuthenticationState {
  isLoading: boolean;
  error: AuthError | null;
  lastActivity: Date | null;
  _rateLimiting: RateLimitingState;
}

// Session Store State  
interface SessionStoreState {
  currentSession: SessionInfo | null;
  isMonitoring: boolean;
  warningShown: boolean;
  timeRemaining: number | null;
  error: string | null;
}

// Preferences Store State
interface PreferencesStoreState {
  preferences: UserPreferences;
  isLoading: boolean;
  error: string | null;
  hasUnsavedChanges: boolean;
}

// Export all types
export type {
  AuthenticationState,
  User,
  UserPreferences,
  DashboardLayout,
  NotificationSettings,
  SessionInfo,
  OIDCProvider,
  SAMLProvider,
  MFAChallenge,
  MFAResponse,
  AuthError,
  LoginFormData,
  OIDCLoginData,
  SAMLLoginData,
  SessionEvent,
  SessionEventData,
  RateLimitingState,
  AuthStoreState,
  SessionStoreState,
  PreferencesStoreState,
};