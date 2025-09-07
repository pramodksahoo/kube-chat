import { useCallback, useEffect, useState } from 'react';
import { OIDCLoginForm } from './OIDCLoginForm';
import { SAMLLoginForm } from './SAMLLoginForm';
import { MFAChallenge } from './MFAChallenge';
import { useAuthStore } from '../../stores/authStore';
import type { LoginFormData, OIDCProvider, SAMLProvider } from '../../types/auth';

interface LoginPageProps {
  onLoginSuccess?: () => void;
  redirectPath?: string;
}

export function LoginPage({ onLoginSuccess, redirectPath }: LoginPageProps) {
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const [availableProviders, setAvailableProviders] = useState<{
    oidc: OIDCProvider[];
    saml: SAMLProvider[];
  }>({
    oidc: [],
    saml: [],
  });
  const [isLoading, setIsLoading] = useState(true);

  const { 
    isAuthenticated, 
    mfaRequired, 
    error: authError,
    isLoading: authLoading,
    login,
    clearError
  } = useAuthStore();

  // Load available authentication providers
  useEffect(() => {
    const loadProviders = async () => {
      try {
        setIsLoading(true);
        
        const response = await fetch('/api/v1/auth/providers', {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        });

        if (response.ok) {
          const providers = await response.json();
          setAvailableProviders({
            oidc: providers.oidc || [],
            saml: providers.saml || [],
          });
        } else {
          // Fallback to demo providers for development
          setAvailableProviders({
            oidc: [
              {
                name: 'corporate-sso',
                issuer: 'https://auth.company.com',
                clientId: 'kubechat-web',
                scopes: ['openid', 'profile', 'email'],
                redirectUri: `${window.location.origin}/auth/callback`,
              }
            ],
            saml: [
              {
                name: 'enterprise-saml',
                ssoUrl: 'https://auth.company.com/saml/sso',
                certificate: 'demo-cert',
                entityId: 'kubechat',
              }
            ],
          });
        }
      } catch (error) {
        console.error('Failed to load authentication providers:', error);
        // Set empty providers on error
        setAvailableProviders({ oidc: [], saml: [] });
      } finally {
        setIsLoading(false);
      }
    };

    void loadProviders();
  }, []);

  // Handle successful authentication
  useEffect(() => {
    if (isAuthenticated && !mfaRequired) {
      onLoginSuccess?.();
      
      // Redirect to intended path or dashboard
      if (redirectPath) {
        window.location.href = redirectPath;
      }
    }
  }, [isAuthenticated, mfaRequired, onLoginSuccess, redirectPath]);

  const handleProviderSelect = useCallback((providerId: string) => {
    setSelectedProvider(providerId);
    clearError();
  }, [clearError]);

  const handleBackToProviders = useCallback(() => {
    setSelectedProvider(null);
    clearError();
  }, [clearError]);

  const handleLoginSubmit = useCallback(async (formData: LoginFormData) => {
    try {
      await login(formData);
    } catch (error) {
      // Error handling is managed by the auth store
      console.error('Login failed:', error);
    }
  }, [login]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading authentication providers...</p>
        </div>
      </div>
    );
  }

  // Show MFA challenge if required
  if (mfaRequired) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full space-y-8">
          <MFAChallenge onSuccess={onLoginSuccess} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="mx-auto h-12 w-auto flex items-center justify-center">
            <img
              className="h-8 w-auto"
              src="/kubechat-logo.png"
              alt="KubeChat"
              onError={(e) => {
                // Fallback to text logo if image not found
                const target = e.target as HTMLElement;
                target.style.display = 'none';
                const textLogo = document.createElement('h1');
                textLogo.className = 'text-2xl font-bold text-blue-600';
                textLogo.textContent = 'KubeChat';
                target.parentNode?.appendChild(textLogo);
              }}
            />
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Choose your preferred authentication method
          </p>
        </div>

        {authError && (
          <div className="rounded-md bg-red-50 p-4" role="alert">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800">
                  Authentication Error
                </h3>
                <div className="mt-2 text-sm text-red-700">
                  <p>{authError.message}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {!selectedProvider ? (
          // Provider selection screen
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                Enterprise Single Sign-On
              </h3>
              
              {availableProviders.oidc.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-gray-700">OIDC Providers</h4>
                  {availableProviders.oidc.map((provider) => (
                    <button
                      key={provider.name}
                      onClick={() => handleProviderSelect(`oidc:${provider.name}`)}
                      disabled={authLoading}
                      className="w-full flex justify-center py-3 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clipRule="evenodd" />
                      </svg>
                      Sign in with {provider.name}
                    </button>
                  ))}
                </div>
              )}

              {availableProviders.saml.length > 0 && (
                <div className="space-y-2 mt-4">
                  <h4 className="text-sm font-medium text-gray-700">SAML Providers</h4>
                  {availableProviders.saml.map((provider) => (
                    <button
                      key={provider.name}
                      onClick={() => handleProviderSelect(`saml:${provider.name}`)}
                      disabled={authLoading}
                      className="w-full flex justify-center py-3 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                      </svg>
                      Sign in with {provider.name}
                    </button>
                  ))}
                </div>
              )}

              {availableProviders.oidc.length === 0 && availableProviders.saml.length === 0 && (
                <div className="text-center py-8">
                  <svg className="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                    <path d="M34 40h10v-4a6 6 0 00-10.712-3.714M34 40H14m20 0v-4a9.971 9.971 0 00-.712-3.714M14 40H4v-4a6 6 0 0110.713-3.714M14 40v-4c0-1.313.253-2.566.713-3.714m0 0A10.003 10.003 0 0124 26c4.21 0 7.813 2.602 9.288 6.286M30 14a6 6 0 11-12 0 6 6 0 0112 0zm12 6a4 4 0 11-8 0 4 4 0 018 0zm-28 0a4 4 0 11-8 0 4 4 0 018 0z" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  <h3 className="mt-2 text-sm font-medium text-gray-900">No providers configured</h3>
                  <p className="mt-1 text-sm text-gray-500">
                    Contact your administrator to set up authentication providers.
                  </p>
                </div>
              )}
            </div>
          </div>
        ) : (
          // Show specific provider login form
          <div>
            <button
              onClick={handleBackToProviders}
              className="mb-4 inline-flex items-center text-sm text-gray-500 hover:text-gray-700"
            >
              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
              </svg>
              Back to providers
            </button>
            
            {selectedProvider.startsWith('oidc:') && (
              <OIDCLoginForm
                provider={availableProviders.oidc.find(p => p.name === selectedProvider.replace('oidc:', ''))!}
                onSubmit={handleLoginSubmit}
                isLoading={authLoading}
              />
            )}
            
            {selectedProvider.startsWith('saml:') && (
              <SAMLLoginForm
                provider={availableProviders.saml.find(p => p.name === selectedProvider.replace('saml:', ''))!}
                onSubmit={handleLoginSubmit}
                isLoading={authLoading}
              />
            )}
          </div>
        )}

        <div className="text-center">
          <p className="text-xs text-gray-500">
            Secure authentication powered by enterprise identity providers
          </p>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;