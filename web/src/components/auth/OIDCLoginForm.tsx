import React, { useCallback, useEffect, useState } from 'react';
import type { OIDCLoginData, OIDCProvider } from '../../types/auth';

interface OIDCLoginFormProps {
  provider: OIDCProvider;
  onSubmit: (data: OIDCLoginData) => Promise<void>;
  isLoading: boolean;
}

export function OIDCLoginForm({ provider, onSubmit, isLoading }: OIDCLoginFormProps) {
  const [remember, setRemember] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  // Handle URL callback parameters for OIDC flow
  useEffect(() => {
    const handleOIDCCallback = async () => {
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get('code');
      const state = urlParams.get('state');
      const error = urlParams.get('error');
      
      if (error) {
        console.error('OIDC error:', error, urlParams.get('error_description'));
        return;
      }
      
      if (code && state) {
        try {
          setIsSubmitting(true);
          await onSubmit({
            provider: 'oidc',
            providerId: provider.name,
            remember,
          });
        } catch (error) {
          console.error('OIDC callback handling failed:', error);
        } finally {
          setIsSubmitting(false);
        }
      }
    };
    
    void handleOIDCCallback();
  }, [provider.name, remember, onSubmit]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      setIsSubmitting(true);
      
      // For OIDC, we need to redirect to the authorization server
      const authUrl = new URL(provider.issuer + '/auth');
      authUrl.searchParams.set('client_id', provider.clientId);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', provider.scopes.join(' '));
      authUrl.searchParams.set('redirect_uri', provider.redirectUri);
      authUrl.searchParams.set('state', crypto.randomUUID());
      
      // Store remember preference for callback handling
      sessionStorage.setItem('kubechat_auth_remember', remember.toString());
      
      // Redirect to OIDC provider
      window.location.href = authUrl.toString();
    } catch (error) {
      console.error('OIDC login initiation failed:', error);
      setIsSubmitting(false);
    }
  }, [provider, remember]);

  const handleRememberChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setRemember(e.target.checked);
  }, []);

  return (
    <form onSubmit={(e) => void handleSubmit(e)} className="space-y-6">
      <div className="text-center">
        <h3 className="text-lg font-medium text-gray-900">
          Sign in with {provider.name}
        </h3>
        <p className="mt-2 text-sm text-gray-600">
          You'll be redirected to your organization's login page
        </p>
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <svg className="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="ml-3">
            <div className="text-sm text-blue-700">
              <p><strong>Provider:</strong> {provider.issuer}</p>
              <p><strong>Scopes:</strong> {provider.scopes.join(', ')}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="flex items-center">
        <input
          id="remember-oidc"
          name="remember"
          type="checkbox"
          checked={remember}
          onChange={handleRememberChange}
          disabled={isLoading || isSubmitting}
          className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded disabled:opacity-50"
        />
        <label 
          htmlFor="remember-oidc" 
          className="ml-2 block text-sm text-gray-900"
        >
          Remember my choice for 30 days
        </label>
      </div>

      <div>
        <button
          type="submit"
          disabled={isLoading || isSubmitting}
          className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          aria-label={`Sign in with ${provider.name} using OIDC`}
        >
          <span className="absolute left-0 inset-y-0 flex items-center pl-3">
            {(isLoading || isSubmitting) ? (
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
            ) : (
              <svg className="h-5 w-5 text-blue-500 group-hover:text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
              </svg>
            )}
          </span>
          {(isLoading || isSubmitting) ? 'Redirecting...' : 'Continue with OIDC'}
        </button>
      </div>

      <div className="text-center">
        <p className="text-xs text-gray-500">
          Secure authentication via OpenID Connect protocol
        </p>
      </div>

      {/* OIDC Security Information */}
      <details className="text-sm text-gray-600">
        <summary className="cursor-pointer hover:text-gray-800">
          Security Information
        </summary>
        <div className="mt-2 space-y-1">
          <p>• Your credentials are never shared with KubeChat</p>
          <p>• Authentication is handled by your organization's identity provider</p>
          <p>• Session tokens are securely managed and automatically refreshed</p>
          <p>• All communication is encrypted using industry-standard protocols</p>
        </div>
      </details>
    </form>
  );
}

export default OIDCLoginForm;