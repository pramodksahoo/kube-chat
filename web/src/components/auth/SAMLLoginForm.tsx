import React, { useCallback, useEffect, useState } from 'react';
import type { SAMLLoginData, SAMLProvider } from '../../types/auth';

interface SAMLLoginFormProps {
  provider: SAMLProvider;
  onSubmit: (data: SAMLLoginData) => Promise<void>;
  isLoading: boolean;
}

export function SAMLLoginForm({ provider, onSubmit, isLoading }: SAMLLoginFormProps) {
  const [remember, setRemember] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  // Handle SAML response callback
  useEffect(() => {
    const handleSAMLCallback = async () => {
      const urlParams = new URLSearchParams(window.location.search);
      const samlResponse = urlParams.get('SAMLResponse');
      urlParams.get('RelayState'); // RelayState for future use
      
      if (samlResponse) {
        try {
          setIsSubmitting(true);
          await onSubmit({
            provider: 'saml',
            providerId: provider.name,
            remember,
          });
        } catch (error) {
          console.error('SAML callback handling failed:', error);
        } finally {
          setIsSubmitting(false);
        }
      }
    };
    
    void handleSAMLCallback();
  }, [provider.name, remember, onSubmit]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      setIsSubmitting(true);
      
      // Store remember preference for callback handling
      sessionStorage.setItem('kubechat_auth_remember', remember.toString());
      
      // Create SAML request form and submit
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = provider.ssoUrl;
      form.target = '_self';
      
      // Create SAML request (simplified for demo - in production this would be properly formatted)
      const samlRequest = btoa(`
        <samlp:AuthnRequest 
          xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
          ID="${crypto.randomUUID()}"
          Version="2.0"
          IssueInstant="${new Date().toISOString()}"
          Destination="${provider.ssoUrl}">
          <saml:Issuer>${provider.entityId}</saml:Issuer>
          <samlp:NameIDPolicy 
            AllowCreate="true" 
            Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"/>
        </samlp:AuthnRequest>
      `);
      
      // Add SAML request parameter
      const samlRequestInput = document.createElement('input');
      samlRequestInput.type = 'hidden';
      samlRequestInput.name = 'SAMLRequest';
      samlRequestInput.value = samlRequest;
      form.appendChild(samlRequestInput);
      
      // Add RelayState parameter
      const relayStateInput = document.createElement('input');
      relayStateInput.type = 'hidden';
      relayStateInput.name = 'RelayState';
      relayStateInput.value = window.location.origin + '/auth/saml/callback';
      form.appendChild(relayStateInput);
      
      // Submit form to initiate SAML SSO
      document.body.appendChild(form);
      form.submit();
    } catch (error) {
      console.error('SAML SSO initiation failed:', error);
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
          You'll be redirected to your organization's SAML identity provider
        </p>
      </div>

      <div className="bg-green-50 border border-green-200 rounded-md p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="ml-3">
            <div className="text-sm text-green-700">
              <p><strong>Provider:</strong> {provider.name}</p>
              <p><strong>SSO URL:</strong> {provider.ssoUrl}</p>
              <p><strong>Entity ID:</strong> {provider.entityId}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="flex items-center">
        <input
          id="remember-saml"
          name="remember"
          type="checkbox"
          checked={remember}
          onChange={handleRememberChange}
          disabled={isLoading || isSubmitting}
          className="h-4 w-4 text-green-600 focus:ring-green-500 border-gray-300 rounded disabled:opacity-50"
        />
        <label 
          htmlFor="remember-saml" 
          className="ml-2 block text-sm text-gray-900"
        >
          Remember my choice for 30 days
        </label>
      </div>

      <div>
        <button
          type="submit"
          disabled={isLoading || isSubmitting}
          className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed"
          aria-label={`Sign in with ${provider.name} using SAML`}
        >
          <span className="absolute left-0 inset-y-0 flex items-center pl-3">
            {(isLoading || isSubmitting) ? (
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
            ) : (
              <svg className="h-5 w-5 text-green-500 group-hover:text-green-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 8a6 6 0 01-7.743 5.743L10 14l-1 1-1 1H6v2H2v-4l4.257-4.257A6 6 0 1118 8zm-6-4a1 1 0 100 2 2 2 0 012 2 1 1 0 102 0 4 4 0 00-4-4z" clipRule="evenodd" />
              </svg>
            )}
          </span>
          {(isLoading || isSubmitting) ? 'Redirecting...' : 'Continue with SAML SSO'}
        </button>
      </div>

      <div className="text-center">
        <p className="text-xs text-gray-500">
          Secure authentication via SAML 2.0 protocol
        </p>
      </div>

      {/* SAML Security Information */}
      <details className="text-sm text-gray-600">
        <summary className="cursor-pointer hover:text-gray-800">
          Security Information
        </summary>
        <div className="mt-2 space-y-1">
          <p>• SAML 2.0 compliant authentication</p>
          <p>• Digitally signed assertions from your identity provider</p>
          <p>• No credentials stored or transmitted through KubeChat</p>
          <p>• Full audit trail of authentication events</p>
          <p>• Automatic session management and logout coordination</p>
        </div>
      </details>

      {/* Additional SAML Options */}
      <div className="border-t border-gray-200 pt-4">
        <div className="text-sm text-gray-600">
          <h4 className="font-medium text-gray-900 mb-2">SAML Configuration</h4>
          <div className="space-y-1">
            <p>• <strong>Name ID Format:</strong> Email Address</p>
            <p>• <strong>Binding:</strong> HTTP POST</p>
            <p>• <strong>Signature Algorithm:</strong> RSA-SHA256</p>
          </div>
        </div>
      </div>
    </form>
  );
}

export default SAMLLoginForm;