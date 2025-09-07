import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { MFAChallenge as MFAChallengeType, MFAResponse } from '../../types/auth';

interface MFAChallengeProps {
  challenge?: MFAChallengeType;
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

export function MFAChallenge({ challenge, onSuccess, onError }: MFAChallengeProps) {
  const [currentChallenge, setCurrentChallenge] = useState<MFAChallengeType | null>(challenge || null);
  const [code, setCode] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const codeInputRef = useRef<HTMLInputElement>(null);

  // Load challenge if not provided
  useEffect(() => {
    if (!challenge) {
      const loadChallenge = async () => {
        try {
          const response = await fetch('/api/v1/auth/mfa/challenge', {
            method: 'GET',
            credentials: 'include',
          });

          if (response.ok) {
            const challengeData = await response.json();
            setCurrentChallenge(challengeData);
          } else {
            setError('Failed to load MFA challenge');
          }
        } catch {
          setError('Failed to connect to authentication service');
        }
      };

      void loadChallenge();
    }
  }, [challenge]);

  // Timer for challenge expiration
  useEffect(() => {
    if (!currentChallenge?.expiresAt) return;

    const updateTimer = () => {
      const now = new Date().getTime();
      const expiry = new Date(currentChallenge.expiresAt).getTime();
      const remaining = Math.max(0, Math.floor((expiry - now) / 1000));
      
      setTimeRemaining(remaining);
      
      if (remaining === 0) {
        setError('Challenge expired. Please try again.');
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    
    return () => clearInterval(interval);
  }, [currentChallenge]);

  // Auto-focus code input
  useEffect(() => {
    if (currentChallenge && codeInputRef.current) {
      codeInputRef.current.focus();
    }
  }, [currentChallenge]);

  const handleCodeChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, ''); // Only allow digits
    setCode(value);
    setError(null);
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!currentChallenge || !code.trim()) {
      setError('Please enter the verification code');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      
      const mfaResponse: MFAResponse = {
        challengeId: currentChallenge.id,
        code: code.trim(),
      };

      const response = await fetch('/api/v1/auth/mfa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(mfaResponse),
      });

      if (response.ok) {
        onSuccess?.();
      } else {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.message || 'Invalid verification code';
        setError(errorMessage);
        setRetryCount(prev => prev + 1);
        setCode(''); // Clear code on error
      }
    } catch {
      setError('Failed to verify code. Please try again.');
      onError?.('MFA verification failed');
    } finally {
      setIsSubmitting(false);
    }
  }, [currentChallenge, code, onSuccess, onError]);

  const handleResendChallenge = useCallback(async () => {
    try {
      setIsSubmitting(true);
      setError(null);
      
      const response = await fetch('/api/v1/auth/mfa/resend', {
        method: 'POST',
        credentials: 'include',
      });

      if (response.ok) {
        const newChallenge = await response.json();
        setCurrentChallenge(newChallenge);
        setCode('');
        setRetryCount(0);
      } else {
        setError('Failed to resend challenge. Please try again.');
      }
    } catch {
      setError('Failed to resend challenge.');
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  const handlePushApproval = useCallback(async () => {
    if (currentChallenge?.type !== 'push') return;

    try {
      setIsSubmitting(true);
      setError(null);
      
      const mfaResponse: MFAResponse = {
        challengeId: currentChallenge.id,
        approved: true,
      };

      const response = await fetch('/api/v1/auth/mfa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(mfaResponse),
      });

      if (response.ok) {
        onSuccess?.();
      } else {
        setError('Push notification approval failed');
      }
    } catch {
      setError('Failed to process push notification approval');
    } finally {
      setIsSubmitting(false);
    }
  }, [currentChallenge, onSuccess]);

  const formatTimeRemaining = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  if (!currentChallenge) {
    return (
      <div className="text-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
        <p className="text-gray-600">Loading multi-factor authentication...</p>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto">
      <div className="text-center mb-6">
        <div className="mx-auto h-12 w-12 bg-blue-100 rounded-full flex items-center justify-center mb-4">
          <svg className="h-6 w-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-gray-900">Multi-Factor Authentication</h2>
        <p className="mt-2 text-sm text-gray-600">{currentChallenge.message}</p>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-md">
          <div className="flex">
            <svg className="h-5 w-5 text-red-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
            <p className="ml-2 text-sm text-red-700">{error}</p>
          </div>
        </div>
      )}

      {timeRemaining !== null && timeRemaining > 0 && (
        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
          <div className="flex items-center">
            <svg className="h-5 w-5 text-yellow-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clipRule="evenodd" />
            </svg>
            <p className="text-sm text-yellow-700">
              Code expires in: <strong>{formatTimeRemaining(timeRemaining)}</strong>
            </p>
          </div>
        </div>
      )}

      {/* TOTP/SMS Code Input */}
      {(currentChallenge.type === 'totp' || currentChallenge.type === 'sms') && (
        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div>
            <label htmlFor="mfa-code" className="sr-only">
              Verification code
            </label>
            <input
              ref={codeInputRef}
              id="mfa-code"
              name="mfa-code"
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={8}
              value={code}
              onChange={handleCodeChange}
              placeholder="Enter verification code"
              disabled={isSubmitting}
              className="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm text-center tracking-widest font-mono disabled:opacity-50"
              autoComplete="one-time-code"
            />
            {currentChallenge.type === 'sms' && currentChallenge.phoneNumber && (
              <p className="mt-1 text-xs text-gray-500 text-center">
                Sent to {currentChallenge.phoneNumber}
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={isSubmitting || !code.trim() || (timeRemaining !== null && timeRemaining === 0)}
            className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
            ) : (
              'Verify Code'
            )}
          </button>
        </form>
      )}

      {/* Push Notification */}
      {currentChallenge.type === 'push' && (
        <div className="space-y-4 text-center">
          <div className="p-4 bg-blue-50 rounded-md">
            <p className="text-sm text-blue-700">
              Check your mobile device for a push notification and approve the login request.
            </p>
          </div>
          
          <button
            onClick={() => void handlePushApproval()}
            disabled={isSubmitting}
            className="w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {isSubmitting ? (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
            ) : (
              'I approved on my device'
            )}
          </button>
        </div>
      )}

      {/* QR Code for TOTP setup */}
      {currentChallenge.type === 'totp' && currentChallenge.qrCode && (
        <div className="mt-6 text-center">
          <h3 className="text-sm font-medium text-gray-900 mb-2">Scan QR Code</h3>
          <div className="bg-white p-4 rounded-md border inline-block">
            <img 
              src={currentChallenge.qrCode} 
              alt="TOTP QR Code"
              className="w-32 h-32"
            />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Scan with your authenticator app
          </p>
        </div>
      )}

      {/* Resend/Help Options */}
      <div className="mt-6 text-center space-y-2">
        {(currentChallenge.type === 'sms' || currentChallenge.type === 'email') && (
          <button
            onClick={() => void handleResendChallenge()}
            disabled={isSubmitting}
            className="text-sm text-blue-600 hover:text-blue-500 disabled:opacity-50"
          >
            Resend code
          </button>
        )}
        
        <div className="text-xs text-gray-500">
          {retryCount > 0 && (
            <p>Failed attempts: {retryCount}/3</p>
          )}
          <p>Having trouble? Contact your administrator for assistance.</p>
        </div>
      </div>
    </div>
  );
}

export default MFAChallenge;