/**
 * API Configuration
 * Dynamically handles API routing for both localhost development and production
 */

// Detect if we're in development mode with port forwards
const isLocalDevelopment = (): boolean => {
  return (
    window.location.hostname === 'localhost' || 
    window.location.hostname === '127.0.0.1' ||
    window.location.hostname.includes('localhost')
  );
};

// Get the appropriate API Gateway URL
const getApiGatewayUrl = (): string => {
  if (isLocalDevelopment()) {
    // In localhost development, route to API Gateway on port 8080
    return `${window.location.protocol}//${window.location.hostname}:8080`;
  } else {
    // In production, API calls go through the same host but are proxied by ingress
    // The ingress will route /api/* to the API Gateway service
    return window.location.origin;
  }
};

// Get the appropriate WebSocket URL  
const getWebSocketUrl = (): string => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  
  if (isLocalDevelopment()) {
    // In localhost development, WebSocket connects directly to API Gateway
    return `${wsProtocol}//${window.location.hostname}:8080`;
  } else {
    // In production, WebSocket goes through the same host
    return `${wsProtocol}//${window.location.host}`;
  }
};

export const API_CONFIG = {
  // Base URLs
  BASE_URL: getApiGatewayUrl(),
  
  // Specific API endpoints - all routed through API Gateway
  AUTH: `${getApiGatewayUrl()}/api/v1/auth`,
  KUBERNETES: `${getApiGatewayUrl()}/api/k8s`, 
  API_V1: `${getApiGatewayUrl()}/api/v1`,
  CHAT: `${getApiGatewayUrl()}/api/v1/chat`,
  AUDIT: `${getApiGatewayUrl()}/api/v1/audit`,
  
  // WebSocket URL
  WEBSOCKET_BASE: getWebSocketUrl(),
  
  // Environment detection
  IS_DEVELOPMENT: isLocalDevelopment(),
  
  // Helper to get full WebSocket URL with session ID
  getWebSocketUrl: (sessionId: string): string => {
    return `${getWebSocketUrl()}/ws/chat/${sessionId}`;
  },
  
  // Helper to get API endpoint
  getApiUrl: (path: string): string => {
    return `${getApiGatewayUrl()}${path.startsWith('/') ? path : `/${path}`}`;
  }
} as const;

export default API_CONFIG;