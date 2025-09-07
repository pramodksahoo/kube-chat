/**
 * AuditWrapper - HOC for automatic audit logging
 * Wraps components to automatically log user interactions and events
 */

import React, { type ComponentType, useEffect, useRef } from 'react';
import { useAuditLogging } from '../../services/auditService';
import { usePermissions } from '../auth/PermissionProvider';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface AuditConfig {
  component: string;
  logMount?: boolean;
  logUnmount?: boolean;
  logInteractions?: boolean;
  logProps?: boolean;
  excludeProps?: string[];
  customLogic?: <T extends object>(props: T) => void;
}

export function withAuditLogging<P extends object>(
  WrappedComponent: ComponentType<P>,
  config: AuditConfig
) {
  const AuditWrappedComponent = (props: P) => {
    const { user } = usePermissions();
    const { logDashboardInteraction, logError } = useAuditLogging(user || undefined);
    const mountTimeRef = useRef<Date | undefined>(undefined);
    const propsRef = useRef<P>(props);

    // Log component mount
    useEffect(() => {
      if (config.logMount) {
        mountTimeRef.current = new Date();
        logDashboardInteraction('view', {
          component: config.component,
          action: 'mount',
          timestamp: mountTimeRef.current.toISOString(),
          ...(config.logProps && !config.excludeProps?.includes('all') ? {
            props: sanitizeProps(props, config.excludeProps || [])
          } : {}),
        });
      }

      // Custom logging logic
      if (config.customLogic) {
        try {
          config.customLogic(props);
        } catch (error) {
          logError(error as Error, {
            action: `${config.component}.custom_logic`,
            details: { component: config.component },
          });
        }
      }

      return () => {
        // Log component unmount
        if (config.logUnmount && mountTimeRef.current) {
          const duration = Date.now() - mountTimeRef.current.getTime();
          logDashboardInteraction('view', {
            component: config.component,
            action: 'unmount',
            duration: Math.round(duration / 1000), // seconds
            timestamp: new Date().toISOString(),
          });
        }
      };
    }, []);

    // Log prop changes
    useEffect(() => {
      if (config.logProps && propsRef.current !== props) {
        const changedProps = getChangedProps(propsRef.current, props, config.excludeProps || []);
        
        if (Object.keys(changedProps).length > 0) {
          logDashboardInteraction('view', {
            component: config.component,
            action: 'props_changed',
            changedProps,
            timestamp: new Date().toISOString(),
          });
        }
        
        propsRef.current = props;
      }
    }, [props]);

    // Create interaction wrapper
    const createInteractionWrapper = (originalHandler: (...args: unknown[]) => void, eventName: string) => {
      return (...args: unknown[]) => {
        if (config.logInteractions) {
          logDashboardInteraction('view', {
            component: config.component,
            action: 'interaction',
            eventName,
            timestamp: new Date().toISOString(),
            args: args.length > 0 ? sanitizeArgs(args) : undefined,
          });
        }

        // Call original handler
        if (typeof originalHandler === 'function') {
          try {
            return originalHandler(...args);
          } catch (error) {
            logError(error as Error, {
              action: `${config.component}.${eventName}`,
              details: {
                component: config.component,
                eventName,
                args: sanitizeArgs(args),
              },
            });
            throw error;
          }
        }
      };
    };

    // Wrap event handlers in props
    const wrappedProps = React.useMemo(() => {
      if (!config.logInteractions) return props;

      const wrapped: any = { ...props };

      Object.keys(wrapped).forEach(key => {
        if (key.startsWith('on') && typeof wrapped[key] === 'function') {
          wrapped[key] = createInteractionWrapper(wrapped[key], key);
        }
      });

      return wrapped;
    }, [props]);

    return <WrappedComponent {...wrappedProps} />;
  };

  AuditWrappedComponent.displayName = `withAuditLogging(${WrappedComponent.displayName || WrappedComponent.name})`;

  return AuditWrappedComponent;
}

// Audit-aware resource component wrapper
export interface ResourceAuditWrapperProps {
  children: React.ReactNode;
  resource?: ResourceStatus;
  action: 'view' | 'edit' | 'delete' | 'create';
  componentName: string;
}

export const ResourceAuditWrapper: React.FC<ResourceAuditWrapperProps> = ({
  children,
  resource,
  action,
  componentName,
}) => {
  const { user } = usePermissions();
  const { logResourceAccess, logError } = useAuditLogging(user || undefined);

  useEffect(() => {
    if (resource) {
      logResourceAccess(action, resource, 'success', {
        component: componentName,
        timestamp: new Date().toISOString(),
      });
    }
  }, [resource, action, componentName, logResourceAccess]);

  // Error boundary functionality
  const handleError = (error: Error, errorInfo: any) => {
    logError(error, {
      action: `${componentName}.error`,
      resource,
      details: {
        component: componentName,
        errorInfo,
        action,
      },
    });
  };

  return (
    <ErrorBoundaryWithAudit onError={handleError}>
      {children}
    </ErrorBoundaryWithAudit>
  );
};

// Custom hooks for specific audit patterns
export function useResourceAudit(componentName: string) {
  const { user } = usePermissions();
  const audit = useAuditLogging(user || undefined);

  const logResourceInteraction = (
    action: 'view' | 'edit' | 'delete' | 'create',
    resource: ResourceStatus,
    outcome: 'success' | 'failure' | 'error' = 'success',
    additionalDetails?: Record<string, any>
  ) => {
    audit.logResourceAccess(action, resource, outcome, {
      component: componentName,
      timestamp: new Date().toISOString(),
      ...additionalDetails,
    });
  };

  const logComponentError = (error: Error, context?: Record<string, any>) => {
    audit.logError(error, {
      action: `${componentName}.error`,
      details: {
        component: componentName,
        timestamp: new Date().toISOString(),
        ...context,
      },
    });
  };

  const logUserAction = (action: string, details?: Record<string, any>) => {
    audit.logDashboardInteraction('view', {
      component: componentName,
      action,
      timestamp: new Date().toISOString(),
      ...details,
    });
  };

  return {
    logResourceInteraction,
    logComponentError,
    logUserAction,
  };
}

export function useClickAudit(componentName: string, elementName?: string) {
  const { logUserAction } = useResourceAudit(componentName);

  return (additionalDetails?: Record<string, any>) => {
    logUserAction('click', {
      element: elementName,
      ...additionalDetails,
    });
  };
}

export function useFormAudit(componentName: string) {
  const { logUserAction } = useResourceAudit(componentName);

  const logFormSubmit = (formData: Record<string, any>, outcome: 'success' | 'failure' = 'success') => {
    logUserAction('form_submit', {
      outcome,
      formData: sanitizeFormData(formData),
    });
  };

  const logFormChange = (fieldName: string, value: any) => {
    logUserAction('form_change', {
      field: fieldName,
      hasValue: !!value,
      valueType: typeof value,
    });
  };

  const logFormValidation = (isValid: boolean, errors?: Record<string, string>) => {
    logUserAction('form_validation', {
      isValid,
      errorCount: errors ? Object.keys(errors).length : 0,
      errorFields: errors ? Object.keys(errors) : [],
    });
  };

  return {
    logFormSubmit,
    logFormChange,
    logFormValidation,
  };
}

// Performance audit hook
export function usePerformanceAudit(componentName: string) {
  const { logUserAction } = useResourceAudit(componentName);
  const startTimeRef = useRef<number | undefined>(undefined);

  const startMeasurement = (operationName: string) => {
    startTimeRef.current = performance.now();
    return operationName;
  };

  const endMeasurement = (operationName: string, additionalDetails?: Record<string, any>) => {
    if (startTimeRef.current) {
      const duration = performance.now() - startTimeRef.current;
      
      logUserAction('performance_measurement', {
        operation: operationName,
        duration: Math.round(duration),
        ...additionalDetails,
      });

      startTimeRef.current = undefined;
    }
  };

  return {
    startMeasurement,
    endMeasurement,
  };
}

// Error boundary with audit logging
interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundaryWithAudit extends React.Component<
  { children: React.ReactNode; onError?: (error: Error, errorInfo: any) => void },
  ErrorBoundaryState
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.props.onError?.(error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <div className="font-medium">Component Error</div>
          <div className="text-sm mt-1">
            {this.state.error?.message || 'An error occurred in this component.'}
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="mt-2 text-sm text-red-600 hover:text-red-800 underline"
          >
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

// Utility functions
function sanitizeProps(props: any, excludeProps: string[]): Record<string, any> {
  const sanitized: Record<string, any> = {};
  
  Object.keys(props).forEach(key => {
    if (excludeProps.includes(key) || excludeProps.includes('all')) {
      return;
    }

    const value = props[key];
    
    if (typeof value === 'function') {
      sanitized[key] = '[Function]';
    } else if (typeof value === 'object' && value !== null) {
      if (React.isValidElement(value)) {
        sanitized[key] = '[React Element]';
      } else if (Array.isArray(value)) {
        sanitized[key] = `[Array(${value.length})]`;
      } else {
        sanitized[key] = '[Object]';
      }
    } else {
      sanitized[key] = value;
    }
  });

  return sanitized;
}

function getChangedProps(oldProps: any, newProps: any, excludeProps: string[]): Record<string, any> {
  const changes: Record<string, any> = {};

  Object.keys(newProps).forEach(key => {
    if (excludeProps.includes(key) || excludeProps.includes('all')) {
      return;
    }

    if (oldProps[key] !== newProps[key]) {
      changes[key] = {
        from: sanitizeValue(oldProps[key]),
        to: sanitizeValue(newProps[key]),
      };
    }
  });

  return changes;
}

function sanitizeArgs(args: any[]): any[] {
  return args.map(sanitizeValue);
}

function sanitizeValue(value: any): any {
  if (typeof value === 'function') {
    return '[Function]';
  } else if (React.isValidElement(value)) {
    return '[React Element]';
  } else if (typeof value === 'object' && value !== null) {
    if (Array.isArray(value)) {
      return `[Array(${value.length})]`;
    }
    return '[Object]';
  }
  return value;
}

function sanitizeFormData(formData: Record<string, any>): Record<string, any> {
  const sensitiveFields = ['password', 'token', 'secret', 'key', 'auth'];
  const sanitized: Record<string, any> = {};

  Object.keys(formData).forEach(key => {
    const isSensitive = sensitiveFields.some(field => 
      key.toLowerCase().includes(field)
    );

    sanitized[key] = isSensitive ? '[REDACTED]' : formData[key];
  });

  return sanitized;
}