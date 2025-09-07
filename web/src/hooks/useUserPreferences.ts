import { useCallback, useEffect } from 'react';
import { usePreferencesStore } from '../stores/preferencesStore';
import type { DashboardLayout, NotificationSettings, UserPreferences } from '../types/auth';

/**
 * Custom hook for user preferences management
 */
export function useUserPreferences() {
  const {
    // State
    preferences,
    isLoading,
    error,
    hasUnsavedChanges,
    
    // Actions
    loadPreferences,
    updatePreferences,
    resetToDefaults,
    setTheme,
    // applyTheme,
    clearError,
    saveToLocal,
    loadFromLocal,
  } = usePreferencesStore();

  // Load preferences on mount if needed
  useEffect(() => {
    if (!preferences.theme) {
      loadFromLocal();
    }
  }, [preferences.theme, loadFromLocal]);

  // Handle theme changes with immediate application
  const changeTheme = useCallback((theme: UserPreferences['theme']) => {
    setTheme(theme);
    // Theme is automatically applied by the store
  }, [setTheme]);

  // Handle language changes
  const changeLanguage = useCallback(async (language: string) => {
    try {
      clearError();
      await updatePreferences({ language });
      
      // Apply language change to document if supported
      if (typeof document !== 'undefined') {
        document.documentElement.lang = language;
      }
    } catch (error) {
      console.error('Failed to change language:', error);
    }
  }, [updatePreferences, clearError]);

  // Handle timezone changes
  const changeTimezone = useCallback(async (timezone: string) => {
    try {
      clearError();
      await updatePreferences({ timezone });
    } catch (error) {
      console.error('Failed to change timezone:', error);
    }
  }, [updatePreferences, clearError]);

  // Handle dashboard layout changes
  const updateDashboardLayout = useCallback(async (layoutUpdates: Partial<DashboardLayout>) => {
    try {
      clearError();
      const newLayout = {
        ...preferences.dashboardLayout,
        ...layoutUpdates,
      };
      await updatePreferences({ dashboardLayout: newLayout });
    } catch (error) {
      console.error('Failed to update dashboard layout:', error);
    }
  }, [preferences.dashboardLayout, updatePreferences, clearError]);

  // Handle notification settings changes
  const updateNotificationSettings = useCallback(async (notificationUpdates: Partial<NotificationSettings>) => {
    try {
      clearError();
      const newNotifications = {
        ...preferences.notifications,
        ...notificationUpdates,
      };
      await updatePreferences({ notifications: newNotifications });
    } catch (error) {
      console.error('Failed to update notification settings:', error);
    }
  }, [preferences.notifications, updatePreferences, clearError]);

  // Toggle sidebar collapse state
  const toggleSidebar = useCallback(async () => {
    const currentCollapsed = preferences.dashboardLayout.sidebar.collapsed;
    await updateDashboardLayout({
      sidebar: {
        ...preferences.dashboardLayout.sidebar,
        collapsed: !currentCollapsed,
      },
    });
  }, [preferences.dashboardLayout.sidebar, updateDashboardLayout]);

  // Update sidebar width
  const updateSidebarWidth = useCallback(async (width: number) => {
    // Validate width constraints
    const constrainedWidth = Math.max(200, Math.min(500, width));
    
    await updateDashboardLayout({
      sidebar: {
        ...preferences.dashboardLayout.sidebar,
        width: constrainedWidth,
      },
    });
  }, [preferences.dashboardLayout.sidebar, updateDashboardLayout]);

  // Toggle panel visibility
  const togglePanel = useCallback(async (panel: keyof DashboardLayout['panels']) => {
    const currentVisible = preferences.dashboardLayout.panels[panel].visible;
    
    await updateDashboardLayout({
      panels: {
        ...preferences.dashboardLayout.panels,
        [panel]: {
          ...preferences.dashboardLayout.panels[panel],
          visible: !currentVisible,
        },
      },
    });
  }, [preferences.dashboardLayout.panels, updateDashboardLayout]);

  // Handle bulk preferences update
  const updateMultiplePreferences = useCallback(async (updates: Partial<UserPreferences>) => {
    try {
      clearError();
      await updatePreferences(updates);
    } catch (error) {
      console.error('Failed to update preferences:', error);
    }
  }, [updatePreferences, clearError]);

  // Save current preferences to local storage
  const savePreferencesLocally = useCallback(() => {
    saveToLocal();
  }, [saveToLocal]);

  // Reset all preferences to defaults
  const resetAllPreferences = useCallback(async () => {
    try {
      clearError();
      await resetToDefaults();
    } catch (error) {
      console.error('Failed to reset preferences:', error);
    }
  }, [resetToDefaults, clearError]);

  // Get system theme preference
  const getSystemTheme = useCallback((): 'light' | 'dark' => {
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return 'light';
  }, []);

  // Get effective theme (resolves 'system' to actual theme)
  const getEffectiveTheme = useCallback((): 'light' | 'dark' => {
    if (preferences.theme === 'system') {
      return getSystemTheme();
    }
    return preferences.theme;
  }, [preferences.theme, getSystemTheme]);

  // Check if notifications are enabled
  const areNotificationsEnabled = useCallback((): boolean => {
    return preferences.notifications.enabled;
  }, [preferences.notifications.enabled]);

  // Check if specific notification type is enabled
  const isNotificationTypeEnabled = useCallback((type: keyof NotificationSettings): boolean => {
    return preferences.notifications.enabled && preferences.notifications[type];
  }, [preferences.notifications]);

  // Get browser notification permission status
  const getNotificationPermission = useCallback((): NotificationPermission | null => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      return Notification.permission;
    }
    return null;
  }, []);

  // Request browser notification permission
  const requestNotificationPermission = useCallback(async (): Promise<NotificationPermission | null> => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      try {
        const permission = await Notification.requestPermission();
        return permission;
      } catch (error) {
        console.error('Failed to request notification permission:', error);
        return null;
      }
    }
    return null;
  }, []);

  // Format timezone for display
  const getTimezoneDisplay = useCallback((): string => {
    try {
      const now = new Date();
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZoneName: 'long',
        timeZone: preferences.timezone,
      });
      
      const parts = formatter.formatToParts(now);
      const timeZoneName = parts.find(part => part.type === 'timeZoneName')?.value || preferences.timezone;
      
      return timeZoneName;
    } catch {
      return preferences.timezone;
    }
  }, [preferences.timezone]);

  // Get available languages (could be expanded to load from server)
  const getAvailableLanguages = useCallback(() => [
    { code: 'en-US', name: 'English (US)' },
    { code: 'en-GB', name: 'English (UK)' },
    { code: 'es-ES', name: 'Spanish' },
    { code: 'fr-FR', name: 'French' },
    { code: 'de-DE', name: 'German' },
    { code: 'ja-JP', name: 'Japanese' },
    { code: 'zh-CN', name: 'Chinese (Simplified)' },
  ], []);

  // Preferences state object
  const preferencesState = {
    preferences,
    isLoading,
    error,
    hasUnsavedChanges,
  };

  // Preferences actions object
  const preferencesActions = {
    loadPreferences,
    updatePreferences: updateMultiplePreferences,
    resetToDefaults: resetAllPreferences,
    changeTheme,
    changeLanguage,
    changeTimezone,
    updateDashboardLayout,
    updateNotificationSettings,
    toggleSidebar,
    updateSidebarWidth,
    togglePanel,
    savePreferencesLocally,
    clearError,
  };

  // Preferences utility functions
  const preferencesUtils = {
    getSystemTheme,
    getEffectiveTheme,
    areNotificationsEnabled,
    isNotificationTypeEnabled,
    getNotificationPermission,
    requestNotificationPermission,
    getTimezoneDisplay,
    getAvailableLanguages,
  };

  return {
    ...preferencesState,
    ...preferencesActions,
    ...preferencesUtils,
  };
}

export default useUserPreferences;