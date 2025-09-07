import type { DashboardLayout, NotificationSettings, UserPreferences } from '../types/auth';

export class PreferencesService {
  private static instance: PreferencesService;
  
  private constructor() {}
  
  public static getInstance(): PreferencesService {
    if (!PreferencesService.instance) {
      PreferencesService.instance = new PreferencesService();
    }
    return PreferencesService.instance;
  }

  /**
   * Get user preferences from server
   */
  public async getUserPreferences(): Promise<UserPreferences> {
    try {
      const response = await fetch('/api/v1/auth/user/preferences', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to get user preferences: ${response.statusText}`);
      }

      const data = await response.json();
      return this.validateAndSanitizePreferences(data);
    } catch (error) {
      // Return default preferences if fetch fails
      console.warn('Failed to fetch user preferences, using defaults:', error);
      return this.getDefaultPreferences();
    }
  }

  /**
   * Update user preferences on server
   */
  public async updateUserPreferences(preferences: UserPreferences): Promise<UserPreferences> {
    try {
      const validatedPreferences = this.validateAndSanitizePreferences(preferences);
      
      const response = await fetch('/api/v1/auth/user/preferences', {
        method: 'PUT',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(validatedPreferences),
      });

      if (!response.ok) {
        throw new Error(`Failed to update user preferences: ${response.statusText}`);
      }

      const data = await response.json();
      
      // Store updated preferences locally for faster access
      this.storePreferencesLocally(data);
      
      return this.validateAndSanitizePreferences(data);
    } catch (error) {
      throw new Error(`Failed to update user preferences: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get default user preferences
   */
  public getDefaultPreferences(): UserPreferences {
    return {
      theme: 'system',
      language: 'en-US',
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
      dashboardLayout: {
        sidebar: {
          collapsed: false,
          width: 280,
        },
        panels: {
          chat: { visible: true, position: 'center' },
          resources: { visible: true, position: 'right' },
          commands: { visible: true, position: 'bottom' },
        },
      },
      notifications: {
        enabled: true,
        email: false,
        push: true,
        sound: true,
        sessionWarnings: true,
        commandResults: true,
        systemAlerts: true,
      },
    };
  }

  /**
   * Validate and sanitize preferences
   */
  public validateAndSanitizePreferences(preferences: Partial<UserPreferences>): UserPreferences {
    const defaults = this.getDefaultPreferences();
    
    const validThemes: UserPreferences['theme'][] = ['light', 'dark', 'system'];
    const theme = validThemes.includes(preferences.theme as any) ? preferences.theme : defaults.theme;
    
    const language = typeof preferences.language === 'string' && preferences.language.length <= 10
      ? preferences.language
      : defaults.language;
    
    const timezone = typeof preferences.timezone === 'string' && preferences.timezone.length <= 50
      ? preferences.timezone
      : defaults.timezone;
    
    return {
      theme: theme!,
      language,
      timezone,
      dashboardLayout: this.validateDashboardLayout(preferences.dashboardLayout, defaults.dashboardLayout),
      notifications: this.validateNotificationSettings(preferences.notifications, defaults.notifications),
    };
  }

  /**
   * Validate dashboard layout preferences
   */
  private validateDashboardLayout(layout: any, defaultLayout: DashboardLayout): DashboardLayout {
    if (!layout || typeof layout !== 'object') {
      return defaultLayout;
    }
    
    const sidebar = {
      collapsed: typeof layout.sidebar?.collapsed === 'boolean' ? layout.sidebar.collapsed : defaultLayout.sidebar.collapsed,
      width: typeof layout.sidebar?.width === 'number' && layout.sidebar.width >= 200 && layout.sidebar.width <= 500
        ? layout.sidebar.width
        : defaultLayout.sidebar.width,
    };
    
    const panels = {
      chat: {
        visible: typeof layout.panels?.chat?.visible === 'boolean' ? layout.panels.chat.visible : defaultLayout.panels.chat.visible,
        position: ['left', 'center', 'right'].includes(layout.panels?.chat?.position) ? layout.panels.chat.position : defaultLayout.panels.chat.position,
      },
      resources: {
        visible: typeof layout.panels?.resources?.visible === 'boolean' ? layout.panels.resources.visible : defaultLayout.panels.resources.visible,
        position: ['left', 'center', 'right'].includes(layout.panels?.resources?.position) ? layout.panels.resources.position : defaultLayout.panels.resources.position,
      },
      commands: {
        visible: typeof layout.panels?.commands?.visible === 'boolean' ? layout.panels.commands.visible : defaultLayout.panels.commands.visible,
        position: ['top', 'bottom'].includes(layout.panels?.commands?.position) ? layout.panels.commands.position : defaultLayout.panels.commands.position,
      },
    };
    
    return { sidebar, panels };
  }

  /**
   * Validate notification settings
   */
  private validateNotificationSettings(notifications: any, defaultSettings: NotificationSettings): NotificationSettings {
    if (!notifications || typeof notifications !== 'object') {
      return defaultSettings;
    }
    
    return {
      enabled: typeof notifications.enabled === 'boolean' ? notifications.enabled : defaultSettings.enabled,
      email: typeof notifications.email === 'boolean' ? notifications.email : defaultSettings.email,
      push: typeof notifications.push === 'boolean' ? notifications.push : defaultSettings.push,
      sound: typeof notifications.sound === 'boolean' ? notifications.sound : defaultSettings.sound,
      sessionWarnings: typeof notifications.sessionWarnings === 'boolean' ? notifications.sessionWarnings : defaultSettings.sessionWarnings,
      commandResults: typeof notifications.commandResults === 'boolean' ? notifications.commandResults : defaultSettings.commandResults,
      systemAlerts: typeof notifications.systemAlerts === 'boolean' ? notifications.systemAlerts : defaultSettings.systemAlerts,
    };
  }

  /**
   * Store preferences locally for faster access
   */
  public storePreferencesLocally(preferences: UserPreferences): void {
    if (typeof window === 'undefined') return;
    
    try {
      const preferencesData = {
        ...preferences,
        timestamp: new Date().toISOString(),
      };
      
      localStorage.setItem('kubechat_user_preferences', JSON.stringify(preferencesData));
    } catch (error) {
      console.error('Failed to store preferences locally:', error);
    }
  }

  /**
   * Get locally stored preferences
   */
  public getLocalPreferences(): UserPreferences | null {
    if (typeof window === 'undefined') return null;
    
    try {
      const stored = localStorage.getItem('kubechat_user_preferences');
      if (!stored) return null;
      
      const data = JSON.parse(stored);
      return this.validateAndSanitizePreferences(data);
    } catch (error) {
      console.error('Failed to retrieve local preferences:', error);
      return null;
    }
  }

  /**
   * Apply theme preference to document
   */
  public applyThemePreference(theme: UserPreferences['theme']): void {
    if (typeof window === 'undefined') return;
    
    const root = document.documentElement;
    
    if (theme === 'system') {
      // Remove explicit theme classes and let system preference take over
      root.classList.remove('dark', 'light');
      
      // Listen for system theme changes
      if (window.matchMedia) {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        root.classList.toggle('dark', mediaQuery.matches);
        root.classList.toggle('light', !mediaQuery.matches);
      }
    } else {
      // Apply explicit theme
      root.classList.remove('dark', 'light');
      root.classList.add(theme);
    }
  }

  /**
   * Encrypt sensitive preference data
   */
  public async encryptSensitiveData(data: string, key?: string): Promise<string> {
    if (typeof window === 'undefined' || !window.crypto?.subtle) {
      // Fallback for environments without crypto support
      return btoa(data);
    }
    
    try {
      const encoder = new TextEncoder();
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(key || 'kubechat-preferences-key'),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );
      
      const cryptoKey = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: encoder.encode('kubechat-salt'),
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        encoder.encode(data)
      );
      
      // Combine IV and encrypted data
      const result = new Uint8Array(iv.length + encrypted.byteLength);
      result.set(iv);
      result.set(new Uint8Array(encrypted), iv.length);
      
      return btoa(String.fromCharCode(...result));
    } catch (error) {
      console.error('Encryption failed, using base64 fallback:', error);
      return btoa(data);
    }
  }

  /**
   * Clear all stored preferences
   */
  public clearStoredPreferences(): void {
    if (typeof window === 'undefined') return;
    
    localStorage.removeItem('kubechat_user_preferences');
  }
}

export default PreferencesService;