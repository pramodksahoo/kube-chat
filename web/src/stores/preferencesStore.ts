import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type { PreferencesStoreState, UserPreferences } from '../types/auth';
import PreferencesService from '../services/preferencesService';

interface PreferencesStoreActions {
  // Preferences management actions
  loadPreferences: () => Promise<void>;
  updatePreferences: (preferences: Partial<UserPreferences>) => Promise<void>;
  resetToDefaults: () => Promise<void>;
  
  // Theme management
  setTheme: (theme: UserPreferences['theme']) => void;
  applyTheme: () => void;
  
  // State management actions
  setPreferences: (preferences: UserPreferences) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setHasUnsavedChanges: (hasChanges: boolean) => void;
  clearError: () => void;
  
  // Local storage management
  saveToLocal: () => void;
  loadFromLocal: () => void;
}

type PreferencesStore = PreferencesStoreState & PreferencesStoreActions;

export const usePreferencesStore = create<PreferencesStore>()(
  subscribeWithSelector((set, get) => ({
    // Initial state
    preferences: PreferencesService.getInstance().getDefaultPreferences(),
    isLoading: false,
    error: null,
    hasUnsavedChanges: false,

    // Preferences management actions
    loadPreferences: async () => {
      const { setLoading, setError, setPreferences } = get();
      
      try {
        setLoading(true);
        setError(null);
        
        const preferencesService = PreferencesService.getInstance();
        const preferences = await preferencesService.getUserPreferences();
        
        setPreferences(preferences);
        
        // Apply theme immediately
        preferencesService.applyThemePreference(preferences.theme);
        
      } catch (error) {
        setError(error instanceof Error ? error.message : 'Failed to load preferences');
        
        // Fall back to local preferences if server fails
        const preferencesService = PreferencesService.getInstance();
        const localPreferences = preferencesService.getLocalPreferences();
        
        if (localPreferences) {
          setPreferences(localPreferences);
          preferencesService.applyThemePreference(localPreferences.theme);
        }
      } finally {
        setLoading(false);
      }
    },

    updatePreferences: async (updates) => {
      const { setLoading, setError, preferences, setPreferences, setHasUnsavedChanges } = get();
      
      try {
        setLoading(true);
        setError(null);
        
        const updatedPreferences = { ...preferences, ...updates };
        const preferencesService = PreferencesService.getInstance();
        
        // Update on server
        const savedPreferences = await preferencesService.updateUserPreferences(updatedPreferences);
        
        setPreferences(savedPreferences);
        setHasUnsavedChanges(false);
        
        // Apply theme if it was changed
        if (updates.theme) {
          preferencesService.applyThemePreference(updates.theme);
        }
        
      } catch (error) {
        setError(error instanceof Error ? error.message : 'Failed to update preferences');
        
        // Still update locally even if server fails
        const updatedPreferences = { ...preferences, ...updates };
        setPreferences(updatedPreferences);
        setHasUnsavedChanges(true);
        
        // Save locally as backup
        const preferencesService = PreferencesService.getInstance();
        preferencesService.storePreferencesLocally(updatedPreferences);
        
        if (updates.theme) {
          preferencesService.applyThemePreference(updates.theme);
        }
      } finally {
        setLoading(false);
      }
    },

    resetToDefaults: async () => {
      const { setLoading, setError, setPreferences } = get();
      
      try {
        setLoading(true);
        setError(null);
        
        const preferencesService = PreferencesService.getInstance();
        const defaultPreferences = preferencesService.getDefaultPreferences();
        
        const savedPreferences = await preferencesService.updateUserPreferences(defaultPreferences);
        
        setPreferences(savedPreferences);
        
        // Apply default theme
        preferencesService.applyThemePreference(savedPreferences.theme);
        
      } catch (error) {
        setError(error instanceof Error ? error.message : 'Failed to reset preferences');
      } finally {
        setLoading(false);
      }
    },

    // Theme management
    setTheme: (theme) => {
      const { updatePreferences } = get();
      void updatePreferences({ theme });
    },

    applyTheme: () => {
      const { preferences } = get();
      const preferencesService = PreferencesService.getInstance();
      preferencesService.applyThemePreference(preferences.theme);
    },

    // State management actions
    setPreferences: (preferences) => {
      set({ preferences });
    },

    setLoading: (loading) => {
      set({ isLoading: loading });
    },

    setError: (error) => {
      set({ error });
    },

    setHasUnsavedChanges: (hasChanges) => {
      set({ hasUnsavedChanges: hasChanges });
    },

    clearError: () => {
      set({ error: null });
    },

    // Local storage management
    saveToLocal: () => {
      const { preferences } = get();
      const preferencesService = PreferencesService.getInstance();
      preferencesService.storePreferencesLocally(preferences);
    },

    loadFromLocal: () => {
      const preferencesService = PreferencesService.getInstance();
      const localPreferences = preferencesService.getLocalPreferences();
      
      if (localPreferences) {
        set({ preferences: localPreferences });
        preferencesService.applyThemePreference(localPreferences.theme);
      }
    },
  }))
);

// Auto-save to local storage on preferences changes
if (typeof window !== 'undefined') {
  usePreferencesStore.subscribe(
    (state) => state.preferences,
    (preferences) => {
      const preferencesService = PreferencesService.getInstance();
      preferencesService.storePreferencesLocally(preferences);
    },
    { fireImmediately: false } // Don't fire on initial state
  );

  // Load preferences on auth state changes
  const loadPreferencesOnAuth = async () => {
    const { useAuthStore } = await import('./authStore');
    
    useAuthStore.subscribe(
      (state) => state.isAuthenticated,
      (isAuthenticated) => {
        const preferencesStore = usePreferencesStore.getState();
        
        if (isAuthenticated) {
          void preferencesStore.loadPreferences();
        } else {
          // Load local preferences when not authenticated
          preferencesStore.loadFromLocal();
        }
      }
    );
  };
  
  void loadPreferencesOnAuth();

  // Handle system theme changes
  if (window.matchMedia) {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const handleSystemThemeChange = () => {
      const { preferences, applyTheme } = usePreferencesStore.getState();
      
      if (preferences.theme === 'system') {
        applyTheme();
      }
    };
    
    mediaQuery.addEventListener('change', handleSystemThemeChange);
  }

  // Save unsaved changes before page unload
  window.addEventListener('beforeunload', (e) => {
    const { hasUnsavedChanges, saveToLocal } = usePreferencesStore.getState();
    
    if (hasUnsavedChanges) {
      saveToLocal();
      
      // Show warning dialog
      e.preventDefault();
      e.returnValue = 'You have unsaved preferences changes. Are you sure you want to leave?';
    }
  });

  // Initialize preferences on app start
  const initializePreferences = () => {
    const preferencesStore = usePreferencesStore.getState();
    
    // First try to load from local storage for immediate theme application
    preferencesStore.loadFromLocal();
    
    // Then check if we need to load from server (will happen when auth state changes)
  };
  
  // Wait for DOM to be ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializePreferences);
  } else {
    initializePreferences();
  }
}

export default usePreferencesStore;