import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface AuthUser {
  email: string;
  name: string;
  groups: string[];
  orgId?: string;
}

interface AuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresIn: number; // seconds
}

interface AuthState {
  // User
  user: AuthUser | null;
  isAuthenticated: boolean;

  // Tokens (persisted for session continuity across app restarts)
  accessToken: string | null;
  idToken: string | null;
  refreshToken: string | null;
  tokenExpiry: number | null; // Unix ms

  // Web mode (cloud backend URL)
  backendUrl: string | null;

  // "Remember me" — when false, tokens live in memory only and are NOT
  // written to disk, so the user must sign in again after an app restart.
  rememberMe: boolean;

  // Actions
  setAuth: (user: AuthUser, tokens: AuthTokens, rememberMe?: boolean) => void;
  setUser: (user: AuthUser, backendUrl: string) => void; // Web mode compat
  clearAuth: () => void;
  clearUser: () => void; // Alias for clearAuth
  isTokenExpired: () => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      isAuthenticated: false,
      accessToken: null,
      idToken: null,
      refreshToken: null,
      tokenExpiry: null,
      backendUrl: null,
      rememberMe: true,

      setAuth: (user, tokens, rememberMe = true) =>
        set({
          user,
          isAuthenticated: true,
          accessToken: tokens.accessToken,
          idToken: tokens.idToken,
          refreshToken: tokens.refreshToken,
          tokenExpiry: Date.now() + tokens.expiresIn * 1000,
          rememberMe,
        }),

      // Web mode compat — keeps the same API as before
      setUser: (user, backendUrl) =>
        set({ user, backendUrl, isAuthenticated: true }),

      clearAuth: () =>
        set({
          user: null,
          isAuthenticated: false,
          accessToken: null,
          idToken: null,
          refreshToken: null,
          tokenExpiry: null,
          backendUrl: null,
        }),

      clearUser: () => get().clearAuth(),

      isTokenExpired: () => {
        const { tokenExpiry } = get();
        if (!tokenExpiry) return true;
        return Date.now() >= tokenExpiry;
      },
    }),
    {
      name: 'maestro-auth',
      // Only persist auth-related fields, not transient state. When the user
      // unchecks "Remember me", the user + token fields are withheld from disk
      // so the session does not survive an app restart (it still works fully
      // in-memory for the current run). The rememberMe preference itself and
      // the backend URL are always persisted.
      partialize: (state) => ({
        rememberMe: state.rememberMe,
        backendUrl: state.backendUrl,
        ...(state.rememberMe
          ? {
              user: state.user,
              isAuthenticated: state.isAuthenticated,
              accessToken: state.accessToken,
              idToken: state.idToken,
              refreshToken: state.refreshToken,
              tokenExpiry: state.tokenExpiry,
            }
          : {}),
      }),
    }
  )
);
