'use client';

import { useEffect } from 'react';
import { isTauriMode } from '@/lib/deploy-mode';
import { useAuthStore } from '@/lib/stores/auth-store';
import { refreshSession, isCognitoConfigured } from '@/lib/cognito-auth';

export function useAuthRefresh() {
  useEffect(() => {
    // Only in desktop mode with Cognito configured
    if (!isTauriMode() || !isCognitoConfigured()) return;

    // Token refresh check — every 30 minutes
    const refreshInterval = setInterval(async () => {
      const store = useAuthStore.getState();
      if (!store.isAuthenticated || !store.refreshToken || !store.user?.email) return;

      // Refresh if within 1 hour of expiry
      const expiresIn = (store.tokenExpiry || 0) - Date.now();
      if (expiresIn < 60 * 60 * 1000) {
        try {
          const session = await refreshSession(store.user.email, store.refreshToken);
          store.setAuth(store.user, {
            accessToken: session.getAccessToken().getJwtToken(),
            idToken: session.getIdToken().getJwtToken(),
            refreshToken: session.getRefreshToken().getToken(),
            expiresIn: 86400,
          });
        } catch {
          // Refresh failed — token revoked or account disabled
          store.clearAuth();
          window.location.reload();
        }
      }
    }, 30 * 60 * 1000); // 30 minutes

    // Account status validation — every 4 hours
    // Uses refresh as a proxy: if refresh fails, account is disabled/revoked
    const statusInterval = setInterval(async () => {
      const store = useAuthStore.getState();
      if (!store.isAuthenticated || !store.refreshToken || !store.user?.email) return;

      try {
        const session = await refreshSession(store.user.email, store.refreshToken);
        store.setAuth(store.user, {
          accessToken: session.getAccessToken().getJwtToken(),
          idToken: session.getIdToken().getJwtToken(),
          refreshToken: session.getRefreshToken().getToken(),
          expiresIn: 86400,
        });
      } catch {
        store.clearAuth();
        window.location.reload();
      }
    }, 4 * 60 * 60 * 1000); // 4 hours

    return () => {
      clearInterval(refreshInterval);
      clearInterval(statusInterval);
    };
  }, []);
}
