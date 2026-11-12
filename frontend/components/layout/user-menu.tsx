'use client';

import Image from 'next/image';
import Link from 'next/link';
import { useEffect } from 'react';
import {
  Activity,
  FolderGit2,
  LogOut,
  Settings,
  Shield,
  User as UserIcon,
} from 'lucide-react';
import { useAuthStore } from '@/lib/stores/auth-store';
import { isLocalMode } from '@/lib/deployment-mode';
import { api } from '@/lib/tauri-api';
import { isBrowserOAuthConfigured, getCognitoConfig } from '@/lib/cognito-auth';
import { revokeRefreshToken, openLogout } from '@/lib/oauth-pkce';
import { ADMIN_GROUPS, useIsReadOnly } from '@/lib/read-only';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

export function UserMenu() {
  const user = useAuthStore((s) => s.user);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const isReadOnly = useIsReadOnly();

  const handleSignOut = async () => {
    const local = isLocalMode();
    // Cloud mode: terminate the Cognito session everywhere (revoke the refresh
    // token + destroy the SSO cookie) so the next person on a shared machine
    // can't silently re-auth. Bounded so a slow network never blocks the exit.
    // Skipped in local mode — there is no hosted session to revoke.
    if (!local && isBrowserOAuthConfigured()) {
      const { refreshToken } = useAuthStore.getState();
      const { domain, clientId } = getCognitoConfig();
      if (domain && clientId) {
        const tasks: Promise<unknown>[] = [];
        if (refreshToken) {
          tasks.push(revokeRefreshToken({ domain, clientId, refreshToken }));
        }
        tasks.push(openLogout());
        await Promise.race([
          Promise.allSettled(tasks),
          new Promise((r) => setTimeout(r, 2500)),
        ]);
      }
    }
    // Clear the cloud auth tokens on the Rust side. cloud_logout only removes
    // the active account's token file — it does NOT touch the merged config
    // mirror, so local-mode scope/credentials survive the sign-out.
    try {
      await api.config.cloud.logout();
    } catch {
      /* best-effort — local clear + exit below always run */
    }
    clearAuth();
    if (local) {
      // No login page to bounce to in local mode — stay in the app.
      toast.success('Signed out of your cloud account.');
      window.location.reload();
      return;
    }
    try {
      sessionStorage.removeItem('startup-gate-completed');
    } catch {
      /* ignore */
    }
    window.location.href = '/';
  };

  // Cmd/Ctrl+Shift+Q signs out from anywhere — quick exit when shadowing a
  // customer demo or stepping away from the laptop.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === 'q') {
        e.preventDefault();
        handleSignOut();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const local = isLocalMode();
  const isAdmin = user?.groups?.some((g) => ADMIN_GROUPS.has(g.toLowerCase()));
  // De-dupe and shorten group names for the badge row
  const visibleGroups = Array.from(new Set(user?.groups ?? [])).slice(0, 3);

  // Local mode has no cloud identity, but we still render the profile button so
  // the operator can reach settings and sign out of any lingering cloud
  // association. (Previously the whole menu was hidden whenever the session was
  // not authenticated, leaving local-mode users with no way to log out.)
  const displayName =
    user?.name || user?.email?.split('@')[0] || (local ? 'Local operator' : 'Account');
  const displaySub = user?.email || (local ? 'Local mode · this machine' : undefined);
  const hasCloudIdentity = Boolean(user);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label="User menu"
          className="relative h-8 w-8 rounded-full overflow-hidden border border-border/60 hover:border-border transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
        >
          <Image
            src="/maestro-icon.png"
            alt={displayName}
            width={32}
            height={32}
            className="h-full w-full object-cover"
          />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col gap-1.5">
            <span className="text-sm font-medium text-foreground truncate">
              {displayName}
            </span>
            {displaySub && (
              <span className="text-xs text-muted-foreground truncate">
                {displaySub}
              </span>
            )}
            {(user?.orgId || visibleGroups.length > 0 || isReadOnly || local) && (
              <div className="flex flex-wrap gap-1 pt-1">
                {local && (
                  <Badge
                    variant="outline"
                    className="text-[10px] uppercase tracking-wide"
                  >
                    Local
                  </Badge>
                )}
                {isReadOnly && (
                  <Badge
                    variant="outline"
                    className="border-amber-500/40 text-[10px] uppercase tracking-wide text-amber-600 dark:text-amber-400"
                  >
                    Read-only
                  </Badge>
                )}
                {user?.orgId && (
                  <Badge
                    variant="outline"
                    className="text-[10px] uppercase tracking-wide"
                  >
                    {user.orgId}
                  </Badge>
                )}
                {visibleGroups.map((g) => (
                  <Badge
                    key={g}
                    variant={ADMIN_GROUPS.has(g.toLowerCase()) ? 'default' : 'secondary'}
                    className="text-[10px]"
                  >
                    {g}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/config" className="cursor-pointer">
            <Settings className="mr-2 h-4 w-4" />
            <span>Settings</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/repositories" className="cursor-pointer">
            <FolderGit2 className="mr-2 h-4 w-4" />
            <span>Repositories</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/audit-logs" className="cursor-pointer">
            <Activity className="mr-2 h-4 w-4" />
            <span>Audit Logs</span>
          </Link>
        </DropdownMenuItem>
        {isAdmin && (
          <DropdownMenuItem asChild>
            <Link href="/users" className="cursor-pointer">
              <Shield className="mr-2 h-4 w-4" />
              <span>Org Users</span>
            </Link>
          </DropdownMenuItem>
        )}
        <DropdownMenuItem asChild>
          <Link href={local ? '/config/data-sync' : '/config/cloud'} className="cursor-pointer">
            <UserIcon className="mr-2 h-4 w-4" />
            <span>Account</span>
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          variant="destructive"
          onClick={handleSignOut}
          className="cursor-pointer flex items-center justify-between"
        >
          <span className="flex items-center">
            <LogOut className="mr-2 h-4 w-4" />
            {local && !hasCloudIdentity ? 'Sign out of cloud' : 'Sign out'}
          </span>
          <kbd className="text-[10px] text-muted-foreground/70 font-mono">
            ⌘⇧Q
          </kbd>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
