'use client';

import { Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { setActiveCloudAccount } from '@/lib/cloud-active';
import type { CloudAccountInput, CloudAccountResponse, CloudStatus } from '@/lib/types';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
import {
  ChevronLeft,
  CheckCircle2,
  XCircle,
  LogOut,
  Upload,
  Loader2,
  AlertTriangle,
  Clock,
  User,
} from 'lucide-react';
import { CloudAccountForm } from '@/components/config/cloud-account-form';

function inputFromAccount(a: CloudAccountResponse): CloudAccountInput {
  return {
    name: a.name,
    enabled: a.enabled,
    api_url: a.api_url,
    auth_provider: a.auth_provider,
    email: a.email,
    cognito_region: a.cognito_region,
    cognito_user_pool_id: a.cognito_user_pool_id,
    cognito_client_id: a.cognito_client_id,
    oidc_issuer: a.oidc_issuer,
    oidc_client_id: a.oidc_client_id,
    auto_sync: a.auto_sync,
    sync_interval_seconds: a.sync_interval_seconds,
  };
}

export default function EditCloudAccountPage() {
  // Suspense boundary required by useSearchParams() under static export.
  return (
    <Suspense fallback={<Skeleton className="h-64 w-full" />}>
      <EditCloudAccountInner />
    </Suspense>
  );
}

function EditCloudAccountInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  // Static export can't pre-render runtime account IDs, so we drive the
  // edit page from a query param (?id=…) instead of a [id] dynamic route.
  const id = searchParams.get('id') ?? undefined;

  const { data: account, isLoading } = useQuery({
    queryKey: ['cloud-account', id],
    queryFn: () => api.config.cloud.getAccount(id!),
    enabled: !!id,
  });

  const { data: status } = useQuery({
    queryKey: ['cloud-status'],
    queryFn: () => api.config.cloud.getStatus(),
    enabled: !!account?.is_active,
    refetchInterval: account?.is_active ? 30000 : false,
  });

  const updateMutation = useMutation({
    mutationFn: (input: CloudAccountInput) => api.config.cloud.updateAccount(id!, input),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-account', id] });
      queryClient.invalidateQueries({ queryKey: ['cloud-accounts'] });
      queryClient.invalidateQueries({ queryKey: ['cloud-config'] });
      toast.success('Cloud account saved');
    },
    onError: (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      toast.error(`Save failed: ${msg}`);
    },
  });

  const activateMutation = useMutation({
    mutationFn: () => setActiveCloudAccount(id!, queryClient),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-account', id] });
      toast.success('This is now the active account');
    },
    onError: (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to switch active account: ${msg}`);
    },
  });

  const logoutMutation = useMutation({
    mutationFn: () => api.config.cloud.logout(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-status'] });
      toast.success('Logged out');
    },
    onError: (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      toast.error(`Logout failed: ${msg}`);
    },
  });

  const syncMutation = useMutation({
    mutationFn: () => api.config.cloud.sync(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['cloud-status'] });
      toast.success(`Synced ${data.total_synced} items`);
    },
    onError: (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      toast.error(`Sync failed: ${msg}`);
    },
  });

  if (isLoading || !account) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-1/3" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push('/config/cloud')}
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Back to accounts
        </Button>
      </div>

      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-3xl font-bold">{account.name}</h1>
            {account.is_active && (
              <Badge variant="secondary" className="gap-1">
                <CheckCircle2 className="h-3 w-3 text-green-500" />
                Active
              </Badge>
            )}
          </div>
          <p className="text-muted-foreground">Edit cloud connection settings</p>
        </div>
        {!account.is_active && (
          <Button
            variant="outline"
            onClick={() => activateMutation.mutate()}
            disabled={activateMutation.isPending}
          >
            {activateMutation.isPending ? 'Activating…' : 'Make Active'}
          </Button>
        )}
      </div>

      {/* Status banner — only meaningful for the active account, since the
          underlying get_cloud_status command always reads the active slot. */}
      {account.is_active && status && (
        <ActiveStatusBanner
          status={status}
          onLogout={() => logoutMutation.mutate()}
          onSync={() => syncMutation.mutate()}
          isSyncing={syncMutation.isPending}
          isLoggingOut={logoutMutation.isPending}
        />
      )}

      <CloudAccountForm
        initial={inputFromAccount(account)}
        submitLabel="Save Changes"
        onSubmit={async (input) => {
          await updateMutation.mutateAsync(input);
        }}
      />
    </div>
  );
}

function ActiveStatusBanner({
  status,
  onLogout,
  onSync,
  isSyncing,
  isLoggingOut,
}: {
  status: CloudStatus;
  onLogout: () => void;
  onSync: () => void;
  isSyncing: boolean;
  isLoggingOut: boolean;
}) {
  return (
    <Card className={status.connected ? 'border-green-500/50' : 'border-yellow-500/50'}>
      <CardContent className="py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4 flex-wrap">
            {status.connected ? (
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
                <span className="font-medium">Connected</span>
              </div>
            ) : !status.authenticated ? (
              <div className="flex items-center gap-2">
                <XCircle className="h-5 w-5 text-yellow-500" />
                <span className="font-medium">Not signed in</span>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <XCircle className="h-5 w-5 text-yellow-500" />
                <span className="font-medium">Disconnected</span>
              </div>
            )}

            {status.authenticated && status.user_email && (
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <User className="h-4 w-4" />
                <span>{status.user_email}</span>
              </div>
            )}

            {status.last_sync_at && (
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Clock className="h-4 w-4" />
                <span>Last sync: {new Date(status.last_sync_at).toLocaleString()}</span>
              </div>
            )}

            {status.pending_changes > 0 && (
              <Badge variant="secondary">{status.pending_changes} pending</Badge>
            )}
          </div>

          {status.authenticated && (
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={onSync}
                disabled={isSyncing || status.sync_in_progress}
              >
                {isSyncing || status.sync_in_progress ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Syncing...
                  </>
                ) : (
                  <>
                    <Upload className="h-4 w-4 mr-2" />
                    Sync Now
                  </>
                )}
              </Button>
              <Button variant="ghost" size="sm" onClick={onLogout} disabled={isLoggingOut}>
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          )}
        </div>

        {status.last_error && (
          <div className="mt-3 flex items-center gap-2 text-sm text-red-500">
            <AlertTriangle className="h-4 w-4" />
            {status.last_error}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
