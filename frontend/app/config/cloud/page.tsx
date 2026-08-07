'use client';

import { useRouter } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { setActiveCloudAccount } from '@/lib/cloud-active';
import type { CloudAccountSummary } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import { Cloud, Plus, Pencil, Trash2, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function CloudAccountsPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data: accounts, isLoading } = useQuery({
    queryKey: ['cloud-accounts'],
    queryFn: () => api.config.cloud.listAccounts(),
  });

  const activateMutation = useMutation({
    mutationFn: (id: string) => setActiveCloudAccount(id, queryClient),
    onSuccess: () => {
      toast.success('Active account switched');
    },
    onError: (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      toast.error(`Failed to switch active account: ${msg}`);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.config.cloud.removeAccount(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-accounts'] });
      queryClient.invalidateQueries({ queryKey: ['cloud-config'] });
      queryClient.invalidateQueries({ queryKey: ['cloud-status'] });
      toast.success('Account deleted');
    },
    onError: (error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      toast.error(`Delete failed: ${msg}`);
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Cloud Sync</h1>
          <p className="text-muted-foreground">Manage your Maestro backend connections</p>
        </div>
        <div className="space-y-3">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      </div>
    );
  }

  const rows = accounts ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Cloud Sync</h1>
          <p className="text-muted-foreground">
            Connect Maestro to your self-hosted backend and choose which one your assessments sync to.
          </p>
        </div>
        <Button onClick={() => router.push('/config/cloud/new')}>
          <Plus className="h-4 w-4 mr-2" />
          New Connection
        </Button>
      </div>

      {/* What this is + when (not) to touch it */}
      <Card className="border-amber-500/40 bg-amber-500/5">
        <CardContent className="py-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
            <div className="text-sm space-y-1">
              <p className="font-medium text-amber-400">
                This is your connection to your organization&apos;s Maestro cloud backend
              </p>
              <p className="text-muted-foreground">
                It was configured automatically during onboarding (from your work email) — the API
                URL and Cognito settings point at the backend your organization deployed. The
                desktop app authenticates and syncs all assessments, findings, and scope through it.
              </p>
              <p className="text-muted-foreground">
                <span className="font-medium text-foreground">Don&apos;t edit or delete this</span>{' '}
                unless you have re-deployed your cloud backend and these values actually changed.
                Pointing it at the wrong API URL or a mismatched Cognito pool will break login and
                sync — you&apos;ll be locked out until it&apos;s corrected. If you&apos;re unsure,
                leave it as-is.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Empty state */}
      {rows.length === 0 && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center text-center gap-3">
              <Cloud className="h-10 w-10 text-muted-foreground" />
              <div>
                <p className="font-medium">No cloud accounts yet</p>
                <p className="text-sm text-muted-foreground">
                  Add a connection to your self-hosted backend to get started.
                </p>
              </div>
              <Button onClick={() => router.push('/config/cloud/new')} className="mt-2">
                <Plus className="h-4 w-4 mr-2" />
                Add Cloud Account
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Account rows */}
      <div className="space-y-3">
        {rows.map((account) => (
          <CloudAccountRow
            key={account.id}
            account={account}
            onActivate={() => activateMutation.mutate(account.id)}
            onEdit={() => router.push(`/config/cloud/edit?id=${account.id}`)}
            onDelete={() => deleteMutation.mutate(account.id)}
            isActivating={activateMutation.isPending && activateMutation.variables === account.id}
          />
        ))}
      </div>
    </div>
  );
}

function CloudAccountRow({
  account,
  onActivate,
  onEdit,
  onDelete,
  isActivating,
}: {
  account: CloudAccountSummary;
  onActivate: () => void;
  onEdit: () => void;
  onDelete: () => void;
  isActivating: boolean;
}) {
  const providerLabel = ({
    cognito: 'AWS Cognito',
    oidc: 'OIDC / Okta',
    local: 'Email / Password',
  } as const)[account.auth_provider];

  return (
    <Card className={account.is_active ? 'border-green-500/50' : undefined}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2">
              <CardTitle className="text-lg truncate">{account.name}</CardTitle>
              {account.is_active && (
                <Badge variant="secondary" className="gap-1">
                  <CheckCircle2 className="h-3 w-3 text-green-500" />
                  Active
                </Badge>
              )}
            </div>
            <CardDescription className="truncate font-mono text-xs">
              {account.api_url || 'No API URL configured'}
            </CardDescription>
          </div>
          <Badge variant="outline">{providerLabel}</Badge>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="flex items-center justify-end gap-2">
          {!account.is_active && (
            <Button variant="outline" size="sm" onClick={onActivate} disabled={isActivating}>
              {isActivating ? 'Activating…' : 'Make Active'}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={onEdit}>
            <Pencil className="h-3 w-3 mr-1" />
            Edit
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" size="sm">
                <Trash2 className="h-3 w-3 mr-1" />
                Delete
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete &quot;{account.name}&quot;?</AlertDialogTitle>
                <AlertDialogDescription>
                  This removes the saved connection and any stored tokens for it. The cloud backend
                  itself is not affected.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={onDelete}>Delete</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </CardContent>
    </Card>
  );
}
