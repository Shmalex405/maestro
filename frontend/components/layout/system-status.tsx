'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { cn } from '@/lib/utils';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { Button } from '@/components/ui/button';
import {
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  Server,
  Database,
  Container,
  KeyRound,
  ChevronDown,
  Play,
  Square,
  AlertTriangle,
  DownloadCloud,
} from 'lucide-react';
import { toast } from 'sonner';
import { isWebMode } from '@/lib/deploy-mode';
import { useInfraStore } from '@/lib/stores/infrastructure-store';
import { Cloud } from 'lucide-react';

type OverallStatus = 'healthy' | 'degraded' | 'critical' | 'unknown';
type ServiceStatus = 'up' | 'down' | 'unknown' | 'loading';

interface Service {
  name: string;
  icon: React.ElementType;
  status: ServiceStatus;
  detail?: string;
  troubleshooting?: string;
  action?: 'start' | 'stop';
}

export function SystemStatus() {
  const [isOpen, setIsOpen] = useState(false);
  const queryClient = useQueryClient();

  // Query system status with 30s polling
  const { data: status, isLoading, isError, refetch } = useQuery({
    queryKey: ['system-status-global'],
    queryFn: async () => {
      try {
        return await api.system.getStatus();
      } catch (e) {
        // If we can't reach the backend at all, return a minimal error state
        throw e;
      }
    },
    refetchInterval: 30000,
    retry: 1,
    retryDelay: 5000,
  });

  // Query Docker status separately for more detail
  const { data: dockerStatus } = useQuery({
    queryKey: ['docker-status'],
    queryFn: () => api.system.getDockerStatus(),
    refetchInterval: 30000,
    retry: 1,
  });

  // Start Kali mutation
  const startKali = useMutation({
    mutationFn: () => api.system.startKali(),
    onSuccess: () => {
      toast.success('Kali container started');
      // Refetch status immediately
      queryClient.invalidateQueries({ queryKey: ['system-status-global'] });
      queryClient.invalidateQueries({ queryKey: ['docker-status'] });
    },
    onError: (error: any) => {
      toast.error(error?.message || 'Failed to start Kali container');
    },
  });

  // Stop Kali mutation
  const stopKali = useMutation({
    mutationFn: () => api.system.stopKali(),
    onSuccess: () => {
      toast.success('Kali container stopped');
      queryClient.invalidateQueries({ queryKey: ['system-status-global'] });
      queryClient.invalidateQueries({ queryKey: ['docker-status'] });
    },
    onError: (error: any) => {
      toast.error(error?.message || 'Failed to stop Kali container');
    },
  });

  // Pull-latest-image mutation. Used when the user updates Maestro and
  // needs the new container image to land — Docker doesn't auto-refresh
  // a `:latest` tag just because the remote one moved.
  //
  // Mirrors startup-gate.tsx's pull flow: try authenticated pull first
  // using backend-brokered GHCR creds (license-gated), then fall back to
  // anonymous pull (only works if package is public). This way the
  // button works regardless of GHCR visibility setting — if the customer
  // has a valid Cognito session, they get the image either way.
  const pullKali = useMutation({
    mutationFn: async () => {
      // Lazy-import the toolkit-api so the system-status panel doesn't
      // pay the network/dep cost on every render — only when the user
      // actually clicks Pull.
      const { getRegistryCredentials } = await import('@/lib/toolkit-api');
      let pulled = false;
      let lastErr: unknown = null;
      try {
        const creds = await getRegistryCredentials();
        // Cache in Rust AppState so the lifecycle recreate also pulls authed.
        await api.system.setToolkitCredentials(
          creds.username,
          creds.password,
          creds.expires_at ?? null,
        );
        await api.system.pullKaliImageWithAuth(creds.username, creds.password);
        pulled = true;
      } catch (e) {
        lastErr = e;
        console.warn(
          '[pull-kali] authenticated pull failed, trying anonymous:',
          e instanceof Error ? e.message : String(e),
        );
      }
      if (!pulled) {
        try {
          await api.system.pullKaliImage();
          pulled = true;
        } catch (e) {
          lastErr = e;
        }
      }
      if (!pulled) {
        throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
      }
    },
    onMutate: () => {
      toast.loading('Pulling latest Kali image…', { id: 'pull-kali', duration: Infinity });
    },
    onSuccess: () => {
      toast.success(
        kaliRunning
          ? 'Image pulled. Stop and start the Kali container to apply.'
          : 'Image pulled. Start the Kali container to apply.',
        { id: 'pull-kali', duration: 6000 },
      );
      queryClient.invalidateQueries({ queryKey: ['system-status-global'] });
      queryClient.invalidateQueries({ queryKey: ['docker-status'] });
    },
    onError: (error: any) => {
      const msg = error?.message || String(error);
      const friendly = /401|403|unauthorized|forbidden/i.test(msg)
        ? 'Pull failed (auth). Sign in to Maestro Cloud first — the backend brokers GHCR credentials after Cognito login.'
        : msg;
      toast.error(`Pull failed: ${friendly}`, { id: 'pull-kali', duration: 10000 });
    },
  });

  const isKaliActionPending = startKali.isPending || stopKali.isPending || pullKali.isPending;

  // Determine service statuses
  const kaliRunning = dockerStatus?.kali_running ?? status?.docker?.kali_running ?? false;
  // Deep image-drift signal comes from get_system_status (status.docker); the
  // lighter get_docker_status() doesn't carry it. `kaliStale` = running but on
  // the wrong toolkit image — the case that used to hide behind a green check.
  const imageCurrent = status?.docker?.image_current;
  const imageExpected = status?.docker?.image_expected;
  const imageActual = status?.docker?.image_actual ?? undefined;
  const kaliStale = kaliRunning && imageCurrent === false;
  const kaliHealthy = imageCurrent ?? (dockerStatus?.kali_healthy ?? status?.docker?.kali_healthy ?? false);
  const tagOf = (img?: string | null) => (img ? img.split(':').pop() || img : 'unknown');
  const dbConnected = status?.database_connected ?? false;
  const mcpConnected = status?.mcp_server_connected ?? false;
  const mcpToolCount = status?.mcp_tool_count ?? null;
  const claudeAuthed = status?.claude_authenticated ?? false;
  const claudeMode = status?.claude_auth_mode || 'oauth';
  const claudeModeLabel =
    claudeMode === 'api_key' ? 'API key'
    : 'OAuth';

  // Infrastructure store (web mode)
  const infraStatus = useInfraStore((s) => s.status);
  const infraHealthy = useInfraStore((s) => s.healthy);
  const infraStart = useInfraStore((s) => s.startInstance);
  const infraStop = useInfraStore((s) => s.stopInstance);
  const [infraActionPending, setInfraActionPending] = useState(false);

  const handleInfraAction = async (action: 'start' | 'stop') => {
    setInfraActionPending(true);
    try {
      if (action === 'start') {
        await infraStart();
        toast.success('Environment started');
      } else {
        await infraStop();
        toast.success('Environment stopped');
      }
    } catch (e: any) {
      toast.error(e?.message || `Failed to ${action} environment`);
    }
    setInfraActionPending(false);
  };

  // Build services array — different for web vs desktop
  const services: Service[] = isWebMode() ? [
    {
      name: 'Environment',
      icon: Cloud,
      status: infraActionPending ? 'loading'
        : infraStatus === 'running' ? 'up'
        : infraStatus === 'starting' || infraStatus === 'pending' ? 'loading'
        : infraStatus === 'unknown' ? 'unknown'
        : 'down',
      detail: infraStatus === 'running'
        ? (infraHealthy ? 'Healthy' : 'Booting')
        : infraStatus === 'starting' ? 'Starting...'
        : infraStatus === 'not_provisioned' ? 'Not set up'
        : 'Stopped',
      action: infraStatus === 'running' ? 'stop'
        : infraStatus === 'stopped' ? 'start'
        : undefined,
    },
    {
      name: 'MCP Server',
      icon: Server,
      status: infraHealthy ? 'up' : infraStatus === 'running' ? 'loading' : 'down',
      detail: infraHealthy ? 'Connected' : undefined,
    },
  ] : [
    {
      name: 'MCP Server',
      icon: Server,
      // Drive off the actual health-check field, not just whether the
      // wrapping getStatus() call resolved. The Tauri command always returns
      // a SystemStatus payload — even when the in-container MCP HTTP server
      // (port 3001) is dead — so checking isError alone gave a false "up".
      status: isLoading ? 'loading' : (isError || !mcpConnected) ? 'down' : 'up',
      // Deep signal: show the actual tool count the server advertised, not
      // just the app version. "12 tools ready" proves it can serve calls.
      detail: mcpConnected
        ? (mcpToolCount != null ? `${mcpToolCount} tools ready` : 'Connected')
        : undefined,
      troubleshooting: kaliRunning
        ? 'Container is up but the MCP server isn\'t serving tools on :3001 — try Stop+Start of the Kali container.'
        : 'Start the Kali container first — the MCP server runs inside it.',
    },
    {
      name: 'Database',
      icon: Database,
      status: isLoading ? 'loading' : dbConnected ? 'up' : 'down',
      detail: dbConnected ? 'Schema OK' : undefined,
      troubleshooting: 'Database query failed — the SQLite file may be missing, locked, or unmigrated.',
    },
    {
      name: 'Kali Container',
      icon: Container,
      // Honest health: running but on the wrong toolkit image is NOT "up".
      // `kaliStale` renders as 'unknown' (not green) with an "Update available"
      // detail + the Pull button — the staleness can no longer hide.
      status: isKaliActionPending ? 'loading' : !kaliRunning ? 'down' : kaliStale ? 'unknown' : 'up',
      detail: !kaliRunning
        ? 'Stopped'
        : kaliStale
          ? `Update available — on ${tagOf(imageActual)}, expected ${tagOf(imageExpected)}`
          : `Healthy · ${tagOf(imageExpected)}`,
      troubleshooting: 'Click the button to start the container',
      action: kaliRunning ? 'stop' : 'start',
    },
    {
      name: `Claude (${claudeModeLabel})`,
      icon: KeyRound,
      status: isLoading ? 'loading' : claudeAuthed ? 'up' : 'down',
      troubleshooting:
        claudeMode === 'api_key'
          ? 'Add your Anthropic API key under Settings → Claude.'
          : 'Open the Terminal pane and click "Connect Claude" to sign in.',
    },
  ];

  // Compute overall status
  const getOverallStatus = (): OverallStatus => {
    if (isLoading) return 'unknown';
    if (isError) return 'critical';

    const upCount = services.filter((s) => s.status === 'up').length;
    if (upCount === services.length) return 'healthy';
    if (upCount >= 2) return 'degraded';
    return 'critical';
  };

  const overall = getOverallStatus();

  // Status colors and text
  const statusConfig = {
    healthy: { color: 'bg-green-500', text: 'All Systems Operational' },
    degraded: { color: 'bg-yellow-500', text: 'Partial Outage' },
    critical: { color: 'bg-red-500', text: 'Service Disruption' },
    unknown: { color: 'bg-gray-400 animate-pulse', text: 'Checking...' },
  };

  const serviceStatusColors = {
    up: 'bg-green-500/10 text-green-600',
    down: 'bg-red-500/10 text-red-600',
    unknown: 'bg-gray-500/10 text-gray-500',
    loading: 'bg-primary/10 text-primary',
  };

  const handleServiceAction = (action: 'start' | 'stop') => {
    if (isWebMode()) {
      handleInfraAction(action);
    } else if (action === 'start') {
      startKali.mutate();
    } else {
      stopKali.mutate();
    }
  };

  return (
    <Popover open={isOpen} onOpenChange={setIsOpen}>
      <PopoverTrigger asChild>
        <button className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors w-full group">
          <div className={cn('h-2 w-2 rounded-full shrink-0', statusConfig[overall].color)} />
          <span className="flex-1 text-left truncate">{statusConfig[overall].text}</span>
          <ChevronDown
            className={cn('h-3 w-3 transition-transform opacity-0 group-hover:opacity-100', isOpen && 'rotate-180')}
          />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" side="top" align="start" sideOffset={8}>
        {/* Header */}
        <div className="flex items-center justify-between p-3 border-b bg-muted/30">
          <span className="font-medium text-sm">System Status</span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={() => {
              refetch();
              queryClient.invalidateQueries({ queryKey: ['docker-status'] });
            }}
            disabled={isLoading}
          >
            <RefreshCw className={cn('h-3 w-3', isLoading && 'animate-spin')} />
          </Button>
        </div>

        {/* Services List */}
        <div className="p-2 space-y-1">
          {services.map((service) => (
            <div
              key={service.name}
              className="flex items-start gap-3 p-2 rounded-md hover:bg-muted/50 transition-colors"
            >
              <div className={cn('p-1.5 rounded shrink-0', serviceStatusColors[service.status])}>
                {service.status === 'loading' ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <service.icon className="h-4 w-4" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{service.name}</span>
                  {service.status === 'up' && <CheckCircle2 className="h-3 w-3 text-green-500 shrink-0" />}
                  {service.status === 'down' && <XCircle className="h-3 w-3 text-red-500 shrink-0" />}
                  {service.status === 'loading' && (
                    <Loader2 className="h-3 w-3 text-primary animate-spin shrink-0" />
                  )}
                </div>
                {service.detail && <p className="text-xs text-muted-foreground">{service.detail}</p>}
                {service.status === 'down' && service.troubleshooting && !service.action && (
                  <p className="text-xs text-yellow-600 mt-1">{service.troubleshooting}</p>
                )}
              </div>

              {/* Kali Start/Stop + Pull Latest buttons */}
              {service.action && (
                <div className="flex items-center gap-1 shrink-0">
                  {/* Pull-latest only on the Kali row (action present + Container icon).
                      The pull triggers a `docker pull ghcr.io/...:latest` so the next
                      container start picks up updates after a Maestro release. */}
                  {service.name === 'Kali Container' && !isWebMode() && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2"
                      title="Pull the latest Kali container image from GHCR. Run this after updating Maestro to ensure the container has the newest tooling baked in."
                      onClick={() => pullKali.mutate()}
                      disabled={isKaliActionPending || infraActionPending}
                    >
                      {pullKali.isPending ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <DownloadCloud className="h-3 w-3" />
                      )}
                    </Button>
                  )}
                  <Button
                    variant={service.action === 'start' ? 'default' : 'outline'}
                    size="sm"
                    className="h-7 px-2"
                    onClick={() => handleServiceAction(service.action!)}
                    disabled={isKaliActionPending || infraActionPending}
                  >
                    {isKaliActionPending && !pullKali.isPending ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : service.action === 'start' ? (
                      <>
                        <Play className="h-3 w-3 mr-1" />
                        Start
                      </>
                    ) : (
                      <>
                        <Square className="h-3 w-3 mr-1" />
                        Stop
                      </>
                    )}
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Warning if Kali is down */}
        {!kaliRunning && !isLoading && (
          <div className="px-3 pb-3">
            <div className="flex items-start gap-2 p-2 rounded-md bg-yellow-500/10 text-yellow-700">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <p className="text-xs">Kali container is required for security scanning. Click Start above.</p>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="p-2 border-t">
          <a href="/config" className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1">
            View full configuration →
          </a>
        </div>
      </PopoverContent>
    </Popover>
  );
}
