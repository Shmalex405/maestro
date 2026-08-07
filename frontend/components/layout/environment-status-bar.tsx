'use client';

import { useEffect, useState, useCallback } from 'react';
import { isWebMode } from '@/lib/deploy-mode';
import { useInfraStore, type InfraStatus } from '@/lib/stores/infrastructure-store';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { AnimatePresence, motion } from 'framer-motion';
import {
  CheckCircle2,
  Loader2,
  StopCircle,
  AlertCircle,
  HelpCircle,
  RefreshCw,
} from 'lucide-react';

function StatusIcon({ status }: { status: InfraStatus }) {
  switch (status) {
    case 'running':
      return <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />;
    case 'starting':
    case 'pending':
    case 'stopping':
      return <Loader2 className="h-3.5 w-3.5 text-amber-400 animate-spin" />;
    case 'stopped':
      return <StopCircle className="h-3.5 w-3.5 text-red-400" />;
    case 'error':
      return <AlertCircle className="h-3.5 w-3.5 text-red-400" />;
    case 'not_provisioned':
      return <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />;
    default:
      return null;
  }
}

function statusLabel(status: InfraStatus, healthy: boolean): string {
  switch (status) {
    case 'running':
      return healthy ? 'Environment Running' : 'Environment Running (services starting...)';
    case 'starting':
    case 'pending':
      return 'Starting Environment...';
    case 'stopping':
      return 'Stopping Environment...';
    case 'stopped':
      return 'Environment Stopped';
    case 'error':
      return 'Environment Error';
    case 'not_provisioned':
      return 'Environment Not Set Up';
    default:
      return '';
  }
}

function barColorClasses(status: InfraStatus, healthy: boolean): string {
  if (status === 'running' && healthy) {
    return 'border-green-500/20 bg-green-500/5';
  }
  if (status === 'running' && !healthy) {
    return 'border-amber-500/20 bg-amber-500/5';
  }
  if (status === 'starting' || status === 'pending' || status === 'stopping') {
    return 'border-amber-500/20 bg-amber-500/5';
  }
  if (status === 'stopped') {
    return 'border-red-500/20 bg-red-500/5';
  }
  if (status === 'error') {
    return 'border-red-500/20 bg-red-500/5';
  }
  if (status === 'not_provisioned') {
    return 'border-border/50 bg-muted/30';
  }
  return '';
}

export function EnvironmentStatusBar() {
  const status = useInfraStore((s) => s.status);
  const healthy = useInfraStore((s) => s.healthy);
  const error = useInfraStore((s) => s.error);
  const checkStatus = useInfraStore((s) => s.checkStatus);
  const startInstance = useInfraStore((s) => s.startInstance);

  const [collapsed, setCollapsed] = useState(false);
  const [starting, setStarting] = useState(false);

  // Don't render in desktop mode
  if (!isWebMode()) return null;

  // Check status on mount and poll every 30s
  // eslint-disable-next-line react-hooks/rules-of-hooks
  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, [checkStatus]);

  // Auto-collapse when running+healthy after 5 seconds
  // eslint-disable-next-line react-hooks/rules-of-hooks
  useEffect(() => {
    if (status === 'running' && healthy) {
      const timer = setTimeout(() => setCollapsed(true), 5000);
      return () => clearTimeout(timer);
    }
    // Expand when status changes to something that needs attention
    setCollapsed(false);
  }, [status, healthy]);

  // eslint-disable-next-line react-hooks/rules-of-hooks
  const handleStart = useCallback(async () => {
    setStarting(true);
    await startInstance();
    setStarting(false);
  }, [startInstance]);

  // Don't render when unknown (still loading initial status)
  if (status === 'unknown') return null;

  const isRunningHealthy = status === 'running' && healthy;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ height: 0, opacity: 0 }}
        animate={{ height: collapsed ? 6 : 36, opacity: 1 }}
        exit={{ height: 0, opacity: 0 }}
        transition={{ duration: 0.2, ease: 'easeInOut' }}
        onClick={() => {
          if (collapsed) setCollapsed(false);
        }}
        className={cn(
          'relative shrink-0 overflow-hidden border-b backdrop-blur-md cursor-pointer select-none',
          barColorClasses(status, healthy),
          collapsed && 'cursor-pointer'
        )}
      >
        {/* Collapsed indicator — thin colored line */}
        {collapsed && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="h-[2px] w-full bg-green-500/30" />
          </div>
        )}

        {/* Expanded content */}
        {!collapsed && (
          <div className="h-9 flex items-center justify-center gap-2 px-4 text-xs">
            <StatusIcon status={status} />

            <span
              className={cn(
                'font-medium',
                isRunningHealthy && 'text-green-400',
                (status === 'starting' || status === 'pending' || status === 'stopping') &&
                  'text-amber-400',
                status === 'stopped' && 'text-red-400',
                status === 'error' && 'text-red-400',
                status === 'not_provisioned' && 'text-muted-foreground'
              )}
            >
              {statusLabel(status, healthy)}
            </span>

            {/* Error message */}
            {status === 'error' && error && (
              <span className="text-red-400/70 truncate max-w-[300px]">{error}</span>
            )}

            {/* Actions */}
            {status === 'stopped' && (
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                onClick={(e) => {
                  e.stopPropagation();
                  handleStart();
                }}
                disabled={starting}
              >
                {starting ? (
                  <Loader2 className="h-3 w-3 animate-spin mr-1" />
                ) : null}
                Start Environment
              </Button>
            )}

            {status === 'error' && (
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                onClick={(e) => {
                  e.stopPropagation();
                  checkStatus();
                }}
              >
                <RefreshCw className="h-3 w-3 mr-1" />
                Retry
              </Button>
            )}

            {status === 'not_provisioned' && (
              <a
                href="/config/cloud"
                className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2"
                onClick={(e) => e.stopPropagation()}
              >
                Setup Guide
              </a>
            )}

            {/* Collapse button for running state */}
            {isRunningHealthy && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setCollapsed(true);
                }}
                className="text-green-400/50 hover:text-green-400 transition-colors ml-1"
                aria-label="Collapse status bar"
              >
                &times;
              </button>
            )}
          </div>
        )}

        {/* Pulse animation for starting state */}
        {(status === 'starting' || status === 'pending') && !collapsed && (
          <motion.div
            className="absolute bottom-0 left-0 h-[2px] bg-amber-400/50"
            initial={{ width: '0%' }}
            animate={{ width: '100%' }}
            transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
          />
        )}
      </motion.div>
    </AnimatePresence>
  );
}
