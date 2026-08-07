'use client';

import { Button } from '@/components/ui/button';
import { RefreshCw, Circle, XCircle, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface TerminalStatusBarProps {
  status: 'spawning' | 'running' | 'exited' | 'error' | 'detached';
  assessmentName?: string;
  exitCode?: number;
  onRestart?: () => void;
}

export function TerminalStatusBar({
  status,
  assessmentName,
  exitCode,
  onRestart,
}: TerminalStatusBarProps) {
  const statusConfig = {
    spawning: { color: 'text-yellow-500', bg: 'bg-yellow-500', label: 'Starting...' },
    running: { color: 'text-green-500', bg: 'bg-green-500', label: 'Running' },
    detached: { color: 'text-primary', bg: 'bg-primary', label: 'Running (detached)' },
    exited: { color: 'text-muted-foreground', bg: 'bg-muted-foreground', label: `Exited${exitCode !== undefined ? ` (${exitCode})` : ''}` },
    error: { color: 'text-red-500', bg: 'bg-red-500', label: 'Error' },
  };

  const config = statusConfig[status];

  return (
    <div className="flex items-center justify-between px-3 py-1.5 bg-muted/30 border-t text-xs">
      <div className="flex items-center gap-2">
        {status === 'spawning' ? (
          <Loader2 className={cn('h-3 w-3 animate-spin', config.color)} />
        ) : status === 'error' ? (
          <XCircle className={cn('h-3 w-3', config.color)} />
        ) : (
          <Circle className={cn('h-3 w-3 fill-current', config.color)} />
        )}
        <span className="text-muted-foreground">{config.label}</span>
        {assessmentName && (
          <>
            <span className="text-muted-foreground/50">|</span>
            <span className="text-muted-foreground truncate max-w-[200px]">{assessmentName}</span>
          </>
        )}
      </div>

      {(status === 'exited' || status === 'error') && onRestart && (
        <Button
          variant="ghost"
          size="sm"
          className="h-5 text-xs gap-1 px-2"
          onClick={onRestart}
        >
          <RefreshCw className="h-3 w-3" />
          Restart
        </Button>
      )}
    </div>
  );
}
