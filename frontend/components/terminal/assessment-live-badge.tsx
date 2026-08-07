'use client';

import { useAssessmentLiveStatus } from '@/lib/hooks/use-assessment-live-status';
import { cn } from '@/lib/utils';

interface AssessmentLiveBadgeProps {
  assessmentId: string | null | undefined;
  /** Compact pill for use in lists; default = full text + dot for header. */
  variant?: 'compact' | 'full';
  className?: string;
}

/**
 * Visual indicator for whether an assessment's claude session is currently
 * running inside the Kali container's tmux. Polls every 10s.
 *
 * - `live`  → green dot (pulsing) — pane reopen will reattach
 * - `idle`  → gray  dot           — pane reopen starts fresh
 * - `unknown` (initial / error) → renders nothing so we don't flash a
 *   misleading "Idle" state before the first probe completes
 */
export function AssessmentLiveBadge({
  assessmentId,
  variant = 'full',
  className,
}: AssessmentLiveBadgeProps) {
  const status = useAssessmentLiveStatus(assessmentId);

  if (status === 'unknown') return null;

  const isLive = status === 'live';

  if (variant === 'compact') {
    return (
      <span
        title={isLive ? 'Live session — reopening will reattach' : 'Session ended'}
        className={cn(
          'inline-flex h-2 w-2 rounded-full shrink-0',
          isLive ? 'bg-green-500 animate-pulse' : 'bg-muted-foreground/30',
          className,
        )}
        aria-label={isLive ? 'Live session' : 'Session ended'}
      />
    );
  }

  return (
    <span
      title={isLive ? 'Live session — reopening will reattach' : 'Session ended — start fresh'}
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border',
        isLive
          ? 'border-green-500/40 bg-green-500/10 text-green-600 dark:text-green-400'
          : 'border-border bg-muted/40 text-muted-foreground',
        className,
      )}
    >
      <span
        className={cn(
          'h-1.5 w-1.5 rounded-full',
          isLive ? 'bg-green-500 animate-pulse' : 'bg-muted-foreground/40',
        )}
      />
      {isLive ? 'Live' : 'Idle'}
    </span>
  );
}
