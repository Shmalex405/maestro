'use client';

// Coverage Dashboard W4 — the "deployed + reachable + vulnerable" card (the
// Wiz money-shot). Renders one correlation: a CVE-bearing image running on an
// internet-facing cloud workload. Each card shows the proven chain
// (image → workload → exposure) and a "Prove it" action that escalates to the
// on-demand LLM exploit (see lib/prove-finding.ts).

import {
  ArrowRight,
  Cloud,
  Container,
  Globe,
  Link2,
  Loader2,
  Network,
  ShieldAlert,
  Webhook,
  Zap,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { severityStyle } from '@/lib/severity';
import type { CloudCorrelation } from '@/lib/types';

const EXPOSURE_ICON: Record<string, typeof Globe> = {
  alb: Network,
  nlb: Network,
  function_url: Link2,
  public_ip: Globe,
  api_gateway: Webhook,
};

const EXPOSURE_LABEL: Record<string, string> = {
  alb: 'ALB',
  nlb: 'NLB',
  function_url: 'Function URL',
  public_ip: 'Public IP',
  api_gateway: 'API Gateway',
};

/** Strip the registry host from an image ref: `…amazonaws.com/app:tag` → `app:tag`. */
function shortImage(ref: string): string {
  const slash = ref.lastIndexOf('/');
  return slash >= 0 ? ref.slice(slash + 1) : ref;
}

export function CorrelationCard({
  c,
  onProve,
  proving,
}: {
  c: CloudCorrelation;
  onProve?: (c: CloudCorrelation) => void;
  proving?: boolean;
}) {
  const sev = severityStyle(c.severity);
  const ExpIcon = EXPOSURE_ICON[c.exposed_via ?? ''] ?? Globe;
  const asset = c.asset_name ?? c.resource_arn.split('/').pop() ?? c.resource_arn;
  const canProve = Boolean(onProve && c.endpoint);

  return (
    <div className={cn('glass-card hover-lift rounded-lg border p-4', sev.border)}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <ShieldAlert className={cn('h-4 w-4 shrink-0', sev.text)} />
          <span
            className={cn(
              'rounded px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide',
              sev.badge,
            )}
          >
            {sev.label}
          </span>
          {c.cve && (
            <span className="truncate font-mono text-xs text-muted-foreground">{c.cve}</span>
          )}
        </div>
        <span className="whitespace-nowrap text-[10px] font-bold uppercase tracking-wider text-red-400">
          Reachable · Vulnerable
        </span>
      </div>

      {/* The proven chain: image → workload → exposure */}
      <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
        <span
          className="flex items-center gap-1 font-mono text-xs text-muted-foreground"
          title={c.image_ref}
        >
          <Container className="h-3.5 w-3.5" /> {shortImage(c.image_ref)}
        </span>
        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground/50" />
        <span className="flex items-center gap-1 font-medium" title={c.resource_arn}>
          <Cloud className="h-3.5 w-3.5 text-sky-400" /> {asset}
          <span className="text-[10px] text-muted-foreground">({c.resource_type})</span>
        </span>
        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground/50" />
        <span className="flex items-center gap-1 text-xs text-amber-300">
          <ExpIcon className="h-3.5 w-3.5" />{' '}
          {EXPOSURE_LABEL[c.exposed_via ?? ''] ?? 'Internet-facing'}
        </span>
      </div>

      {c.endpoint && (
        <div className="mt-1.5 truncate font-mono text-xs text-muted-foreground">{c.endpoint}</div>
      )}

      {onProve && (
        <div className="mt-3 flex justify-end">
          <button
            type="button"
            disabled={!canProve || proving}
            onClick={() => onProve(c)}
            title={canProve ? 'Escalate to an on-demand LLM exploit' : 'No reachable endpoint to exploit'}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-semibold transition-colors',
              'bg-red-500/10 text-red-300 hover:bg-red-500/20',
              'disabled:cursor-not-allowed disabled:opacity-40',
            )}
          >
            {proving ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Zap className="h-3.5 w-3.5" />
            )}
            Prove it
          </button>
        </div>
      )}
    </div>
  );
}
