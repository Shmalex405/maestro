'use client';

import { useState, useEffect } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import {
  Shield,
  Square,
  FileText,
  Clock,
  Target,
  CheckCircle2,
  XCircle,
  Loader2,
  Pause,
  Cloud,
  Container,
  MapPin,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Assessment } from '@/lib/types';
import { AssessmentLiveBadge } from './assessment-live-badge';

interface AssessmentHeaderBarProps {
  assessment: Assessment | null;
  onStop?: () => void;
  onViewReport?: () => void;
}

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  running: { label: 'Running', color: 'bg-primary', icon: <Loader2 className="h-3 w-3 animate-spin" /> },
  completed: { label: 'Completed', color: 'bg-green-500', icon: <CheckCircle2 className="h-3 w-3" /> },
  failed: { label: 'Failed', color: 'bg-red-500', icon: <XCircle className="h-3 w-3" /> },
  cancelled: { label: 'Cancelled', color: 'bg-zinc-500', icon: <Square className="h-3 w-3" /> },
  paused: { label: 'Paused', color: 'bg-yellow-500', icon: <Pause className="h-3 w-3" /> },
  pending: { label: 'Pending', color: 'bg-zinc-400', icon: <Clock className="h-3 w-3" /> },
  not_started: { label: 'Not Started', color: 'bg-zinc-400', icon: <Clock className="h-3 w-3" /> },
};

const TYPE_LABELS: Record<string, string> = {
  full: 'Full Assessment',
  recon: 'Reconnaissance',
  vuln_scan: 'Vulnerability Scan',
  web_app: 'Web App Test',
  code_scan: 'Code Scan',
  api_security: 'API Security',
  cloud_assessment: 'Cloud',
  combined: 'Combined',
  dual_track: 'Dual-Track',
  extreme: 'Extreme',
};

// Provider chip colors mirror config/cloud-accounts/page.tsx so the same
// visual identity follows an account from configuration through assessment.
const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-500',
  azure: 'bg-blue-500',
  gcp: 'bg-red-500',
};

const PROVIDER_LABELS: Record<string, string> = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
};

/** Resolve provider from account ID prefix or explicit field. The wizard
 *  encodes account_id as the user-chosen ID (e.g. "aws-staging"); we sniff
 *  the prefix as a best-effort hint. Falls back to a neutral cloud chip. */
function inferProvider(accountId: string): string | null {
  const lower = accountId.toLowerCase();
  if (lower.startsWith('aws-') || lower.includes('aws')) return 'aws';
  if (lower.startsWith('azure-') || lower.includes('azure')) return 'azure';
  if (lower.startsWith('gcp-') || lower.includes('gcp')) return 'gcp';
  return null;
}

function formatElapsed(startedAt: string | undefined | null): string {
  if (!startedAt) return '--:--';
  const start = new Date(startedAt).getTime();
  const now = Date.now();
  const elapsed = Math.max(0, Math.floor((now - start) / 1000));
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = elapsed % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function AssessmentHeaderBar({ assessment, onStop, onViewReport }: AssessmentHeaderBarProps) {
  const [elapsed, setElapsed] = useState('--:--');

  // Tick elapsed timer
  useEffect(() => {
    if (!assessment?.started_at) return;
    if (assessment.status !== 'running') {
      // Show final elapsed for completed assessments
      setElapsed(formatElapsed(assessment.started_at));
      return;
    }
    setElapsed(formatElapsed(assessment.started_at));
    const interval = setInterval(() => setElapsed(formatElapsed(assessment.started_at)), 1000);
    return () => clearInterval(interval);
  }, [assessment?.started_at, assessment?.status]);

  if (!assessment) return null;

  const status = STATUS_CONFIG[assessment.status] || STATUS_CONFIG.pending;
  const typeLabel = TYPE_LABELS[assessment.type] || assessment.type;
  const isActive = assessment.status === 'running';
  const cloudScope = assessment.options?.cloud_scope;
  const provider = cloudScope ? inferProvider(cloudScope.account_id) : null;
  const providerColor = provider ? PROVIDER_COLORS[provider] : 'bg-zinc-500';
  const providerLabel = provider ? PROVIDER_LABELS[provider] : 'Cloud';

  return (
    <div className="flex items-center gap-3 px-4 py-2 border-b bg-background/95 backdrop-blur-sm">
      {/* Assessment name + type */}
      <div className="flex items-center gap-2 min-w-0">
        <Shield className="h-4 w-4 text-primary shrink-0" />
        <span className="font-medium text-sm truncate">{assessment.name}</span>
        <Badge variant="outline" className="text-[10px] px-1.5 py-0 shrink-0">
          {typeLabel}
        </Badge>
      </div>

      {/* Cloud scope chips — provider, account, regions, optional cluster.
          Renders before target tags so cloud branding leads the eye for
          cloud_assessment and combined types. */}
      {cloudScope && (
        <div className="flex items-center gap-1 min-w-0 overflow-hidden">
          <Badge className={cn('text-white text-[10px] px-1.5 py-0 gap-1 shrink-0', providerColor)}>
            <Cloud className="h-2.5 w-2.5" />
            {providerLabel}
          </Badge>
          <Badge variant="outline" className="text-[10px] px-1.5 py-0 shrink-0 font-mono max-w-[160px] truncate">
            {cloudScope.account_id}
          </Badge>
          {cloudScope.regions.slice(0, 2).map((region) => (
            <Badge key={region} variant="secondary" className="text-[10px] px-1.5 py-0 shrink-0 gap-1">
              <MapPin className="h-2.5 w-2.5" />
              {region}
            </Badge>
          ))}
          {cloudScope.regions.length > 2 && (
            <span className="text-[10px] text-muted-foreground">+{cloudScope.regions.length - 2}</span>
          )}
          {cloudScope.k8s_cluster_id && (
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 shrink-0 gap-1 font-mono max-w-[140px] truncate">
              <Container className="h-2.5 w-2.5" />
              {cloudScope.k8s_cluster_id}
            </Badge>
          )}
        </div>
      )}

      {/* Target tags */}
      <div className="flex items-center gap-1 min-w-0 overflow-hidden">
        {(assessment.targets || []).slice(0, 3).map((target) => (
          <Badge key={target} variant="secondary" className="text-[10px] px-1.5 py-0 shrink-0 max-w-[180px] truncate">
            <Target className="h-2.5 w-2.5 mr-0.5 shrink-0" />
            {target}
          </Badge>
        ))}
        {(assessment.targets || []).length > 3 && (
          <span className="text-[10px] text-muted-foreground">+{assessment.targets!.length - 3}</span>
        )}
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Live-session badge — independent of DB status; reflects whether
          tmux still has the assess-<id> session alive in the container. */}
      <AssessmentLiveBadge assessmentId={assessment.id} />

      {/* Status badge */}
      <Badge className={cn('text-white text-[10px] px-2 py-0 gap-1 shrink-0', status.color)}>
        {status.icon}
        {status.label}
      </Badge>

      {/* Progress bar (when running) */}
      {isActive && assessment.progress > 0 && (
        <div className="w-24 shrink-0">
          <Progress value={assessment.progress} className="h-1.5" />
        </div>
      )}

      {/* Elapsed time */}
      <div className="flex items-center gap-1 text-xs text-muted-foreground shrink-0">
        <Clock className="h-3 w-3" />
        {elapsed}
      </div>

      {/* Quick actions */}
      <div className="flex items-center gap-1 shrink-0">
        {isActive && onStop && (
          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={onStop}>
            <Square className="h-3 w-3 mr-1" />
            Stop
          </Button>
        )}
        {assessment.status === 'completed' && onViewReport && (
          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={onViewReport}>
            <FileText className="h-3 w-3 mr-1" />
            Report
          </Button>
        )}
      </div>
    </div>
  );
}
