/**
 * Shared assessment display helpers.
 *
 * Extracted from app/assessments/page.tsx so the Reports page's
 * "Ran Assessments" section and the per-assessment execution overview can
 * render assessment rows with identical titles, timestamps, and status
 * iconography. Pure move — no behavior change.
 */

import {
  Loader2,
  CheckCircle2,
  Clock,
  XCircle,
  CircleSlash,
} from 'lucide-react';
import type { Assessment } from './types';

// Status config with icons and colors. Keyed by Assessment.status.
// `incomplete` = ran but never completed (idle/archived without deliverables);
// neutral amber, NOT the red error treatment that `failed` gets.
export const statusConfig: Record<string, { icon: typeof Clock; color: string }> = {
  not_started: { icon: Clock, color: 'text-muted-foreground' },
  pending: { icon: Clock, color: 'text-yellow-500' },
  running: { icon: Loader2, color: 'text-primary' },
  completed: { icon: CheckCircle2, color: 'text-green-500' },
  failed: { icon: XCircle, color: 'text-red-500' },
  incomplete: { icon: CircleSlash, color: 'text-amber-500' },
  cancelled: { icon: XCircle, color: 'text-muted-foreground' },
};

export function formatRelativeTime(dateString: string | null | undefined): string {
  if (!dateString) return 'Just now';
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return 'Just now';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m`;
  if (diffHours < 24) return `${diffHours}h`;
  if (diffDays < 30) return `${diffDays}d`;
  return date.toLocaleDateString();
}

// Resolve the best timestamp the backend gave us.
// The backend's AssessmentResponse currently exposes started_at /
// completed_at but NOT created_at / updated_at (the columns don't exist
// in the assessments table — see backend-rs migrations 0001). Fall
// through the chain so we always have something to render.
export function assessmentTimestamp(a: Assessment): string | undefined {
  return a.updated_at || a.created_at || a.started_at || a.completed_at || undefined;
}

/** Display-name map for assessment types — surfaced in titles. */
export const ASSESSMENT_TYPE_LABELS: Record<string, string> = {
  full: 'Full Assessment',
  recon: 'Reconnaissance Scan',
  vuln_scan: 'Vulnerability Scan',
  web_app: 'Web App Test',
  code_scan: 'Code Security Scan',
  exploit_validation: 'Exploit Validation',
  cycode_validation: 'Cycode Validation',
  custom: 'Custom Assessment',
};

// Generate display title like "Assessment Type - target"
export function getDisplayTitle(assessment: Assessment): string {
  const typeName = ASSESSMENT_TYPE_LABELS[assessment.type] || 'Security Assessment';
  const target = assessment.targets?.[0] || assessment.repo_paths?.[0] || '';

  // Extract domain/hostname from target
  let shortTarget = target;
  try {
    if (target.startsWith('http')) {
      shortTarget = new URL(target).hostname;
    } else if (target.includes('/')) {
      // For paths, get the last segment
      shortTarget = target.split('/').pop() || target;
    }
  } catch {
    // Keep original
  }

  if (shortTarget) {
    return `${typeName} - ${shortTarget}`;
  }
  return assessment.name || typeName;
}
