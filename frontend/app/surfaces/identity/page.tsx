'use client';

// =============================================================================
// Identity / IDP surface (/surfaces/identity) — the identity-plane drill-down.
//
// Active Directory + Entra ID + M365/O365 + Okta + Google Workspace + Ping
// red teaming (see docs/identity-redteam-plan.md). An identity assessment runs only when
// `identity_targets` is defined in config/scope.yml; its findings land in the
// `identity` category (backend-rs category_from_source) and surface here via the
// shared surface lens (lib/surface.ts → identity: ['identity']).
//
// Aggregation view — same shared FilterBar + DashboardFindingsTable the cloud
// and web surfaces use, pinned to the identity surface. No parallel data path.
// The page stays behind NEXT_PUBLIC_IDENTITY_ENABLED (default on); when no
// identity target has been scanned the shared table renders its own empty state
// and the coverage card below explains what scoping a target unlocks.
// =============================================================================

import { Suspense, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { KeyRound, ArrowRight, Building2, Cloud, Mail, ShieldCheck, Fingerprint, Chrome, Network } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { FilterBar } from '@/components/dashboard/filter-bar';
import { DashboardFindingsTable } from '@/components/dashboard/dashboard-findings-table';
import { SurfaceAnalytics } from '@/components/dashboard/surface-analytics';
import { FindingsOverTime } from '@/components/dashboard/findings-over-time';
import { api } from '@/lib/tauri-api';
import { useDashboardFilterStore } from '@/lib/stores/dashboard-filter-store';

// The identity plane spans every major IDP, not just Microsoft. Entra-first
// per docs/identity-redteam-plan.md §1 (the cloud-adjacent IDP is the fastest
// path to value); AD, M365, Okta, Google Workspace, and Ping follow. Each
// provider is gated on an `identity_targets` entry of its `provider` kind.
const COVERAGE = [
  {
    icon: Cloud,
    title: 'Microsoft Entra ID (Azure AD)',
    detail:
      'Tenant/user/directory enumeration, password spray, illicit consent grants, device-code phishing, token replay, conditional-access & service-principal abuse, primary-refresh-token attacks.',
  },
  {
    icon: Building2,
    title: 'On-prem Active Directory',
    detail:
      'BloodHound attack-path mapping, Kerberoasting / AS-REP roasting, ADCS abuse (ESC1–13), DCSync, ACL & delegation abuse, LAPS read, NTLM relay.',
  },
  {
    icon: Mail,
    title: 'Microsoft 365 / O365',
    detail:
      'Mailbox / SharePoint / OneDrive / Teams access, eDiscovery & app-registration abuse, AADInternals / Golden SAML.',
  },
  {
    icon: Fingerprint,
    title: 'Okta',
    detail:
      'Org/user enumeration, lockout-aware password spray, OAuth/OIDC illicit-consent abuse, SAML assertion testing, API-token and MFA-factor enumeration.',
  },
  {
    icon: Chrome,
    title: 'Google Workspace',
    detail:
      'Domain/user/admin-role enumeration (Admin SDK Directory), domain-wide-delegation service-account OAuth abuse, SAML SSO testing, OAuth token replay.',
  },
  {
    icon: Network,
    title: 'Ping (PingOne / PingFederate)',
    detail:
      'SSO endpoint & federation enumeration, lockout-aware spray, OAuth/OIDC and SAML federation abuse, token testing.',
  },
];

function IdentitySurface() {
  const setSurface = useDashboardFilterStore((s) => s.setSurface);

  // Pin the FilterBar to the identity surface on mount.
  useEffect(() => {
    setSurface('identity');
  }, [setSurface]);

  // Count identity findings for the header chip — same backend filter the shared
  // table uses (category=identity), so the chip and the grid stay in lockstep.
  const { data: findings } = useQuery({
    queryKey: ['identity-finding-count'],
    queryFn: () => api.findings.list({ category: 'identity' }),
  });
  const identityCount = Array.isArray(findings) ? findings.length : 0;

  return (
    <div className="space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-primary/10 p-2">
            <KeyRound className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Identity / IDP</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Active Directory, Entra ID, and M365/O365 red teaming — the identity plane.
            </p>
          </div>
        </div>
        <Link href="/findings?surface=identity">
          <Button variant="outline" size="sm" className="gap-1.5">
            All identity findings <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </Link>
      </div>

      {/* Shared FilterBar — surface pinned to identity */}
      <div className="glass-card rounded-xl p-3">
        <FilterBar showSurface={false} />
      </div>

      {/* Analytics strip — severity tiles (clickable filters) + donut + breakdown */}
      <SurfaceAnalytics />

      {/* Findings over time (trend) — locked to the identity surface */}
      <FindingsOverTime initialDays={30} category="identity" />

      {/* Identity findings (surface lens) */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <KeyRound className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Identity findings</span>
          {identityCount > 0 && (
            <span className="ml-auto text-xs font-semibold text-primary">{identityCount}</span>
          )}
        </div>
        <DashboardFindingsTable />
      </div>

      {/* Coverage card — what scoping an identity_target unlocks. */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">What identity testing covers</span>
          <span className="text-[10px] text-muted-foreground">
            runs only when <span className="font-mono">identity_targets</span> is in scope
          </span>
        </div>
        <div className="divide-y divide-border/40">
          {COVERAGE.map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.title} className="flex items-start gap-3 p-4">
                <div className="rounded-lg bg-muted/50 p-2">
                  <Icon className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="flex-1">
                  <span className="text-sm font-medium">{item.title}</span>
                  <p className="mt-0.5 text-xs text-muted-foreground">{item.detail}</p>
                </div>
              </div>
            );
          })}
        </div>
        <div className="border-t border-border/40 px-4 py-3 text-xs text-muted-foreground">
          Scope a target in <span className="font-mono">config/scope.yml</span> — see the deployment
          guide at <span className="font-mono">docs/user-guide/identity-targets/overview.md</span>.
          Every spray is account-lockout-gated; state-changing steps are opt-in and pause for
          confirmation.
        </div>
      </div>
    </div>
  );
}

export default function IdentitySurfacePage() {
  return (
    <Suspense fallback={<div className="p-6"><Skeleton className="h-40 w-full" /></div>}>
      <IdentitySurface />
    </Suspense>
  );
}
