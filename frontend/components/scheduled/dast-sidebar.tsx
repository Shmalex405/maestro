'use client';

// =============================================================================
// Scheduled DAST — section sub-sidebar.
//
// A second, narrower sidebar shown beside the main Maestro sidebar for every
// /scheduled/* route, so the section feels like its own product area. The main
// sidebar stays visible (its "Scheduled DAST" link highlights for any
// /scheduled/* path); this nav is purely intra-section.
// =============================================================================

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import {
  LayoutDashboard,
  History,
  ShieldAlert,
  Globe,
  Boxes,
  CalendarClock,
  FileText,
  Settings2,
  ArrowLeft,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/tauri-api';
import { tierOf } from '@/components/scheduled/dast-shared';
import type { Severity } from '@/lib/types';

interface DastNavItem {
  name: string;
  href: string;
  icon: LucideIcon;
  /** Exact-match active detection (for the index route). */
  exact?: boolean;
}

const NAV: DastNavItem[] = [
  { name: 'Overview', href: '/scheduled', icon: LayoutDashboard, exact: true },
  { name: 'Applications', href: '/scheduled/applications', icon: Boxes },
  { name: 'Scans', href: '/scheduled/scans', icon: History },
  { name: 'Vulnerabilities', href: '/scheduled/vulnerabilities', icon: ShieldAlert },
  { name: 'Targets', href: '/scheduled/targets', icon: Globe },
  { name: 'Schedules', href: '/scheduled/schedules', icon: CalendarClock },
  { name: 'Reports', href: '/scheduled/reports', icon: FileText },
  { name: 'Settings', href: '/scheduled/settings', icon: Settings2 },
];

export function DastSidebar() {
  const pathname = usePathname();

  // Escalation queue badge: new unproven Crit/High DAST candidates awaiting a
  // Prove run. Shares the 'dast-vulns' query cache with the workbench.
  const { data: vulns } = useQuery({
    queryKey: ['dast-vulns'],
    queryFn: () => api.findings.list({ scan_only: 'true', limit: 300 }),
  });
  const queueCount = (vulns?.data ?? []).filter(
    (f) => tierOf(f) === 'unproven' && (['critical', 'high'] as Severity[]).includes(f.severity),
  ).length;

  const isActive = (item: DastNavItem) =>
    item.exact ? pathname === item.href : pathname === item.href || pathname.startsWith(`${item.href}/`);

  return (
    <aside className="sticky top-0 flex h-[calc(100vh-3rem)] w-[208px] shrink-0 flex-col self-start border-r border-border/40 bg-white/[0.01]">
      <div className="px-3 pt-4 pb-3">
        <Link
          href="/coverage"
          className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground/70 transition-colors hover:text-primary"
        >
          <ArrowLeft className="h-3 w-3" /> Maestro
        </Link>
        <div className="mt-3 flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/10">
            <CalendarClock className="h-4 w-4 text-primary" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold leading-tight">Scheduled DAST</p>
            <p className="text-[10px] text-muted-foreground/70">Continuous scanning</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-2 py-2">
        {NAV.map((item) => {
          const active = isActive(item);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                active
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-white/[0.03] hover:text-foreground',
              )}
            >
              <Icon className={cn('h-4 w-4 shrink-0', active ? 'text-primary' : 'text-muted-foreground')} />
              <span className="truncate">{item.name}</span>
              {item.href === '/scheduled/vulnerabilities' && queueCount > 0 ? (
                <span
                  className="ml-auto rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-amber-400"
                  title={`${queueCount} unproven Crit/High awaiting Prove`}
                >
                  {queueCount}
                </span>
              ) : (
                active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary" />
              )}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
