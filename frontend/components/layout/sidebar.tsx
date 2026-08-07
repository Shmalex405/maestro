'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import Image from 'next/image';
import {
  LayoutDashboard,
  Radar,
  AlertTriangle,
  Settings,
  ScrollText,
  FileText,
  FolderGit2,
  Upload,
  Users,
  HelpCircle,
  BookOpen,
  CalendarClock,
  Globe,
  Cloud,
  KeyRound,
  FileCode2,
  FolderKanban,
  Bot,
  Workflow,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { SystemStatus } from './system-status';
import { isWebMode } from '@/lib/deploy-mode';
import { isIdentityEnabled } from '@/lib/identity-enabled';
import { isAiEnabled } from '@/lib/ai-enabled';
import { useLiveAssessmentSessions } from '@/lib/hooks/use-live-assessment-sessions';

interface NavItem {
  name: string;
  href: string;
  icon: LucideIcon;
  /** When true, the item renders unless NEXT_PUBLIC_IDENTITY_ENABLED=false.
   *  Mirrors the isWebMode()/codex-enabled gating already applied to other
   *  nav items — lets a web/cloud-only deployment hide the Identity surface. */
  identityOnly?: boolean;
  /** When true, the item renders unless NEXT_PUBLIC_AI_ENABLED=false — lets a
   *  deployment that doesn't sell AI testing hide the AI/LLM surface. */
  aiOnly?: boolean;
}

interface NavSection {
  /** Uppercase divider label, or null for the very first (top) group. */
  section: string | null;
  items: NavItem[];
}

// Sectioned IA (replaces the old flat 11-item list). Section headers are a
// purely-visual grouping — the active-state logic and live-session badge below
// are unchanged. The SURFACES section holds the per-surface aggregation pages
// (Web & API, Cloud, Identity) plus the continuous Scheduled DAST tier;
// Identity is flag-gated (identityOnly) so a web/cloud-only build can hide it.
const navSections: NavSection[] = [
  {
    section: 'POSTURE',
    items: [
      { name: 'Coverage', href: '/', icon: LayoutDashboard },
      { name: 'Findings', href: '/findings', icon: AlertTriangle },
      { name: 'Attack Graph', href: '/graph', icon: Workflow },
    ],
  },
  {
    section: 'SURFACES',
    items: [
      { name: 'Web & API', href: '/surfaces/web', icon: Globe },
      { name: 'Cloud', href: '/surfaces/cloud', icon: Cloud },
      { name: 'Identity / IDP', href: '/surfaces/identity', icon: KeyRound, identityOnly: true },
      { name: 'AI / LLM', href: '/surfaces/ai', icon: Bot, aiOnly: true },
      { name: 'Code Security', href: '/surfaces/code', icon: FileCode2 },
      { name: 'Scheduled DAST', href: '/scheduled', icon: CalendarClock },
    ],
  },
  {
    section: 'WORK',
    items: [
      { name: 'Projects', href: '/projects', icon: FolderKanban },
      { name: 'Assessments', href: '/assessments', icon: Radar },
      { name: 'Reports', href: '/reports', icon: FileText },
      { name: 'Code Repos', href: '/repositories', icon: FolderGit2 },
      { name: 'Import', href: '/import', icon: Upload },
    ],
  },
  {
    section: 'ADMIN',
    items: [
      { name: 'Users', href: '/users', icon: Users },
      { name: 'Docs', href: '/docs', icon: BookOpen },
      { name: 'Help', href: '/help', icon: HelpCircle },
      { name: 'Config', href: '/config', icon: Settings },
      { name: 'Audit Logs', href: '/audit-logs', icon: ScrollText },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  // Global awareness: how many tmux-backed assessments are live across both
  // brains. Pulses next to the Assessments link so users see at a glance
  // that work is in flight even if they've navigated to Findings, Reports,
  // etc. The hook polls every 10s + on focus, so the badge is current.
  const { liveIds } = useLiveAssessmentSessions();
  const liveCount = liveIds.size;

  return (
    <div className="flex h-full w-[220px] flex-col border-r border-sidebar-border bg-sidebar">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 px-4">
        <Image
          src="/maestro-icon.png"
          alt="Maestro"
          width={32}
          height={32}
          className="h-8 w-8"
        />
        <div className="flex flex-col">
          <span className="font-semibold text-[15px] leading-tight tracking-tight text-foreground">
            Maestro
          </span>
          <span className="text-[10px] text-muted-foreground leading-tight">
            Security Platform
          </span>
        </div>
      </div>

      {/* Divider */}
      <div className="mx-3 h-px bg-sidebar-border" />

      {/* Navigation */}
      <nav className="flex-1 space-y-3 px-2 py-3 overflow-y-auto">
        {navSections.map((group) => {
          const items = group.items.filter((item) => {
            if (isWebMode() && item.href === '/repositories') return false;
            if (item.identityOnly && !isIdentityEnabled()) return false;
            if (item.aiOnly && !isAiEnabled()) return false;
            return true;
          });
          if (items.length === 0) return null;

          return (
            <div key={group.section ?? 'top'} className="space-y-0.5">
              {group.section && (
                <div className="px-2.5 pt-1 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
                  {group.section}
                </div>
              )}
              {items.map((item) => {
                const isActive = pathname === item.href ||
                  (item.href !== '/' && pathname.startsWith(item.href));

                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={cn(
                      'group flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[13px] font-medium transition-all duration-150',
                      isActive
                        ? 'bg-primary/12 text-primary shadow-[inset_0_0_0_1px_oklch(0.72_0.17_55_/_12%)]'
                        : 'text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground'
                    )}
                  >
                    <item.icon className={cn(
                      'h-4 w-4 shrink-0 transition-colors',
                      isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-sidebar-foreground'
                    )} />
                    <span>{item.name}</span>
                    {/* Live-session count next to Assessments — only when at least
                        one tmux session is running. Pulses so it's obvious without
                        being noisy. Click the row to jump to the assessments list,
                        where each row's individual live badge shows which one. */}
                    {item.href === '/assessments' && liveCount > 0 && (
                      <span
                        title={`${liveCount} live ${liveCount === 1 ? 'session' : 'sessions'} — click to view`}
                        className="ml-auto inline-flex items-center gap-1 rounded-full bg-green-500/10 border border-green-500/40 px-1.5 py-0 text-[10px] font-semibold text-green-600 dark:text-green-400"
                      >
                        <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" />
                        {liveCount}
                      </span>
                    )}
                    {isActive && item.href !== '/assessments' && (
                      <div className="ml-auto h-1.5 w-1.5 rounded-full bg-primary animate-pulse-glow" />
                    )}
                  </Link>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Footer - System Status */}
      <div className="mx-3 h-px bg-sidebar-border" />
      <div className="p-3">
        <SystemStatus />
      </div>
    </div>
  );
}
