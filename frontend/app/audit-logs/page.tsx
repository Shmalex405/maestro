'use client';

import { Fragment, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type { AuditLog } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { SearchableSelect } from '@/components/ui/searchable-select';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import {
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Activity,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { cn } from '@/lib/utils';

// Action keys whose presence in `details` means "background machinery
// changed something" rather than "user did something deliberate". When
// the "Hide background updates" toggle is on, we drop any *.update row
// whose details ONLY contain keys from this set.
const BACKGROUND_UPDATE_KEYS = new Set([
  'progress',
  'status',
  'current_step',
  'findings_count',
  'critical_count',
  'high_count',
  'medium_count',
  'low_count',
  'completed_at',
  'started_at',
  'updated_at',
  'error_message',
]);

// Actions that should pop visually — destructive or sensitive.
const DESTRUCTIVE_ACTIONS = new Set([
  'assessment.delete',
  'finding.delete',
  'project.delete',
  'repository.delete',
  'user.delete',
  'user.role.change',
  'org.member.remove',
]);

// Resource types we know about. Used both for the resource-type filter
// dropdown and to map mixed-case backend values to a stable set.
const RESOURCE_TYPES = ['assessment', 'finding', 'project', 'repository', 'user', 'integration'];

function formatRelativeTime(dateString?: string | null): string {
  if (!dateString) return '—';
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return '—';
  const diffMs = Date.now() - date.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMs / 3_600_000);
  const diffDays = Math.floor(diffMs / 86_400_000);
  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 30) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

function isBackgroundUpdate(log: AuditLog): boolean {
  const action = (log.action || log.tool || '').toLowerCase();
  if (!action.endsWith('.update')) return false;
  const details = log.details;
  if (!details || typeof details !== 'object') return false;
  const keys = Object.keys(details);
  if (keys.length === 0) return false;
  return keys.every((k) => BACKGROUND_UPDATE_KEYS.has(k));
}

function resolveAction(log: AuditLog): string {
  return log.action || log.tool || '—';
}

function resolveResourceType(log: AuditLog): string | null {
  if (log.resource_type) return log.resource_type.toLowerCase();
  // Derive from action prefix (e.g. "assessment.create" → "assessment")
  const action = resolveAction(log);
  if (action.includes('.')) return action.split('.')[0].toLowerCase();
  return null;
}

function resolveResourceLabel(log: AuditLog): string {
  const t = resolveResourceType(log);
  const id = log.resource_id || log.target;
  if (!t && !id) return '—';
  if (!id) return t || '—';
  return `${t || 'resource'}: ${id.slice(0, 12)}`;
}

function resolveWho(log: AuditLog): string {
  return log.user_email || log.user_id || log.user || 'system';
}

function resolveWhen(log: AuditLog): string | undefined {
  return log.created_at || log.timestamp;
}

// Render a few key:value pairs from `details`. Long values truncate.
function detailPreview(log: AuditLog): string {
  if (log.error) return log.error;
  const d = log.details;
  if (!d || typeof d !== 'object') return '—';
  const entries = Object.entries(d).slice(0, 3);
  if (entries.length === 0) return '—';
  return entries
    .map(([k, v]) => {
      if (v === null || v === undefined) return `${k}: null`;
      if (typeof v === 'string') return `${k}: ${v.length > 30 ? v.slice(0, 30) + '…' : v}`;
      if (Array.isArray(v)) return `${k}: [${v.length}]`;
      if (typeof v === 'object') return `${k}: {…}`;
      return `${k}: ${String(v)}`;
    })
    .join(' · ');
}

// Squash consecutive same-resource same-user updates within the window
// (60s) into one "primary" row plus a count of suppressed rows. Returns
// the visible rows, each tagged with how many it absorbs.
type RolledRow = AuditLog & { rolledCount?: number };
const SQUASH_WINDOW_MS = 60_000;

function squash(logs: AuditLog[]): RolledRow[] {
  const out: RolledRow[] = [];
  for (const log of logs) {
    const last = out[out.length - 1];
    if (!last) {
      out.push({ ...log });
      continue;
    }
    const sameAction = resolveAction(last) === resolveAction(log);
    const sameResource =
      (last.resource_id || last.target) === (log.resource_id || log.target);
    const sameUser = resolveWho(last) === resolveWho(log);
    const lastWhen = resolveWhen(last);
    const thisWhen = resolveWhen(log);
    const close =
      lastWhen && thisWhen
        ? Math.abs(new Date(lastWhen).getTime() - new Date(thisWhen).getTime()) <
          SQUASH_WINDOW_MS
        : false;
    if (
      sameAction &&
      sameResource &&
      sameUser &&
      close &&
      resolveAction(log).toLowerCase().endsWith('.update')
    ) {
      last.rolledCount = (last.rolledCount || 1) + 1;
    } else {
      out.push({ ...log });
    }
  }
  return out;
}

export default function AuditLogsPage() {
  const [filters, setFilters] = useState({
    tool: '',
    target: '',
    resourceType: '',
    page: 1,
    limit: 50,
  });
  const [hideBackground, setHideBackground] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const { data: logs, isLoading, refetch } = useQuery({
    queryKey: ['audit-logs', filters],
    queryFn: () =>
      api.auditLogs.list({
        tool: filters.tool || undefined,
        target: filters.target || undefined,
        page: filters.page,
        limit: filters.limit,
      }),
  });

  const { data: tools } = useQuery({
    queryKey: ['system-tools'],
    queryFn: () => api.system.getTools(),
  });

  const ENTITY_ACTIONS = [
    'assessment.create',
    'assessment.update',
    'assessment.delete',
    'finding.create',
    'finding.update',
    'finding.delete',
    'project.create',
    'project.update',
    'project.delete',
    'repository.create',
    'repository.delete',
  ];
  const uniqueActions = tools
    ? [...new Set([...tools.map((t: { name: string }) => t.name), ...ENTITY_ACTIONS])].sort()
    : ENTITY_ACTIONS.slice().sort();

  // Build a list of distinct resource IDs from the loaded page so the
  // user can pick a specific resource to filter by. Narrowed to the
  // selected resource type when one is chosen.
  const resourceIdOptions = useMemo(() => {
    const raw = (logs?.data || []) as AuditLog[];
    const byId = new Map<string, { id: string; type: string; hint?: string }>();
    for (const log of raw) {
      const id = log.resource_id || log.target;
      if (!id) continue;
      const type = resolveResourceType(log) || 'resource';
      if (filters.resourceType && type !== filters.resourceType) continue;
      // Pick up a friendly name from create events, else fall back.
      let hint = byId.get(id)?.hint;
      const d = log.details;
      if (!hint && d && typeof d === 'object') {
        const dd = d as Record<string, unknown>;
        const candidate = dd.name || dd.title || dd.email;
        if (typeof candidate === 'string' && candidate.length > 0) {
          hint = candidate.length > 24 ? candidate.slice(0, 24) + '…' : candidate;
        }
      }
      byId.set(id, { id, type, hint });
    }
    return [...byId.values()]
      .map((r) => ({
        value: r.id,
        label: `${r.type}: ${r.id.slice(0, 12)}${r.id.length > 12 ? '…' : ''}`,
        hint: r.hint,
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [logs, filters.resourceType]);

  // Apply client-side post-filtering: hide background updates,
  // narrow to selected resource type, then squash consecutive updates.
  const visibleRows = useMemo<RolledRow[]>(() => {
    const raw = logs?.data || [];
    let filtered: AuditLog[] = raw as AuditLog[];
    if (hideBackground) {
      filtered = filtered.filter((l) => !isBackgroundUpdate(l));
    }
    if (filters.resourceType) {
      filtered = filtered.filter(
        (l) => resolveResourceType(l) === filters.resourceType,
      );
    }
    return squash(filtered);
  }, [logs, hideBackground, filters.resourceType]);

  const toggleExpanded = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Audit Logs</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Who did what, to what, and when
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Switch
              id="hide-bg"
              checked={hideBackground}
              onCheckedChange={setHideBackground}
            />
            <Label htmlFor="hide-bg" className="text-xs text-muted-foreground cursor-pointer">
              Hide background updates
            </Label>
          </div>
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="text-sm font-medium">Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4">
            <SearchableSelect
              value={filters.tool}
              onChange={(value) =>
                setFilters((f) => ({ ...f, tool: value, page: 1 }))
              }
              options={uniqueActions.map((action: string) => ({
                value: action,
                label: action,
              }))}
              placeholder="All Actions"
              searchPlaceholder="Search actions…"
              allOptionLabel="All Actions"
              width="w-[240px]"
            />
            <SearchableSelect
              value={filters.resourceType}
              onChange={(value) =>
                setFilters((f) => ({ ...f, resourceType: value, page: 1 }))
              }
              options={RESOURCE_TYPES.map((rt) => ({ value: rt, label: rt }))}
              placeholder="All Resources"
              searchPlaceholder="Search resources…"
              allOptionLabel="All Resources"
              width="w-[200px]"
            />
            <SearchableSelect
              value={filters.target}
              onChange={(value) =>
                setFilters((f) => ({ ...f, target: value, page: 1 }))
              }
              options={resourceIdOptions}
              placeholder={
                filters.resourceType
                  ? `All ${filters.resourceType}s`
                  : 'Any specific resource'
              }
              searchPlaceholder="Search ID, name, email…"
              emptyText={
                resourceIdOptions.length === 0
                  ? 'No resources on this page'
                  : 'No matches'
              }
              allOptionLabel={
                filters.resourceType
                  ? `All ${filters.resourceType}s`
                  : 'Any resource'
              }
              width="w-[280px]"
            />
            {(filters.tool || filters.target || filters.resourceType) && (
              <Button
                variant="ghost"
                onClick={() =>
                  setFilters({ tool: '', target: '', resourceType: '', page: 1, limit: 50 })
                }
              >
                Clear Filters
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Logs Table */}
      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[140px]">When</TableHead>
                <TableHead className="w-[180px]">Action</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead className="w-[200px]">User</TableHead>
                <TableHead>Details</TableHead>
                <TableHead className="w-[40px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                    <TableCell><Skeleton className="h-6 w-32" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-48" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-40" /></TableCell>
                    <TableCell></TableCell>
                  </TableRow>
                ))
              ) : visibleRows.length ? (
                visibleRows.map((log) => {
                  const action = resolveAction(log);
                  const isDestructive = DESTRUCTIVE_ACTIONS.has(action);
                  const when = resolveWhen(log);
                  const isExpanded = expanded.has(log.id);
                  return (
                    <Fragment key={log.id}>
                      <TableRow
                        className={cn(
                          'cursor-pointer hover:bg-muted/40',
                          isDestructive && 'bg-destructive/5',
                        )}
                        onClick={() => toggleExpanded(log.id)}
                      >
                        <TableCell
                          className="text-xs text-muted-foreground whitespace-nowrap"
                          title={when ? new Date(when).toLocaleString() : undefined}
                        >
                          {formatRelativeTime(when)}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={isDestructive ? 'destructive' : 'outline'}
                            className="font-mono text-xs"
                          >
                            {action}
                          </Badge>
                          {log.rolledCount && log.rolledCount > 1 && (
                            <Badge variant="secondary" className="ml-1 text-xs">
                              ×{log.rolledCount}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="max-w-[260px] truncate font-mono text-xs">
                          {resolveResourceLabel(log)}
                        </TableCell>
                        <TableCell className="truncate text-xs text-muted-foreground">
                          {resolveWho(log)}
                        </TableCell>
                        <TableCell className="max-w-[320px] truncate text-xs text-muted-foreground">
                          {detailPreview(log)}
                        </TableCell>
                        <TableCell>
                          {log.details && Object.keys(log.details).length > 0 ? (
                            isExpanded ? (
                              <ChevronUp className="h-4 w-4 text-muted-foreground" />
                            ) : (
                              <ChevronDown className="h-4 w-4 text-muted-foreground" />
                            )
                          ) : null}
                        </TableCell>
                      </TableRow>
                      {isExpanded && log.details && (
                        <TableRow>
                          <TableCell colSpan={6} className="bg-muted/20 p-4">
                            <pre className="text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">
                              {JSON.stringify(log.details, null, 2)}
                            </pre>
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                    <Activity className="mx-auto h-12 w-12 mb-4 opacity-50" />
                    <p>
                      {hideBackground && (logs?.data?.length || 0) > 0
                        ? 'All entries on this page are background updates. Toggle "Hide background updates" off to see them.'
                        : 'No audit logs found'}
                    </p>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pagination */}
      {logs && logs.total > filters.limit && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {(filters.page - 1) * filters.limit + 1} to{' '}
            {Math.min(filters.page * filters.limit, logs.total)} of {logs.total} logs
            {hideBackground && (logs.data?.length ?? 0) > visibleRows.length && (
              <span className="ml-2">
                ({(logs.data?.length ?? 0) - visibleRows.length} hidden on this page)
              </span>
            )}
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={filters.page === 1}
              onClick={() => setFilters((f) => ({ ...f, page: f.page - 1 }))}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!logs.hasMore}
              onClick={() => setFilters((f) => ({ ...f, page: f.page + 1 }))}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
