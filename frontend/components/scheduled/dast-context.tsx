'use client';

// =============================================================================
// Scheduled DAST — section-wide context.
//
// Holds the data + mutations + dialog state shared across every sub-page
// (Overview, Scans, Vulnerabilities, Targets, Schedules, Reports, Settings),
// and renders the shared dialogs (schedule / run-now / scan-run sheet /
// scan-config) once at the layout level so any page can open them.
// =============================================================================

import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { api } from '@/lib/tauri-api';
import type { Target, Scan, ScanSchedule, ScanAuth, ScanScope, Application } from '@/lib/types';
import {
  DAST_TARGET_TYPES,
  PickTargetDialog,
  NewTargetDialog,
  ScanRunSheet,
  ScanConfigDialog,
} from './dast-shared';

interface DastContextValue {
  targets: Target[];
  targetById: Map<string, Target>;
  schedules: ScanSchedule[] | undefined;
  schedulesLoading: boolean;
  scheduledIds: Set<string>;
  dastTargetOptions: { value: string; label: string }[];
  unscheduledOptions: { value: string; label: string }[];
  policyOptions: { value: string; label: string }[];
  // Mutations
  upsertSchedule: (target_id: string, cadence: string, policyId?: string, authMode?: string) => void;
  removeSchedule: (id: string) => void;
  runScan: (target_id: string, policyId?: string, authMode?: string) => void;
  /** Run/schedule from a combined picker value ("app:<id>" | "target:<id>"). */
  runSelection: (selection: string, policyId?: string, authMode?: string) => void;
  scheduleSelection: (selection: string, cadence: string, policyId?: string, authMode?: string) => void;
  upsertPending: boolean;
  runPending: boolean;
  createTarget: (rawValue: string, targetType: string) => void;
  createTargetPending: boolean;
  archiveTarget: (id: string) => void;
  // Dialog openers
  openSchedule: () => void;
  openRun: () => void;
  openNewTarget: () => void;
  openConfig: (targetId: string) => void;
  openScan: (scan: Scan) => void;
}

const DastContext = createContext<DastContextValue | null>(null);

export function useScheduledDast(): DastContextValue {
  const ctx = useContext(DastContext);
  if (!ctx) throw new Error('useScheduledDast must be used within ScheduledDastProvider');
  return ctx;
}

export function ScheduledDastProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [runOpen, setRunOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [configTargetId, setConfigTargetId] = useState<string | null>(null);
  const [newTargetOpen, setNewTargetOpen] = useState(false);

  const { data: schedules, isLoading: schedulesLoading } = useQuery({
    queryKey: ['scan-schedules'],
    queryFn: () => api.scanSchedules.list(),
  });
  // Only targets created on the Scheduled DAST Targets page (source='dast') —
  // keeps AI-assessment / scope / repo targets out of the DAST views.
  const { data: targets } = useQuery({
    queryKey: ['targets', 'dast'],
    queryFn: () => api.targets.list({ source: 'dast' }),
  });
  const { data: policies } = useQuery({
    queryKey: ['scan-policies'],
    queryFn: () => api.scanPolicies.list(),
  });
  const { data: applications } = useQuery({
    queryKey: ['applications'],
    queryFn: () => api.applications.list(),
  });

  const targetById = useMemo(() => new Map((targets ?? []).map((t) => [t.id, t])), [targets]);
  const scheduledIds = useMemo(
    () => new Set((schedules ?? []).map((s) => s.target_id).filter((x): x is string => !!x)),
    [schedules],
  );
  const policyById = useMemo(() => new Map((policies ?? []).map((p) => [p.id, p])), [policies]);
  const policyOptions = useMemo(
    () => (policies ?? []).map((p) => ({ value: p.id, label: p.name })),
    [policies],
  );
  // Resolve a policy id into the pipeline's selection options (empty = full).
  const policySelection = (policyId?: string): Record<string, unknown> => {
    if (!policyId) return {};
    const p = policyById.get(policyId);
    if (!p) return {};
    const out: Record<string, unknown> = {};
    if (p.categories.length) out.selected_categories = p.categories;
    if (p.test_ids.length) out.selected_tests = p.test_ids;
    return out;
  };

  const dastTargetOptions = useMemo(
    () =>
      (targets ?? [])
        .filter((t) => DAST_TARGET_TYPES.has(t.target_type))
        .map((t) => ({ value: t.id, label: t.canonical_value })),
    [targets],
  );
  const unscheduledOptions = useMemo(
    () => dastTargetOptions.filter((o) => !scheduledIds.has(o.value)),
    [dastTargetOptions, scheduledIds],
  );

  // DAST targets grouped by application — for app-level fan-out runs.
  const targetsByApp = useMemo(() => {
    const m = new Map<string, Target[]>();
    for (const t of targets ?? []) {
      if (!t.application_id || !DAST_TARGET_TYPES.has(t.target_type)) continue;
      const arr = m.get(t.application_id) ?? [];
      arr.push(t);
      m.set(t.application_id, arr);
    }
    return m;
  }, [targets]);

  // Combined picker: applications (visually marked) that have ≥1 target, then
  // individual targets. value encodes the kind: "app:<id>" | "target:<id>".
  const scanPickerOptions = useMemo(() => {
    const appOpts = (applications ?? [])
      .map((a) => ({ a, n: (targetsByApp.get(a.id) ?? []).length }))
      .filter((x) => x.n > 0)
      .map(({ a, n }) => ({
        value: `app:${a.id}`,
        label: a.name,
        hint: `Application · ${n} target${n === 1 ? '' : 's'}`,
      }));
    const tgtOpts = dastTargetOptions.map((o) => ({
      value: `target:${o.value}`,
      label: o.label,
      hint: 'Target',
    }));
    return [...appOpts, ...tgtOpts];
  }, [applications, targetsByApp, dastTargetOptions]);

  const upsert = useMutation({
    mutationFn: (body: {
      target_id?: string;
      application_id?: string;
      cadence: string;
      policy_id?: string;
      auth_mode?: string;
    }) => api.scanSchedules.upsert({ ...body, scan_type: 'deterministic' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-schedules'] });
      setScheduleOpen(false);
    },
    onError: (e) => toast.error(`Couldn't save schedule: ${e instanceof Error ? e.message : String(e)}`),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.scanSchedules.remove(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['scan-schedules'] }),
    onError: (e) => toast.error(`Couldn't remove schedule: ${e instanceof Error ? e.message : String(e)}`),
  });

  // Create a DAST target (tagged source='dast' so it lands on this page).
  const createTargetM = useMutation({
    mutationFn: ({ rawValue, targetType }: { rawValue: string; targetType: string }) =>
      api.targets.resolve(rawValue, targetType, undefined, 'dast'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets', 'dast'] });
      setNewTargetOpen(false);
      toast.success('Target added.');
    },
    onError: (e) => toast.error(`Couldn't add target: ${e instanceof Error ? e.message : String(e)}`),
  });

  // Archive (remove) a DAST target.
  const archiveTargetM = useMutation({
    mutationFn: (id: string) => api.targets.archive(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets', 'dast'] });
      toast.success('Target removed.');
    },
    onError: (e) => toast.error(`Couldn't remove target: ${e instanceof Error ? e.message : String(e)}`),
  });

  // Manual DAST scan = the deterministic pipeline (mode: sequential), NOT an LLM
  // exploitation assessment. Auto-records a scan that lands in Scans, and now
  // persists its findings stamped with scan_id (migration 0035).
  const runScanM = useMutation({
    mutationFn: async ({
      targetId,
      policyId,
      authMode,
    }: {
      targetId: string;
      policyId?: string;
      authMode?: string;
    }) => {
      const t = targetById.get(targetId);
      if (!t) throw new Error('target not found');

      // Best-effort: pull the target's saved auth + scope and pass them into
      // the run so the DAST pipeline can scan behind auth + stay in scope.
      // Layer the scan-policy selection on top (empty = full assessment).
      // 'unauthed' mode skips auth entirely (anonymous scan) but keeps scope.
      const opts: Record<string, unknown> = { ...policySelection(policyId) };
      try {
        const cfg = await api.scanConfigs.get({ target_id: targetId });
        const auth = (cfg.auth ?? {}) as ScanAuth;
        const scope = (cfg.scope ?? {}) as ScanScope;
        if (authMode !== 'unauthed' && auth.type && auth.type !== 'none') opts.web_app = { auth };
        if ((scope.include?.length ?? 0) > 0 || (scope.exclude?.length ?? 0) > 0 || scope.openapi_url) opts.scope = scope;
      } catch {
        // Config fetch is non-fatal — proceed with an unconfigured run.
      }
      const options = Object.keys(opts).length > 0 ? opts : undefined;

      return api.agents.runOrchestrator({
        mode: 'sequential',
        targets: [t.canonical_value],
        ...(options ? { options: options as never } : {}),
      });
    },
    onSuccess: () => {
      setRunOpen(false);
      toast.success('DAST scan started — it will appear in Scans as it runs.');
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['scans'] });
        queryClient.invalidateQueries({ queryKey: ['dast-vulns'] });
      }, 1500);
    },
    onError: (e) => toast.error(`Couldn't start the scan: ${e instanceof Error ? e.message : String(e)}`),
  });

  // Run/schedule from a combined picker value ("app:<id>" | "target:<id>").
  const splitSel = (sel: string): [string, string] => {
    const i = sel.indexOf(':');
    return [sel.slice(0, i), sel.slice(i + 1)];
  };
  const runSelection = (sel: string, policyId?: string, authMode?: string) => {
    const [kind, id] = splitSel(sel);
    if (kind === 'app') {
      const ts = targetsByApp.get(id) ?? [];
      if (!ts.length) {
        toast.error('That application has no targets yet.');
        return;
      }
      ts.forEach((t) => runScanM.mutate({ targetId: t.id, policyId, authMode }));
      setRunOpen(false);
    } else {
      runScanM.mutate({ targetId: id, policyId, authMode });
    }
  };
  const scheduleSelection = (sel: string, cadence: string, policyId?: string, authMode?: string) => {
    const [kind, id] = splitSel(sel);
    const common = {
      cadence,
      ...(policyId ? { policy_id: policyId } : {}),
      ...(authMode ? { auth_mode: authMode } : {}),
    };
    if (kind === 'app') upsert.mutate({ application_id: id, ...common });
    else upsert.mutate({ target_id: id, ...common });
  };

  const value: DastContextValue = {
    targets: targets ?? [],
    targetById,
    schedules,
    schedulesLoading,
    scheduledIds,
    dastTargetOptions,
    unscheduledOptions,
    policyOptions,
    upsertSchedule: (target_id, cadence, policyId, authMode) =>
      upsert.mutate({
        target_id,
        cadence,
        ...(policyId ? { policy_id: policyId } : {}),
        ...(authMode ? { auth_mode: authMode } : {}),
      }),
    removeSchedule: (id) => remove.mutate(id),
    runScan: (target_id, policyId, authMode) => runScanM.mutate({ targetId: target_id, policyId, authMode }),
    runSelection,
    scheduleSelection,
    upsertPending: upsert.isPending,
    runPending: runScanM.isPending,
    createTarget: (rawValue, targetType) => createTargetM.mutate({ rawValue, targetType }),
    createTargetPending: createTargetM.isPending,
    archiveTarget: (id) => archiveTargetM.mutate(id),
    openSchedule: () => setScheduleOpen(true),
    openRun: () => setRunOpen(true),
    openNewTarget: () => setNewTargetOpen(true),
    openConfig: (targetId) => setConfigTargetId(targetId),
    openScan: (scan) => setSelectedScan(scan),
  };

  return (
    <DastContext.Provider value={value}>
      {children}

      <NewTargetDialog
        open={newTargetOpen}
        onOpenChange={setNewTargetOpen}
        onConfirm={(rawValue, targetType) => createTargetM.mutate({ rawValue, targetType })}
        busy={createTargetM.isPending}
      />

      <PickTargetDialog
        open={scheduleOpen}
        onOpenChange={setScheduleOpen}
        title="Schedule a scan"
        description="Run cheap, deterministic DAST on a recurring cadence — against a single target or an entire application (all its current targets). Authed or unauthed."
        cta="Schedule"
        options={scanPickerOptions}
        withCadence
        withAuthMode
        policies={policyOptions}
        onConfirm={(sel, cadence, policyId, authMode) => scheduleSelection(sel, cadence, policyId, authMode)}
        busy={upsert.isPending}
      />

      <PickTargetDialog
        open={runOpen}
        onOpenChange={setRunOpen}
        title="Run a DAST scan"
        description="Runs the deterministic DAST pipeline now (nuclei, nikto, sqlmap, web/API tests) — not an LLM exploitation run. Pick a single target or a whole application. The result appears in Scans."
        cta="Run scan"
        options={scanPickerOptions}
        withCadence={false}
        withAuthMode
        policies={policyOptions}
        onConfirm={(sel, _cadence, policyId, authMode) => runSelection(sel, policyId, authMode)}
        busy={runScanM.isPending}
      />

      <ScanRunSheet
        scan={selectedScan}
        targetLabel={
          selectedScan
            ? targetById.get(selectedScan.target_id)?.canonical_value ?? selectedScan.target_id
            : ''
        }
        open={!!selectedScan}
        onOpenChange={(v) => {
          if (!v) setSelectedScan(null);
        }}
      />

      <ScanConfigDialog
        targetId={configTargetId}
        targetLabel={
          configTargetId ? targetById.get(configTargetId)?.canonical_value ?? configTargetId : ''
        }
        open={!!configTargetId}
        onOpenChange={(v) => {
          if (!v) setConfigTargetId(null);
        }}
      />
    </DastContext.Provider>
  );
}
