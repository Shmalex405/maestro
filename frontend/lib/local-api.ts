// Local-mode entity API.
//
// In local mode there is no backend: findings, assessments, reports and projects
// live in the local SQLite DB and are reached through Tauri commands rather than
// HTTP. This module holds those implementations plus the shape adapters, so
// tauri-api.ts only has to choose a branch (see `route` there) instead of
// carrying two bodies per method.
//
// ── Two conventions that are easy to get wrong ───────────────────────────────
//
// 1. Tauri v2 converts command ARGUMENTS from camelCase on the JS side to
//    snake_case in Rust (unless the command sets `rename_all = "snake_case"`).
//    So `get_findings_stats(project_id: ...)` is called with `{ projectId }`.
// 2. Struct PAYLOADS are governed by the struct's own serde attrs. The local
//    param structs carry no rename, so their keys stay snake_case:
//    `{ params: { project_id, sort_by, ... } }`.
//
// Mixing those up produces a silent `null` argument, not an error, so both are
// spelled out at each call site below.

import { invoke } from '@tauri-apps/api/core';
import type {
  Assessment,
  Finding,
  FindingsFilter,
  FindingsStats,
  PaginatedResult,
  Project,
  Report,
  ScanSnapshot,
  Severity,
  FindingStatus,
  FindingCategory,
} from './types';
import type { TeamOnlyFeature } from './deployment-mode';
import { featureUnavailableReason } from './deployment-mode';

// ─────────────────────────────────────────────────────────────────────────────
// The local Finding shape
// ─────────────────────────────────────────────────────────────────────────────
//
// Mirrors `Finding` in src-tauri/src/database.rs. It is NOT the same shape as
// the TS/cloud `Finding`: two fields are named differently and one is a list
// where the UI expects a scalar. Everything else lines up after the parity
// migration.

interface LocalFinding {
  id: string;
  assessment_id?: string | null;
  title: string;
  severity: string;
  status: string;
  target: string;
  description: string;
  evidence?: string | null;
  remediation?: string | null;
  /** Cloud/TS calls this `cvss`. */
  cvss_score?: number | null;
  /** Cloud/TS carries a single `cve` string. */
  cve_ids?: string[] | null;
  source?: string | null;
  category?: string | null;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  code_snippet?: string | null;
  cwe?: string | null;
  created_at: string;
  updated_at: string;
  // Parity columns.
  exploitable?: string | null;
  original_severity?: string | null;
  calibrated_severity?: string | null;
  calibration_rule?: string | null;
  calibration_justification?: string | null;
  tags?: string[] | null;
  jira_ticket?: string | null;
  jira_url?: string | null;
  validated_at?: string | null;
  validation_method?: string | null;
  source_tool?: string | null;
  evidence_type?: string | null;
}

/** Drop SQLite's nulls so optional TS fields read as absent rather than null.
 *  `calibrated_severity` is the exception the UI cares about — it distinguishes
 *  "no calibration ran" (undefined) from a value, and null would be truthy-ish
 *  in a `!= null` check somewhere. */
const opt = <T>(v: T | null | undefined): T | undefined => (v ?? undefined);

/** Local row → the Finding shape the UI renders. */
export function toFinding(l: LocalFinding): Finding {
  return {
    id: l.id,
    assessment_id: opt(l.assessment_id),
    title: l.title,
    severity: l.severity as Severity,
    status: l.status as FindingStatus,
    target: l.target,
    description: l.description,
    evidence: opt(l.evidence),
    evidence_type: opt(l.evidence_type) as Finding['evidence_type'],
    remediation: opt(l.remediation),
    // Name differences between the local and cloud schemas.
    cvss: opt(l.cvss_score),
    // The UI shows one CVE; local stores a list. Join rather than take [0] so a
    // multi-CVE finding doesn't silently lose the others.
    cve: l.cve_ids?.length ? l.cve_ids.join(', ') : undefined,
    cwe: opt(l.cwe),
    source: opt(l.source),
    source_tool: opt(l.source_tool),
    category: opt(l.category) as FindingCategory | undefined,
    created_at: l.created_at,
    updated_at: opt(l.updated_at),
    file_path: opt(l.file_path),
    line_start: opt(l.line_start),
    line_end: opt(l.line_end),
    code_snippet: opt(l.code_snippet),
    exploitable: opt(l.exploitable),
    original_severity: opt(l.original_severity) as Severity | undefined,
    calibrated_severity: opt(l.calibrated_severity) as Severity | undefined,
    calibration_rule: opt(l.calibration_rule),
    calibration_justification: opt(l.calibration_justification),
    tags: opt(l.tags),
    jira_ticket: opt(l.jira_ticket),
    jira_url: opt(l.jira_url),
    validated_at: opt(l.validated_at),
    validation_method: opt(l.validation_method),
  };
}

/** UI filter → the snake_case keys `ListFindingsParams` expects. */
function toLocalListParams(
  p?: FindingsFilter & { page?: number; limit?: number; sort?: string; snapshot_id?: string },
): Record<string, unknown> {
  // `sort` arrives as "field:dir" from the workbench; the local command takes
  // the two halves separately.
  const [sortBy, sortDir] = (p?.sort ?? '').split(':');
  return {
    assessment_id: p?.assessment_id,
    // Local takes a single severity/status, the UI sends arrays. Passing the
    // first is a real narrowing — noted in localApi.findings.list.
    severity: p?.severity?.[0],
    status: p?.status?.[0],
    search: p?.search,
    target: p?.target,
    category: p?.category,
    project_id: p?.project_id,
    limit: p?.limit,
    page: p?.page,
    snapshot_id: p?.snapshot_id,
    sort_by: sortBy || undefined,
    sort_dir: sortDir || undefined,
  };
}

/** Raised for a capability with no local backing. Thrown rather than returning
 *  empty so a caller that should have been gated is loud, not quietly wrong. */
export class TeamOnlyError extends Error {
  constructor(public feature: TeamOnlyFeature) {
    super(
      featureUnavailableReason(feature) ??
        'This feature requires a team backend.',
    );
    this.name = 'TeamOnlyError';
  }
}

const teamOnly = (feature: TeamOnlyFeature): never => {
  throw new TeamOnlyError(feature);
};

// ─────────────────────────────────────────────────────────────────────────────
// Findings
// ─────────────────────────────────────────────────────────────────────────────

async function listFindings(
  params?: FindingsFilter & { page?: number; limit?: number; sort?: string; snapshot_id?: string },
): Promise<PaginatedResult<Finding>> {
  const res = await invoke<{
    data: LocalFinding[];
    total: number;
    page: number;
    limit: number;
    hasMore: boolean;
  }>('list_findings', { params: toLocalListParams(params) });

  return {
    data: res.data.map(toFinding),
    total: res.total,
    page: res.page,
    limit: res.limit,
    hasMore: res.hasMore,
  };
}

/** Aggregate the stat tiles.
 *
 *  The local `get_findings_stats` command returns totals by severity/status/
 *  category plus an exploitable count, but the workbench tiles also want
 *  by_tool, fully/partial exploited splits, and CVE/Jira counts. Rather than
 *  duplicate that aggregation in SQL, fetch the rows once and count in JS.
 *
 *  That is a deliberate call for local scale: a single-operator DB holds
 *  hundreds to low thousands of findings, so one unpaginated read is cheap and
 *  guarantees the tiles agree with the table. It would be the wrong choice
 *  against a shared Postgres, which is exactly why cloud mode keeps its
 *  server-side aggregate. */
async function findingsStats(
  category?: string,
  target?: string,
  search?: string,
  exploitable?: string,
  projectId?: string,
): Promise<FindingsStats> {
  const all = await listFindings({
    category,
    target,
    search,
    project_id: projectId,
    limit: 100_000,
    page: 1,
  } as FindingsFilter & { limit: number; page: number });

  const rows = exploitable
    ? all.data.filter((f) => (f.exploitable ?? '').toLowerCase() === exploitable.toLowerCase())
    : all.data;

  const tally = <K extends string>(pick: (f: Finding) => K | undefined) =>
    rows.reduce<Record<string, number>>((acc, f) => {
      const k = pick(f);
      if (k) acc[k] = (acc[k] ?? 0) + 1;
      return acc;
    }, {});

  const countWhere = (pred: (f: Finding) => boolean) => rows.filter(pred).length;
  const expl = (f: Finding) => (f.exploitable ?? '').toLowerCase();

  return {
    total: rows.length,
    by_severity: tally((f) => f.severity) as Record<Severity, number>,
    by_status: tally((f) => f.status) as Record<FindingStatus, number>,
    by_category: tally((f) => f.category) as Record<FindingCategory, number>,
    by_tool: tally((f) => f.source_tool ?? f.source),
    exploitable: countWhere((f) => expl(f) === 'true' || expl(f) === 'potentially'),
    exploitable_count: countWhere((f) => expl(f) === 'true' || expl(f) === 'potentially'),
    fully_exploited_count: countWhere((f) => expl(f) === 'true'),
    partial_exploited_count: countWhere((f) => expl(f) === 'potentially'),
    remediated_count: countWhere((f) => f.status === 'remediated'),
    with_cve: countWhere((f) => !!f.cve),
    with_jira: countWhere((f) => !!f.jira_ticket),
  };
}

export const localApi = {
  findings: {
    /** NOTE: the local command takes a single severity/status where the UI can
     *  send several. Only the first is applied, so a multi-select filter is
     *  narrower locally than in cloud mode. Widening it means changing
     *  ListFindingsParams to accept a list — worth doing if it bites. */
    list: listFindings,

    get: async (id: string): Promise<Finding> => {
      const f = await invoke<LocalFinding | null>('get_finding', { id });
      if (!f) throw new Error(`Finding ${id} not found`);
      return toFinding(f);
    },

    create: async (data: Record<string, unknown>): Promise<Finding> =>
      toFinding(await invoke<LocalFinding>('create_finding', { data })),

    update: async (id: string, data: Record<string, unknown>): Promise<void> => {
      // The local command returns unit; callers that want the row re-read it.
      await invoke('update_finding', { id, data });
    },

    delete: (id: string): Promise<void> => invoke('delete_finding', { id }),

    stats: findingsStats,

    export: (format: string, filters?: { severity?: string; status?: string }): Promise<string> =>
      invoke('export_findings', {
        params: { format, severity: filters?.severity, status: filters?.status },
      }),

    scanHistory: (target?: string): Promise<ScanSnapshot[]> =>
      invoke('list_scan_history', { target }),

    createSnapshot: (assessmentId: string): Promise<ScanSnapshot> =>
      invoke('create_scan_snapshot', { assessmentId }),

    /** No local comments table — comments are a collaboration feature. */
    comments: {
      list: async () => [],
      create: async () => teamOnly('user-management'),
    },
  },

  assessments: {
    list: async (params?: Record<string, unknown>): Promise<PaginatedResult<Assessment>> => {
      const res = await invoke<{
        data: Assessment[];
        total: number;
        page: number;
        limit: number;
        hasMore: boolean;
      }>('list_assessments', { params });
      return res;
    },

    get: async (id: string): Promise<Assessment> => {
      const a = await invoke<Assessment | null>('get_assessment', { id });
      if (!a) throw new Error(`Assessment ${id} not found`);
      return a;
    },

    create: (data: Record<string, unknown>): Promise<Assessment> =>
      invoke('create_assessment', { data }),
    update: (id: string, data: Record<string, unknown>): Promise<Assessment> =>
      invoke('update_assessment', { id, data }),
    delete: (id: string): Promise<void> => invoke('delete_assessment', { id }),
    cancel: (id: string): Promise<void> => invoke('cancel_assessment', { id }),
    pause: (id: string): Promise<void> => invoke('pause_assessment', { id }),
    resume: (id: string): Promise<Assessment> => invoke('resume_assessment', { id }),
    getReport: (id: string): Promise<Report | null> => invoke('get_assessment_report', { id }),
    generateReport: (id: string, format?: string): Promise<Report> =>
      invoke('generate_assessment_report', { id, format }),

    /** Provenance and per-test coverage are promoted to the backend at the end
     *  of a run; locally there is no promotion step and no table to read. Empty
     *  rather than an error — the execution overview already renders a labeled
     *  placeholder for "no coverage captured". */
    listToolExecutions: async () => [],
    listTestResults: async () => [],
  },

  reports: {
    list: (params?: Record<string, unknown>): Promise<PaginatedResult<Report>> =>
      invoke('list_reports', { params }),
    get: async (id: string): Promise<Report> => {
      const r = await invoke<Report | null>('get_report', { id });
      if (!r) throw new Error(`Report ${id} not found`);
      return r;
    },
    generate: (params: Record<string, unknown>): Promise<Report> =>
      invoke('generate_report', { params }),
    exportTo: (id: string, destination: string): Promise<string> =>
      invoke('export_report', { id, destination }),
    listFiles: (): Promise<unknown[]> => invoke('list_report_files'),
    // `file_path` → `filePath`: Tauri camelCases command arguments.
    readFile: (filePath: string): Promise<string> => invoke('read_report_file', { filePath }),
    generatePdf: (params: Record<string, unknown>): Promise<unknown> =>
      invoke('generate_pdf_report', { params }),
  },

  projects: {
    list: (status?: string): Promise<Project[]> => invoke('list_projects', { status }),
    get: async (id: string): Promise<Project> => {
      const p = await invoke<Project | null>('get_project', { id });
      if (!p) throw new Error(`Project ${id} not found`);
      return p;
    },
    create: (data: Record<string, unknown>): Promise<Project> =>
      invoke('create_project', { data }),
    update: (id: string, data: Record<string, unknown>): Promise<Project> =>
      invoke('update_project', { id, data }),
    delete: (id: string): Promise<void> => invoke('delete_project', { id }),
  },

  /** Capabilities with no local schema at all. Calling these is a bug — they
   *  should be gated by isFeatureAvailable() before render. */
  unavailable: {
    graph: () => teamOnly('attack-graph'),
    footholds: () => teamOnly('post-exploitation'),
    schedules: () => teamOnly('scheduled-dast'),
    users: () => teamOnly('user-management'),
  },
};
