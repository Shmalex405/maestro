const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new ApiError(response.status, error.message || `Request failed: ${response.statusText}`);
  }

  // Handle empty responses
  const text = await response.text();
  return text ? JSON.parse(text) : (null as T);
}

function qs(params?: Record<string, unknown>): string {
  if (!params) return '';
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, String(value));
    }
  });
  return searchParams.toString();
}

// Types
export interface Assessment {
  id: string;
  type: 'full' | 'recon' | 'vuln_scan' | 'web_app' | 'code_scan' | 'cycode_validation' | 'exploit_validation';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  targets?: string[];
  repo_paths?: string[];
  credential_app?: string;
  jira_project?: string;
  email_recipients?: string[];
  severity_threshold?: string;
  options?: Record<string, unknown>;
  phases?: string[];
  progress: number;
  current_step?: string;
  started_at: string;
  completed_at?: string;
  findings_count: number;
  critical_count?: number;
  high_count?: number;
  error_message?: string;
  report_path?: string;
}

export interface Report {
  id: string;
  assessment_id: string;
  title: string;
  content: string;
  format: 'markdown' | 'html' | 'json';
  created_at: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  exploitable_count: number;
}

export interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description?: string;
  target: string;
  evidence?: string;
  remediation?: string;
  cve?: string;
  cycode_ref?: string;
  status: 'open' | 'in_progress' | 'remediated' | 'accepted';
  created_at: string;
  updated_at?: string;
  jira_ticket?: string;
}

export interface AuditLog {
  id: number;
  timestamp: string;
  tool: string;
  target?: string;
  arguments?: string;
  user?: string;
  session_id?: string;
  result_status?: string;
  execution_time_ms?: number;
}

export interface ScopeConfig {
  networks: Array<{
    cidr: string;
    environment: string;
    notes?: string;
  }>;
  domains: Array<{
    pattern: string;
    environment: string;
  }>;
  exclusions: Array<{
    pattern: string;
    reason: string;
  }>;
  cloud_accounts: Array<{
    id: string;
    provider: 'aws' | 'azure' | 'gcp';
    account_id?: string;
    subscription_id?: string;
    tenant_id?: string;
    project_id?: string;
    regions: string[];
    auth_method: string;
    role_arn?: string;
    client_id?: string;
    client_secret?: string;
    service_account_key?: string;
    services_in_scope: string[];
    resource_groups_in_scope?: string[];
    exclusions: string[];
    notes: string;
  }>;
  kubernetes: Array<{
    id: string;
    cluster: string;
    provider: string;
    auth_method: string;
    kubeconfig_path?: string;
    api_server?: string;
    token?: string;
    namespaces_in_scope: string[];
    namespaces_excluded: string[];
    notes: string;
  }>;
}

export interface CredentialsConfig {
  applications: Record<string, {
    environment: string;
    base_url: string;
    auth_type: string;
    [key: string]: unknown;
  }>;
  test_accounts?: Record<string, {
    username: string;
    role: string;
  }>;
}

export interface ToolsConfig {
  [toolName: string]: Record<string, unknown>;
}

export interface AgentsConfig {
  [agentName: string]: {
    enabled: boolean;
    timeout_minutes?: number;
    auto_start?: boolean;
    requires_approval?: boolean;
  };
}

export interface PaginatedResult<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
}

export interface FindingsStats {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
}

export interface SystemStatus {
  healthy: boolean;
  container_status: 'running' | 'stopped' | 'unknown';
  database_connected: boolean;
  uptime_seconds?: number;
}

// API Client
export const api = {
  // Assessments
  assessments: {
    list: (params?: { status?: string; type?: string; page?: number; limit?: number }) =>
      request<PaginatedResult<Assessment>>(`/api/assessments?${qs(params)}`),

    get: (id: string) =>
      request<Assessment>(`/api/assessments/${id}`),

    create: (data: {
      type: Assessment['type'];
      targets?: string[];
      repo_paths?: string[];
      credential_app?: string;
      jira_project?: string;
      email_recipients?: string[];
      severity_threshold?: string;
      options?: Record<string, unknown>;
    }) =>
      request<Assessment>('/api/assessments', {
        method: 'POST',
        body: JSON.stringify(data),
      }),

    cancel: (id: string) =>
      request<void>(`/api/assessments/${id}`, { method: 'DELETE' }),

    getReport: (id: string) =>
      request<Report>(`/api/assessments/${id}/report`),

    generateReport: (id: string, format?: 'markdown' | 'html' | 'json') =>
      request<Report>(`/api/assessments/${id}/report`, {
        method: 'POST',
        body: JSON.stringify({ format: format || 'markdown' }),
      }),
  },

  // Reports
  reports: {
    list: (params?: { page?: number; limit?: number }) =>
      request<PaginatedResult<Report>>(`/api/reports?${qs(params)}`),

    get: (id: string) =>
      request<Report>(`/api/reports/${id}`),

    download: (id: string, format: 'markdown' | 'html' | 'pdf') =>
      `${API_BASE_URL}/api/reports/${id}/download?format=${format}`,
  },

  // Findings
  findings: {
    list: (params?: {
      severity?: string;
      status?: string;
      target?: string;
      search?: string;
      page?: number;
      limit?: number;
      sort?: string;
    }) =>
      request<PaginatedResult<Finding>>(`/api/findings?${qs(params)}`),

    get: (id: string) =>
      request<Finding>(`/api/findings/${id}`),

    update: (id: string, data: Partial<Finding>) =>
      request<Finding>(`/api/findings/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),

    delete: (id: string) =>
      request<void>(`/api/findings/${id}`, { method: 'DELETE' }),

    createJiraTicket: (id: string, projectKey: string) =>
      request<{ ticket_key: string; url: string }>(`/api/findings/${id}/jira`, {
        method: 'POST',
        body: JSON.stringify({ project_key: projectKey }),
      }),

    stats: () =>
      request<FindingsStats>('/api/findings/stats'),

    export: (format: 'json' | 'csv' | 'markdown', params?: Record<string, string>) =>
      request<string>(`/api/findings/export?format=${format}&${qs(params)}`),
  },

  // Configuration
  config: {
    scope: {
      get: () => request<ScopeConfig>('/api/config/scope'),
      update: (data: ScopeConfig) =>
        request<ScopeConfig>('/api/config/scope', {
          method: 'PUT',
          body: JSON.stringify(data),
        }),
      validate: (target: string) =>
        request<{ valid: boolean; reason?: string; environment?: string }>(
          '/api/config/scope/validate',
          {
            method: 'POST',
            body: JSON.stringify({ target }),
          }
        ),
    },

    credentials: {
      get: () => request<CredentialsConfig>('/api/config/credentials'),
      update: (data: CredentialsConfig) =>
        request<CredentialsConfig>('/api/config/credentials', {
          method: 'PUT',
          body: JSON.stringify(data),
        }),
      testConnection: (appName: string) =>
        request<{ success: boolean; message?: string }>(
          '/api/config/credentials/test',
          {
            method: 'POST',
            body: JSON.stringify({ app_name: appName }),
          }
        ),
    },

    tools: {
      get: () => request<ToolsConfig>('/api/config/tools'),
      update: (data: ToolsConfig) =>
        request<ToolsConfig>('/api/config/tools', {
          method: 'PUT',
          body: JSON.stringify(data),
        }),
    },

    agents: {
      get: () => request<AgentsConfig>('/api/config/agents'),
      update: (data: AgentsConfig) =>
        request<AgentsConfig>('/api/config/agents', {
          method: 'PUT',
          body: JSON.stringify(data),
        }),
    },
  },

  // System
  system: {
    health: () => request<{ status: string }>('/api/health'),
    status: () => request<SystemStatus>('/api/system/status'),
    tools: () => request<Array<{ name: string; category: string; description: string }>>('/api/system/tools'),
  },

  // Audit Logs
  auditLogs: {
    list: (params?: {
      tool?: string;
      target?: string;
      from?: string;
      to?: string;
      page?: number;
      limit?: number;
    }) =>
      request<PaginatedResult<AuditLog>>(`/api/audit-logs?${qs(params)}`),
  },

  // Context - Contextual Intelligence for assessment configuration
  context: {
    /**
     * Get contextual intelligence for a list of targets
     * Returns previous assessments, open findings, regression test suggestions
     */
    getTargetContext: (targets: string[]) =>
      request<{
        targets: Array<{
          target: string;
          previousAssessments: Array<{
            id: string;
            type: string;
            status: string;
            completedAt: string;
            findingsCount: number;
            criticalCount: number;
            highCount: number;
          }>;
          openFindings: Array<{
            id: string;
            title: string;
            severity: string;
            status: string;
            createdAt: string;
            daysSinceCreated: number;
          }>;
          remediatedFindings: Array<{
            id: string;
            title: string;
            severity: string;
            remediatedAt: string;
            daysSinceRemediated: number;
            lastTestedAt?: string;
            needsRegressionTest: boolean;
          }>;
          stats: {
            totalAssessments: number;
            lastAssessmentDate?: string;
            daysSinceLastAssessment?: number;
            totalFindings: number;
            openCritical: number;
            openHigh: number;
            pendingRegressionTests: number;
          };
        }>;
        suggestions: Array<{
          id: string;
          type: 'regression' | 'open-finding' | 'coverage-gap' | 'threat-intel' | 'compliance';
          priority: 'high' | 'medium' | 'low';
          title: string;
          description: string;
          reasoning: string;
          relatedFindingId?: string;
        }>;
        regressionTests: Array<{
          findingId: string;
          title: string;
          severity: string;
          target: string;
          remediatedAt: string;
        }>;
        coverageAnalysis: {
          testedRecently: string[];
          needsTesting: string[];
          neverTested: string[];
        };
        summary: {
          totalPreviousAssessments: number;
          totalOpenFindings: number;
          pendingRegressionTests: number;
          oldestUntestedTarget?: string;
          mostCriticalOpenFinding?: {
            id: string;
            title: string;
            target: string;
          };
        };
      }>('/api/context/targets', {
        method: 'POST',
        body: JSON.stringify({ targets }),
      }),

    /**
     * Get detailed context for a specific finding
     */
    getFindingContext: (findingId: string) =>
      request<{
        finding: Finding;
        relatedFindings: Array<{
          id: string;
          title: string;
          severity: string;
          status: string;
          created_at: string;
        }>;
        assessmentIds: string[];
      }>(`/api/context/finding/${findingId}`),
  },

  // Templates
  templates: {
    list: (params?: { category?: string; search?: string; builtin?: boolean }) =>
      request<{
        templates: Array<{
          id: string;
          name: string;
          description: string;
          category: 'compliance' | 'industry' | 'attack-type' | 'custom';
          system_prompt: string;
          focus_areas: string[];
          risk_profile: 'aggressive' | 'balanced' | 'conservative';
          phase_instructions?: Record<string, string>;
          phases?: string[];
          severity_threshold?: string;
          author?: string;
          usage_count: number;
          tags?: string[];
          is_builtin: boolean;
          created_at: string;
          updated_at: string;
        }>;
      }>(`/api/templates?${qs(params)}`),

    get: (id: string) =>
      request<{
        id: string;
        name: string;
        description: string;
        category: 'compliance' | 'industry' | 'attack-type' | 'custom';
        system_prompt: string;
        focus_areas: string[];
        risk_profile: 'aggressive' | 'balanced' | 'conservative';
        phase_instructions?: Record<string, string>;
        phases?: string[];
        severity_threshold?: string;
        author?: string;
        usage_count: number;
        tags?: string[];
        is_builtin: boolean;
        created_at: string;
        updated_at: string;
      }>(`/api/templates/${id}`),

    create: (data: {
      name: string;
      description?: string;
      category?: 'compliance' | 'industry' | 'attack-type' | 'custom';
      system_prompt: string;
      focus_areas?: string[];
      risk_profile?: 'aggressive' | 'balanced' | 'conservative';
      phase_instructions?: Record<string, string>;
      phases?: string[];
      severity_threshold?: string;
      author?: string;
      tags?: string[];
    }) =>
      request<{
        id: string;
        name: string;
        description: string;
        category: string;
        system_prompt: string;
        focus_areas: string[];
        risk_profile: string;
        created_at: string;
        updated_at: string;
      }>('/api/templates', {
        method: 'POST',
        body: JSON.stringify(data),
      }),

    update: (id: string, data: Partial<{
      name: string;
      description: string;
      category: string;
      system_prompt: string;
      focus_areas: string[];
      risk_profile: string;
      phase_instructions: Record<string, string>;
      phases: string[];
      severity_threshold: string;
      tags: string[];
    }>) =>
      request(`/api/templates/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),

    delete: (id: string) =>
      request<void>(`/api/templates/${id}`, { method: 'DELETE' }),

    use: (id: string) =>
      request<{ success: boolean }>(`/api/templates/${id}/use`, { method: 'POST' }),

    categories: () =>
      request<{ categories: Record<string, number> }>('/api/templates/meta/categories'),
  },
};

// SSE helper for assessment events
export function subscribeToAssessmentEvents(
  assessmentId: string,
  handlers: {
    onStatusChange?: (data: { status: string; message?: string }) => void;
    onProgress?: (data: { percent: number; currentTool: string }) => void;
    onStepStarted?: (data: { step: string; description: string }) => void;
    onStepCompleted?: (data: { step: string; result: unknown }) => void;
    onFindingCreated?: (data: Finding) => void;
    onCompleted?: (data: Assessment) => void;
    onError?: (data: { message: string; code?: string }) => void;
    onLog?: (data: { level: string; message: string; timestamp: string }) => void;
  }
): () => void {
  const eventSource = new EventSource(`${API_BASE_URL}/api/assessments/${assessmentId}/events`);

  eventSource.addEventListener('status_change', (e) => {
    handlers.onStatusChange?.(JSON.parse(e.data));
  });

  eventSource.addEventListener('progress', (e) => {
    handlers.onProgress?.(JSON.parse(e.data));
  });

  eventSource.addEventListener('step_started', (e) => {
    handlers.onStepStarted?.(JSON.parse(e.data));
  });

  eventSource.addEventListener('step_completed', (e) => {
    handlers.onStepCompleted?.(JSON.parse(e.data));
  });

  eventSource.addEventListener('finding_created', (e) => {
    handlers.onFindingCreated?.(JSON.parse(e.data));
  });

  eventSource.addEventListener('completed', (e) => {
    handlers.onCompleted?.(JSON.parse(e.data));
  });

  eventSource.addEventListener('error', (e: Event) => {
    const messageEvent = e as MessageEvent;
    if (messageEvent.data) {
      handlers.onError?.(JSON.parse(messageEvent.data));
    }
  });

  eventSource.addEventListener('log', (e) => {
    handlers.onLog?.(JSON.parse(e.data));
  });

  return () => {
    eventSource.close();
  };
}
