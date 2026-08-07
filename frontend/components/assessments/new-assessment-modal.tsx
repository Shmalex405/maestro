'use client';

import { useEffect, useMemo, useState } from 'react';

import { AWS_REGIONS } from '@/lib/aws-regions';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Loader2,
  FolderPlus,
  Globe,
  Cloud,
  Network,
  ChevronLeft,
  AlertTriangle,
  Sparkles,
  Bot,
  CheckCircle2,
  FileSpreadsheet,
  Fingerprint,
  BrainCircuit,
} from 'lucide-react';

import { api } from '@/lib/tauri-api';
import { isCodexEnabled } from '@/lib/codex-enabled';
import type {
  Assessment,
  AssessmentType,
  Project,
  CloudAccountScope,
  K8sClusterScope,
  IdentityTarget,
  AiTarget,
  ScopeDomain,
  ScopeNetwork,
  CredentialApp,
  Repository,
  Import,
} from '@/lib/types';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { SearchableSelect } from '@/components/ui/searchable-select';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { toast } from 'sonner';
import type { AwsSourcesLibrary } from '@/lib/tauri-api';
import { useAuthStore } from '@/lib/stores/auth-store';

// Sentinel for the "Assume from" picker meaning backend-brokered creds
// (the per-org Maestro cloud assumes the role and validates org_id —
// Option A), rather than a configured source credential.
const MAESTRO_CLOUD = '__maestro_cloud__';

const NO_PROJECT = '__none__';
const NEW_PROJECT = '__new__';
const NO_CLUSTER = '__none__';
const NO_CREDENTIAL = '__none__';

const CAPABILITY_LABEL: Record<CapabilityId, string> = {
  web_app: 'web application',
  api_security: 'API',
  cloud_assessment: 'cloud infrastructure',
  identity: 'identity / IDP',
  ai: 'AI / LLM',
};

/**
 * Build the prompt that's auto-placed into the assessment terminal after
 * Launch. Lists everything the user picked in the wizard so the operator
 * just has to hit Enter to start. Plain prose — the team-assessment skill
 * does the heavy lifting on the agent side.
 */
function composeAssessmentPrompt(args: {
  capabilities: CapabilityId[];
  targets: string[];
  repoPaths: string[];
  credentialApp: string | null;
  cloudScope?: {
    account_id: string;
    regions: string[];
    services: string[];
    k8s_cluster_id?: string;
  };
  identityTargetIds?: string[];
  aiTargetIds?: string[];
  importedFindings?: Array<{
    vulnerability_type: string;
    severity: string;
    file_path?: string | null;
    line_number?: number | null;
    description?: string | null;
  }>;
}): string {
  const capLabel =
    args.capabilities.length === 1
      ? CAPABILITY_LABEL[args.capabilities[0]]
      : args.capabilities.map((c) => CAPABILITY_LABEL[c]).join(' + ');

  const parts: string[] = [];
  // Invoke the /assess command so its Workflow-chunk orchestration protocol
  // (.claude/commands/assess.md) loads. No profile arg — the inline scope below
  // (Targets / credential app / repos) IS the scope; assess.md uses it directly
  // when no profile matches. (Users had been prepending this by hand.)
  parts.push('/assess');
  parts.push('');
  parts.push(`Run a full ${capLabel} security assessment.`);
  parts.push('');

  if (args.targets.length > 0) {
    parts.push('Targets (in-scope):');
    for (const t of args.targets) parts.push(`- ${t}`);
    parts.push('');
  }

  if (args.cloudScope) {
    parts.push(`Cloud account: ${args.cloudScope.account_id}`);
    if (args.cloudScope.regions.length > 0) {
      parts.push(`Regions: ${args.cloudScope.regions.join(', ')}`);
    }
    if (args.cloudScope.services.length > 0) {
      parts.push(`Services: ${args.cloudScope.services.join(', ')}`);
    }
    if (args.cloudScope.k8s_cluster_id) {
      parts.push(`Kubernetes cluster: ${args.cloudScope.k8s_cluster_id}`);
    }
    parts.push(
      'This cloud account is authorized in scope for this engagement — it was ' +
        'selected from your registered cloud accounts, so treat it as in-scope and ' +
        'do not halt waiting for it to appear in a local scope file. Authentication ' +
        'is managed: the read-only assessment-role credentials are already injected ' +
        'into the container, so do NOT prompt for a role ARN, profile, or access ' +
        'keys. Confirm with `aws sts get-caller-identity`, then proceed.',
    );
    parts.push('');
  }

  if (args.identityTargetIds && args.identityTargetIds.length > 0) {
    parts.push('Identity targets (in-scope):');
    for (const id of args.identityTargetIds) parts.push(`- ${id}`);
    parts.push(
      'These identity providers are authorized in scope for this engagement — ' +
        'they were selected from your registered identity targets, so treat them ' +
        'as in-scope and run the identity surface (identity-recon / identity-exploit ' +
        '/ identity-analysis) against them per .claude/commands/assess.md → ' +
        '"Identity surface (conditional)". Follow the Lockout Mandate: lockout-aware ' +
        'spray, fail-closed, never touch break-glass / excluded principals.',
    );
    parts.push('');
  }

  if (args.aiTargetIds && args.aiTargetIds.length > 0) {
    parts.push('AI targets (in-scope):');
    for (const id of args.aiTargetIds) parts.push(`- ${id}`);
    parts.push(
      'These AI/LLM systems are authorized in scope for this engagement — they ' +
        'were selected from your registered AI targets, so treat them as in-scope ' +
        'and run the AI surface (ai-recon / ai-redteam / ai-analysis) against them ' +
        'per .claude/commands/assess.md → "AI surface (conditional)". Follow the AI ' +
        'Safety Mandate: consumption probe-only, excessive agency ' +
        'capability-not-execution, never the upstream model provider.',
    );
    parts.push('');
  }

  if (args.credentialApp) {
    parts.push(`Authenticate using credential app: ${args.credentialApp}`);
    parts.push('');
  }

  if (args.repoPaths.length > 0) {
    parts.push('Repositories to scan (SAST + IaC):');
    for (const r of args.repoPaths) parts.push(`- ${r}`);
    parts.push('');
  }

  if (args.importedFindings && args.importedFindings.length > 0) {
    parts.push(
      `Imported findings to validate (${args.importedFindings.length} from a prior scan/import):`,
    );
    for (const f of args.importedFindings) {
      const loc = f.file_path
        ? ` @ ${f.file_path}${f.line_number ? `:${f.line_number}` : ''}`
        : '';
      const desc = f.description
        ? ` — ${String(f.description).replace(/\s+/g, ' ').slice(0, 200)}`
        : '';
      parts.push(
        `- [${String(f.severity || 'unknown').toUpperCase()}] ${f.vulnerability_type}${loc}${desc}`,
      );
    }
    parts.push(
      'For EACH imported finding: analyze it from the code/context, locate the live ' +
        'endpoint or code path, attempt to validate/exploit it non-destructively, document ' +
        'real evidence (request + response), and either create a confirmed finding or mark ' +
        'it a false positive with reasoning. Fold these into the assessment alongside the ' +
        'scope above — do not skip them.',
    );
    parts.push('');
  }

  parts.push(
    'Orchestrate this assessment with the Workflow chunks per ' +
      '.claude/commands/assess.md — this is the DEFAULT path. Handle interactive ' +
      'auth yourself as Phase 1, then run the three Workflow chunks in sequence via ' +
      'the Workflow tool (maestro-assess-recon → maestro-assess-exploit → ' +
      'maestro-assess-report), re-authenticating between chunks. Do NOT fall back to ' +
      'the hand-driven Team protocol (skills/team-assessment/SKILL.md) unless the ' +
      'Workflow tool is unavailable or the profile sets orchestrator: team. Validate ' +
      'scope, then begin Phase 1.',
  );

  return parts.join('\n');
}

/**
 * Capability the user can toggle on Step 1. The old wizard exposed a
 * pre-baked "Combined" tile that was mutually exclusive with the other
 * three — now the user multi-selects the same three capabilities and we
 * derive the legacy `AssessmentType` for the backend at submit time
 * (single → that capability; multiple → "combined").
 */
type CapabilityId =
  | 'web_app'
  | 'api_security'
  | 'cloud_assessment'
  | 'identity'
  | 'ai';
type Brain = 'claude' | 'codex';

const CAPABILITY_OPTIONS: Array<{
  id: CapabilityId;
  label: string;
  description: string;
  icon: typeof Globe;
}> = [
  {
    id: 'web_app',
    label: 'Web App',
    description: 'URLs and domains. Auth, injection, headers, business logic.',
    icon: Globe,
  },
  {
    id: 'api_security',
    label: 'API',
    description: 'REST + GraphQL endpoints. Schema fuzzing, IDOR, rate limit.',
    icon: Network,
  },
  {
    id: 'cloud_assessment',
    label: 'Cloud',
    description: 'AWS / Azure / GCP / K8s. IAM, storage, compute, posture.',
    icon: Cloud,
  },
  {
    id: 'identity',
    label: 'Identity / IDP',
    description: 'AD / Entra / Okta / Google / Ping. Spray, consent, privesc.',
    icon: Fingerprint,
  },
  {
    id: 'ai',
    label: 'AI / LLM',
    description: 'Prompt injection, jailbreak, output handling, excessive agency.',
    icon: BrainCircuit,
  },
];

// Legacy single-value `AssessmentType` enum doesn't carry identity/ai, so
// those collapse to 'custom' when chosen alone; the explicit list always
// rides along in `options.capabilities` for any path that wants fidelity.
const LEGACY_TYPE: Partial<Record<CapabilityId, AssessmentType>> = {
  web_app: 'web_app',
  api_security: 'api_security',
  cloud_assessment: 'cloud_assessment',
};

// Service catalogues mirror config/cloud-accounts/page.tsx so the wizard
// surfaces the same set users authored their accounts with.
const PROVIDER_SERVICES: Record<string, string[]> = {
  aws: [
    'ec2', 's3', 'lambda', 'rds', 'ecs', 'eks', 'iam', 'secretsmanager',
    'sqs', 'sns', 'cloudtrail', 'guardduty', 'vpc',
  ],
  azure: [
    'aad', 'storageaccounts', 'virtualmachines', 'keyvault', 'appservice',
    'sqldatabase', 'network',
  ],
  gcp: [
    'compute', 'storage', 'functions', 'gke', 'iam', 'secretmanager',
    'cloudsql', 'cloudresourcemanager',
  ],
};

// Region catalogues per provider. Cloud accounts are saved with a small
// `regions` list (the Add-Account form defaults to a single region), so the
// wizard previously let users toggle only that one. We surface the full
// provider catalogue here and union it with whatever the account was
// configured with — so an operator can scope a run to any region at launch
// time without first editing the account.
const PROVIDER_REGIONS: Record<string, string[]> = {
  aws: AWS_REGIONS,
  azure: [
    'eastus', 'eastus2', 'westus', 'westus2', 'westus3', 'centralus',
    'northeurope', 'westeurope', 'uksouth', 'ukwest', 'southeastasia',
    'eastasia', 'australiaeast', 'japaneast', 'canadacentral', 'brazilsouth',
  ],
  gcp: [
    'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2',
    'europe-west1', 'europe-west2', 'europe-west3', 'europe-north1',
    'asia-east1', 'asia-northeast1', 'asia-south1', 'asia-southeast1',
    'australia-southeast1', 'southamerica-east1',
  ],
};

export interface NewAssessmentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called once the assessment has been created on the backend. The
   *  parent navigates to the new assessment's terminal view. */
  onCreated: (assessment: Assessment) => void;
  /** Optional pre-selected project — when the user opens the modal from
   *  inside a project context (e.g. project list view), default that
   *  project as the selection. */
  defaultProjectId?: string | null;
}

export function NewAssessmentModal({
  open,
  onOpenChange,
  onCreated,
  defaultProjectId,
}: NewAssessmentModalProps) {
  const queryClient = useQueryClient();

  // Wizard state
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [name, setName] = useState('');
  // Multi-select set of capabilities the user wants to test. Replaces the
  // old single-`type` selection; at least one must be chosen to advance.
  const [capabilities, setCapabilities] = useState<CapabilityId[]>([
    'web_app',
  ]);

  // Step 2 — web/api targets. Multi-select set of scope entries the user
  // ticked. Values are the literal pattern/cidr strings we'll submit as
  // targets. Free-text entry was removed in v0.1.89 — users hit 500s from
  // typing out-of-scope placeholder URLs; restricting to configured scope
  // makes that class of failure structurally impossible.
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);

  // Step 2 — cloud scope
  const [cloudAccountId, setCloudAccountId] = useState('');
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);
  const [selectedServices, setSelectedServices] = useState<string[]>([]);
  const [selectedClusterId, setSelectedClusterId] = useState(NO_CLUSTER);
  // Which identity this assessment assumes the target role FROM. Defaults
  // to MAESTRO_CLOUD (backend-brokered — no laptop AWS creds); the user
  // can switch to a configured source credential per assessment.
  const [sourceCredentialId, setSourceCredentialId] = useState(MAESTRO_CLOUD);
  // Step 2 — Identity scope. Multi-select of configured identity_targets ids to
  // include in this run. Gated behind the Identity capability tile (Step 1) and
  // threaded into the kickoff as an "Identity targets (in-scope):" block, so the
  // operator scopes IDPs per assessment instead of every configured one auto-running.
  const [selectedIdentityTargetIds, setSelectedIdentityTargetIds] = useState<string[]>([]);
  // Step 2 — AI scope. Multi-select of configured ai_targets ids to include in
  // this run (opt-in per assessment, like cloud accounts). Default = all
  // configured targets; the user can uncheck any to exclude it. Non-blocking.
  const [selectedAiTargetIds, setSelectedAiTargetIds] = useState<string[]>([]);
  // Logged-in operator email — folded into the session name for CloudTrail.
  const operatorEmail = useAuthStore((s) => s.user?.email);

  // Step 3 — options
  const [projectChoice, setProjectChoice] = useState<string>(
    defaultProjectId ?? NO_PROJECT,
  );
  const [newProjectName, setNewProjectName] = useState('');
  // Multi-select set of repository IDs the user ticked from their
  // configured Code Repositories. We submit each repo's `container_path`
  // as the assessment's `repo_paths`. Free-text entry was removed in
  // v0.1.90 for the same reason as targets — typing an unmounted path
  // makes SAST agents look at nothing and produce confusing empty
  // findings.
  const [selectedRepoIds, setSelectedRepoIds] = useState<string[]>([]);
  // Step 3 — imports the user wants this run to validate. Their findings are
  // folded into the kickoff prompt so the harness validates them as part of
  // the assessment (the bridge from the Import page to a live run).
  const [selectedImportIds, setSelectedImportIds] = useState<string[]>([]);
  const [brain, setBrain] = useState<Brain>('claude');
  // Optional credential app to authenticate against the target. Sourced from
  // the user's saved Credentials config (`config/credentials.yml` /
  // cloud-stored CredentialsConfig.applications).
  const [credentialApp, setCredentialApp] = useState<string>(NO_CREDENTIAL);

  // Reset state every time the modal reopens.
  useEffect(() => {
    if (open) {
      setStep(1);
      setName('');
      setCapabilities(['web_app']);
      setSelectedTargets([]);
      setCloudAccountId('');
      setSelectedRegions([]);
      setSelectedServices([]);
      setSelectedClusterId(NO_CLUSTER);
      setSourceCredentialId(MAESTRO_CLOUD);
      setSelectedIdentityTargetIds([]);
      setSelectedAiTargetIds([]);
      setProjectChoice(defaultProjectId ?? NO_PROJECT);
      setNewProjectName('');
      setSelectedRepoIds([]);
      setSelectedImportIds([]);
      setBrain('claude');
      setCredentialApp(NO_CREDENTIAL);
    }
  }, [open, defaultProjectId]);

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: () => api.projects.list(),
    enabled: open,
  });

  // Capability-derived flags. Each is true if the user ticked the
  // corresponding tile on Step 1; downstream rendering and validation
  // hangs off these instead of the old single `type === '...'` checks.
  const needsWeb = capabilities.includes('web_app');
  const needsApi = capabilities.includes('api_security');
  const needsCloud = capabilities.includes('cloud_assessment');
  const needsIdentity = capabilities.includes('identity');
  const needsAi = capabilities.includes('ai');
  const needsTargets = needsWeb || needsApi;
  // Scope is needed for both target selection (web/api) and cloud-account
  // selection (cloud), so load whenever the modal opens — not just for cloud.
  const { data: scope, isLoading: scopeLoading } = useQuery({
    queryKey: ['scope-config'],
    queryFn: () => api.config.scope.get(),
    enabled: open,
  });

  // Credentials list for the optional Step-3 credential picker.
  const { data: credentialsConfig } = useQuery({
    queryKey: ['credentials-config'],
    queryFn: () => api.config.credentials.get(),
    enabled: open,
  });

  // Source-credential library for the cloud "Assume from" picker. Only
  // fetched when a cloud assessment is in play.
  const { data: awsSources } = useQuery<AwsSourcesLibrary>({
    queryKey: ['aws-sources'],
    queryFn: () => api.config.scope.listAwsSources(),
    enabled: open && needsCloud,
  });

  // Backend-brokered is the default (MAESTRO_CLOUD sentinel set on open),
  // so we do not auto-select a source credential — the user opts into one
  // only by picking it from the dropdown.

  // Configured Code Repositories for the optional Step-3 repo picker.
  const { data: repositories, isLoading: reposLoading } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => api.repositories.list(),
    enabled: open,
  });

  // Prior imports for the optional Step-3 import picker — selecting one folds
  // its findings into the kickoff prompt so the run validates them.
  const { data: imports, isLoading: importsLoading } = useQuery({
    queryKey: ['imports'],
    queryFn: () => api.imports.list(),
    enabled: open,
  });

  const scopeDomains: ScopeDomain[] = scope?.domains ?? [];
  const scopeNetworks: ScopeNetwork[] = scope?.networks ?? [];
  const cloudAccounts: CloudAccountScope[] = scope?.cloud_accounts ?? [];
  const k8sClusters: K8sClusterScope[] = scope?.kubernetes ?? [];
  // Identity targets auto-run when in scope (no per-assessment picker) —
  // surfaced here for awareness so the operator sees which IDPs a run
  // will include alongside the selected web/cloud scope.
  const identityTargets: IdentityTarget[] = scope?.identity_targets ?? [];
  // AI/LLM targets — opt-in per assessment (a checklist below, default none),
  // mirroring how cloud accounts are selected. Threaded into the kickoff as an
  // "AI targets (in-scope):" block so /assess runs the AI surface against them.
  const aiTargets: AiTarget[] = scope?.ai_targets ?? [];

  const credentialApps: Array<[string, CredentialApp]> = useMemo(
    () => Object.entries(credentialsConfig?.applications ?? {}),
    [credentialsConfig],
  );

  const selectedAccount = useMemo(
    () => cloudAccounts.find((a) => a.id === cloudAccountId),
    [cloudAccounts, cloudAccountId],
  );

  // When the user picks a different account, seed the selections. The scope IS
  // the account you pick + the read-only role it assumes — the region/service
  // grids are an optional narrowing, not the definition of scope. So BOTH
  // default to "All" (every chip ticked out of the gate): a run covers the
  // whole account unless the operator pares it down. (Regions used to seed from
  // the account's saved regions, which defaulted to a single hardcoded
  // us-east-1 — wrong for any deployment not in that region.) An empty service
  // set falls back to recon-only discovery.
  useEffect(() => {
    if (!selectedAccount) return;
    const catalogue = PROVIDER_REGIONS[selectedAccount.provider] ?? [];
    const allRegions = [...selectedAccount.regions];
    for (const r of catalogue) if (!allRegions.includes(r)) allRegions.push(r);
    setSelectedRegions(allRegions);
    setSelectedServices(PROVIDER_SERVICES[selectedAccount.provider] ?? []);
  }, [selectedAccount]);

  // Filter clusters to ones whose provider matches the selected account so
  // an AWS account doesn't show GCP clusters in the dropdown.
  const matchingClusters = useMemo(() => {
    if (!selectedAccount) return k8sClusters;
    return k8sClusters.filter(
      (c) => !c.provider || c.provider === selectedAccount.provider,
    );
  }, [k8sClusters, selectedAccount]);

  const availableServices = selectedAccount
    ? PROVIDER_SERVICES[selectedAccount.provider] ?? []
    : [];

  // Full region list the user can pick from: the provider catalogue unioned
  // with whatever the account was saved with (so a custom/opt-in region the
  // operator codified still shows even if it's not in our static list).
  // Configured regions sort first.
  const availableRegions = useMemo(() => {
    if (!selectedAccount) return [] as string[];
    const catalogue = PROVIDER_REGIONS[selectedAccount.provider] ?? [];
    const merged = [...selectedAccount.regions];
    for (const r of catalogue) if (!merged.includes(r)) merged.push(r);
    return merged;
  }, [selectedAccount]);

  // Whether the "All" pseudo-chip is active for each group.
  const allRegionsSelected =
    availableRegions.length > 0 &&
    availableRegions.every((r) => selectedRegions.includes(r));
  const allServicesSelected =
    availableServices.length > 0 &&
    availableServices.every((s) => selectedServices.includes(s));

  // (Removed the region/service "outside configured scope" warning: an
  // assessment's scope is the cloud account you pick + the read-only role it
  // assumes, not a per-region/service allowlist. The warning was pure noise —
  // and flooded once regions defaulted to "All".)

  // ---- Step validation ----
  // Step 1 needs both a name and at least one capability selected.
  const step1Valid = name.trim().length > 0 && capabilities.length > 0;

  // Targets is just an alias for the selected scope entries — kept under
  // the old name to minimise churn in the submit path below.
  const targets = selectedTargets;

  // Resolve the ticked repo IDs back to their container paths. SAST agents
  // run inside the Kali container and need the in-container path
  // (`/mnt/host-home/...`), not the host path, so we always submit
  // `container_path` rather than `path`.
  const repoPaths = useMemo(() => {
    if (!repositories || selectedRepoIds.length === 0) return [] as string[];
    const byId = new Map(repositories.map((r) => [r.id, r] as const));
    return selectedRepoIds
      .map((id) => byId.get(id)?.container_path)
      .filter((p): p is string => typeof p === 'string' && p.length > 0);
  }, [repositories, selectedRepoIds]);

  // Each chosen capability contributes its own requirement; the user
  // needs to satisfy every one before they can advance to step 3.
  const step2Valid = useMemo(() => {
    if (needsTargets && targets.length === 0) return false;
    if (needsCloud && (cloudAccountId === '' || selectedRegions.length === 0)) {
      return false;
    }
    // Identity / AI capabilities each need at least one in-scope target ticked,
    // otherwise the surface would run against nothing.
    if (needsIdentity && selectedIdentityTargetIds.length === 0) return false;
    if (needsAi && selectedAiTargetIds.length === 0) return false;
    // Belt and braces: empty capability set shouldn't reach this point,
    // but if it does, refuse to advance.
    return capabilities.length > 0;
  }, [
    needsTargets,
    needsCloud,
    needsIdentity,
    needsAi,
    targets,
    cloudAccountId,
    selectedRegions,
    selectedIdentityTargetIds,
    selectedAiTargetIds,
    capabilities,
  ]);

  const step3Valid =
    projectChoice !== NEW_PROJECT || newProjectName.trim().length > 0;

  // ---- Step navigation ----
  const goNext = async () => {
    if (step === 1 && step1Valid) {
      setStep(2);
      return;
    }
    if (step === 2 && step2Valid) {
      // No blocking pre-flight here. We used to call the
      // `validate_cloud_scope` Tauri command, which reads the on-disk
      // `config/scope.yml`. In a cloud-routed deployment that file is
      // empty/stale (cloud is the source of truth), so every cloud account
      // came back "not configured in scope.yml" and hard-blocked launch —
      // even though the account is defined in the cloud backend the dropdown
      // sourced it from. The account is present by construction (same source
      // as the dropdown). The assessment-runtime scope guard remains the real
      // enforcement point.
      setStep(3);
      return;
    }
    if (step === 3 && step3Valid) {
      createMutation.mutate();
    }
  };

  const goBack = () => {
    setStep((s) => (s > 1 ? ((s - 1) as 1 | 2 | 3) : s));
  };

  const createMutation = useMutation({
    mutationFn: async () => {
      let projectId: string | undefined;

      if (projectChoice === NEW_PROJECT) {
        const trimmed = newProjectName.trim();
        if (!trimmed) {
          throw new Error('Please enter a project name');
        }
        const project = await api.projects.create({ name: trimmed });
        projectId = project.id;
      } else if (projectChoice !== NO_PROJECT) {
        projectId = projectChoice;
      }

      // Cloud scope rides in `options.cloud_scope` so no Rust schema
      // change is needed. Orchestrator + cloud-recon agent read this to
      // know what to enumerate. Brain choice ditto via options.brain so
      // it survives the create -> terminal handoff.
      const cloudScope = needsCloud
        ? {
            account_id: cloudAccountId,
            regions: selectedRegions,
            services: selectedServices,
            ...(sourceCredentialId ? { source_credential_id: sourceCredentialId } : {}),
            ...(selectedClusterId !== NO_CLUSTER
              ? { k8s_cluster_id: selectedClusterId }
              : {}),
          }
        : undefined;

      // The legacy `AssessmentType` enum doesn't carry a list, so we
      // collapse the multi-select into the closest single value: one
      // capability → that capability, more than one → "combined". The
      // raw set rides along in `options.capabilities` so any backend
      // path that wants the explicit list (orchestrator dispatch, future
      // mode picker) can read it without losing fidelity.
      const derivedType: AssessmentType =
        capabilities.length === 1
          ? (LEGACY_TYPE[capabilities[0]] ?? 'custom')
          : ('combined' as AssessmentType);

      const credentialAppValue =
        credentialApp !== NO_CREDENTIAL ? credentialApp : undefined;

      // Prompt that the terminal-view will auto-type into Claude/Codex once
      // the CLI is ready. Stored alongside the rest of the wizard's choices
      // so a Resume / fresh remount can read the same source.
      // Fetch the findings for the selected imports and fold them into the
      // kickoff prompt so the harness validates them as part of this run.
      let importedFindings: Array<{
        vulnerability_type: string;
        severity: string;
        file_path?: string | null;
        line_number?: number | null;
        description?: string | null;
      }> = [];
      if (selectedImportIds.length > 0) {
        const lists = await Promise.all(
          selectedImportIds.map((id) =>
            api.importedFindings.list({ import_id: id }).catch(() => []),
          ),
        );
        importedFindings = lists.flat().map((f) => ({
          vulnerability_type: f.vulnerability_type,
          severity: f.severity,
          file_path: f.file_path,
          line_number: f.line_number,
          description: f.description,
        }));
      }

      const pendingPrompt = composeAssessmentPrompt({
        capabilities,
        targets,
        repoPaths,
        credentialApp: credentialAppValue ?? null,
        cloudScope,
        identityTargetIds: needsIdentity ? selectedIdentityTargetIds : [],
        aiTargetIds: needsAi ? selectedAiTargetIds : [],
        importedFindings,
      });

      const options: Record<string, unknown> = {
        brain,
        capabilities,
        pending_prompt: pendingPrompt,
      };
      if (cloudScope) options.cloud_scope = cloudScope;
      if (needsIdentity && selectedIdentityTargetIds.length > 0) {
        options.identity_target_ids = selectedIdentityTargetIds;
      }
      if (needsAi && selectedAiTargetIds.length > 0) {
        options.ai_target_ids = selectedAiTargetIds;
      }
      if (selectedImportIds.length > 0) options.import_ids = selectedImportIds;

      try {
        const assessment = await api.assessments.create({
          name: name.trim(),
          type: derivedType,
          project_id: projectId,
          targets: targets.length > 0 ? targets : undefined,
          repo_paths: repoPaths.length > 0 ? repoPaths : undefined,
          credential_app: credentialAppValue,
          start: false,
          options,
        });
        // Install the assume-role session into the Kali container so the
        // run authenticates as the chosen source. Non-fatal — the
        // assessment already exists; surface a warning if injection fails
        // (e.g. container not running, expired SSO, missing source).
        if (
          needsCloud &&
          selectedAccount &&
          selectedAccount.provider === 'aws' &&
          selectedAccount.auth_method === 'role'
        ) {
          try {
            const brokered = sourceCredentialId === MAESTRO_CLOUD;
            const session = await api.config.scope.startCloudAssessmentCredentials(
              selectedAccount,
              brokered ? undefined : sourceCredentialId,
              brokered, // use_backend
              false, // use_federation (direct federation is single-tenant only)
              brokered ? (operatorEmail ?? undefined) : undefined,
            );
            if (!session.ok) {
              // A cloud assessment with no installed credentials will run its
              // cloud tools against an absent ~/.aws/credentials and every cloud
              // test fails with "Unable to locate credentials" — but that used to
              // be buried in a dismissible warning toast, so the run looked fine.
              // Surface it as a prominent error that names the consequence.
              if (session.needs_reauth) {
                // SSO expired beyond silent refresh — the assessment is
                // created, but it can't authenticate until the user signs
                // in again. Point them at the in-app re-auth on the Cloud
                // Accounts page (Verify pops the SSO sign-in there).
                toast.error(
                  'AWS SSO session expired — cloud tests will FAIL until you re-authenticate in Config → Cloud Accounts (click Verify), then start this assessment.',
                  { duration: 12000 },
                );
              } else if (session.error) {
                toast.error(
                  `Cloud credentials NOT installed — every cloud test will fail with "Unable to locate credentials". Fix and re-run: ${session.error}`,
                  { duration: 12000 },
                );
              }
            }
          } catch (e) {
            toast.error(
              `Cloud credentials NOT installed — every cloud test will fail with "Unable to locate credentials". Fix and re-run: ${e instanceof Error ? e.message : String(e)}`,
              { duration: 12000 },
            );
          }
        }
        return assessment;
      } catch (err) {
        // Surface the actual cloud-side detail (the wrapped `ApiError`
        // carries `status` + `message`). Without this, the user just sees
        // a generic "Failed to create assessment" while the real cause
        // (validation error, scope mismatch, etc.) is buried in devtools.
        const status =
          err && typeof err === 'object' && 'status' in err
            ? (err as { status: number }).status
            : null;
        const detail = err instanceof Error ? err.message : String(err);
        console.error('[new-assessment] create failed', { status, detail, err });
        const prefix = status ? `Cloud backend returned ${status}` : 'Create failed';
        throw new Error(`${prefix}: ${detail}`);
      }
    },
    onSuccess: (assessment) => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      onCreated(assessment);
    },
  });

  const projectOptions = (projects || []).map((p: Project) => ({
    value: p.id,
    label: p.name,
  }));

  const stepDescription =
    step === 1
      ? 'Name your assessment and pick what you want to test.'
      : step === 2
        ? 'Define what’s in scope.'
        : 'Where to file results, what code to scan, which brain drives.';

  const isPending = createMutation.isPending;
  const canAdvance =
    (step === 1 && step1Valid) ||
    (step === 2 && step2Valid) ||
    (step === 3 && step3Valid && !isPending);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>New assessment — Step {step} of 3</DialogTitle>
          <DialogDescription>{stepDescription}</DialogDescription>
        </DialogHeader>

        {/* Step indicator */}
        <div className="flex items-center gap-2 px-1">
          {[1, 2, 3].map((n) => (
            <div
              key={n}
              className={`h-1.5 flex-1 rounded-full transition-colors ${
                n <= step ? 'bg-primary' : 'bg-muted'
              }`}
            />
          ))}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void goNext();
          }}
          className="space-y-4 py-2"
        >
          {/* ============ STEP 1: Name + Type ============ */}
          {step === 1 && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="assessment-name">
                  Name <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="assessment-name"
                  autoFocus
                  placeholder="e.g. Acme staging audit · Q2 API pen test"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  maxLength={120}
                />
              </div>

              <div className="space-y-2">
                <Label>
                  Assessment type{' '}
                  <span className="text-xs text-muted-foreground font-normal">
                    (pick one or more)
                  </span>
                </Label>
                <div className="grid grid-cols-2 gap-2">
                  {CAPABILITY_OPTIONS.map((opt) => {
                    const Icon = opt.icon;
                    const selected = capabilities.includes(opt.id);
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        role="checkbox"
                        aria-checked={selected}
                        onClick={() =>
                          setCapabilities((prev) =>
                            prev.includes(opt.id)
                              ? prev.filter((c) => c !== opt.id)
                              : [...prev, opt.id],
                          )
                        }
                        className={`text-left rounded-lg border p-3 transition-colors ${
                          selected
                            ? 'border-primary bg-primary/5'
                            : 'border-border hover:border-primary/40 hover:bg-muted/50'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <Icon
                            className={`h-4 w-4 ${
                              selected ? 'text-primary' : 'text-muted-foreground'
                            }`}
                          />
                          <span className="font-medium text-sm">{opt.label}</span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-snug">
                          {opt.description}
                        </p>
                      </button>
                    );
                  })}
                </div>
                {capabilities.length === 0 && (
                  <p className="text-xs text-destructive">
                    Select at least one assessment type to continue.
                  </p>
                )}
              </div>
            </>
          )}

          {/* ============ STEP 2: Scope ============ */}
          {step === 2 && (
            <>
              {needsTargets && (
                <div className="space-y-1.5">
                  <Label>
                    {needsApi && !needsWeb ? 'API endpoints' : 'Targets'}{' '}
                    <span className="text-destructive">*</span>
                  </Label>
                  {scopeLoading ? (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Loading scope…
                    </div>
                  ) : scopeDomains.length === 0 && scopeNetworks.length === 0 ? (
                    <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                        <div>
                          <p className="font-medium text-amber-400">
                            No domains or networks in scope
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Add at least one entry under{' '}
                            <span className="font-mono">
                              Config → Scope
                            </span>{' '}
                            before launching a web or API assessment.
                          </p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="flex flex-col gap-1 p-2 border rounded-md max-h-56 overflow-y-auto">
                        {scopeDomains.map((d) => {
                          const value = d.pattern;
                          const active = selectedTargets.includes(value);
                          return (
                            <button
                              key={`d-${value}`}
                              type="button"
                              role="checkbox"
                              aria-checked={active}
                              onClick={() =>
                                setSelectedTargets((cur) =>
                                  active
                                    ? cur.filter((t) => t !== value)
                                    : [...cur, value],
                                )
                              }
                              className={`flex items-center justify-between rounded-md border px-2.5 py-2 text-left text-sm transition-colors ${
                                active
                                  ? 'border-primary bg-primary/5'
                                  : 'border-transparent hover:bg-muted/50'
                              }`}
                            >
                              <span className="flex items-center gap-2 min-w-0">
                                <Globe className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                                <span className="font-mono truncate">{value}</span>
                              </span>
                              <Badge
                                variant="outline"
                                className="text-[10px] ml-2 shrink-0"
                              >
                                {d.environment}
                              </Badge>
                            </button>
                          );
                        })}
                        {scopeNetworks.map((n) => {
                          const value = n.cidr;
                          const active = selectedTargets.includes(value);
                          return (
                            <button
                              key={`n-${value}`}
                              type="button"
                              role="checkbox"
                              aria-checked={active}
                              onClick={() =>
                                setSelectedTargets((cur) =>
                                  active
                                    ? cur.filter((t) => t !== value)
                                    : [...cur, value],
                                )
                              }
                              className={`flex items-center justify-between rounded-md border px-2.5 py-2 text-left text-sm transition-colors ${
                                active
                                  ? 'border-primary bg-primary/5'
                                  : 'border-transparent hover:bg-muted/50'
                              }`}
                            >
                              <span className="flex items-center gap-2 min-w-0">
                                <Network className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                                <span className="font-mono truncate">{value}</span>
                              </span>
                              <Badge
                                variant="outline"
                                className="text-[10px] ml-2 shrink-0"
                              >
                                {n.environment}
                              </Badge>
                            </button>
                          );
                        })}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Pick one or more entries from your configured scope.
                        Edit the list under{' '}
                        <span className="font-mono">Config → Scope</span>.
                      </p>
                    </>
                  )}
                </div>
              )}

              {needsCloud && (
                <div className="space-y-3">
                  {scopeLoading ? (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Loading cloud scope…
                    </div>
                  ) : cloudAccounts.length === 0 ? (
                    <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                        <div>
                          <p className="font-medium text-amber-400">
                            No cloud accounts configured
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Add an account in{' '}
                            <span className="font-mono">
                              Config → Cloud Accounts
                            </span>{' '}
                            before launching a cloud assessment.
                          </p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="space-y-1.5">
                        <Label>
                          Cloud account{' '}
                          <span className="text-destructive">*</span>
                        </Label>
                        <Select
                          value={cloudAccountId}
                          onValueChange={(v) => {
                            setCloudAccountId(v);
                            setSelectedClusterId(NO_CLUSTER);
                          }}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select an account" />
                          </SelectTrigger>
                          <SelectContent>
                            {cloudAccounts.map((a) => (
                              <SelectItem key={a.id} value={a.id}>
                                <span className="font-mono">{a.id}</span>
                                <span className="text-muted-foreground ml-2">
                                  {a.provider.toUpperCase()}
                                  {a.account_id && ` · ${a.account_id}`}
                                  {a.subscription_id &&
                                    ` · ${a.subscription_id}`}
                                  {a.project_id && ` · ${a.project_id}`}
                                </span>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>

                      {selectedAccount && (
                        <>
                          {selectedAccount.provider === 'aws' &&
                            selectedAccount.auth_method === 'role' && (
                              <div className="space-y-1.5">
                                <Label>Assume from</Label>
                                <Select
                                  value={sourceCredentialId}
                                  onValueChange={setSourceCredentialId}
                                >
                                  <SelectTrigger>
                                    <SelectValue placeholder="Choose how to authenticate" />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value={MAESTRO_CLOUD}>
                                      Maestro cloud — managed
                                      <span className="text-muted-foreground ml-2">
                                        · recommended
                                      </span>
                                    </SelectItem>
                                    {(awsSources?.sources ?? []).map((s) => (
                                      <SelectItem key={s.id} value={s.id}>
                                        <span>{s.name}</span>
                                        {awsSources?.default_id === s.id && (
                                          <span className="text-muted-foreground ml-2">
                                            · default
                                          </span>
                                        )}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                                <p className="text-xs text-muted-foreground flex items-center gap-1">
                                  <CheckCircle2 className="h-3 w-3 text-emerald-500 flex-shrink-0" />
                                  {sourceCredentialId === MAESTRO_CLOUD ? (
                                    <>
                                      Your Maestro cloud assumes{' '}
                                      <span className="font-mono">
                                        {selectedAccount.role_arn ?? 'the target role'}
                                      </span>{' '}
                                      and brokers the creds — no AWS keys on this machine.
                                    </>
                                  ) : (
                                    <>
                                      Maestro assumes{' '}
                                      <span className="font-mono">
                                        {selectedAccount.role_arn ?? 'the target role'}
                                      </span>{' '}
                                      from this source credential.
                                    </>
                                  )}
                                </p>
                              </div>
                            )}
                          <div className="space-y-1.5">
                            <Label>
                              Regions{' '}
                              <span className="text-destructive">*</span>
                            </Label>
                            <div className="flex flex-wrap gap-1.5 p-2 border rounded-md max-h-32 overflow-y-auto">
                              <Badge
                                variant={allRegionsSelected ? 'default' : 'outline'}
                                className="cursor-pointer text-xs font-medium"
                                onClick={() =>
                                  setSelectedRegions(
                                    allRegionsSelected ? [] : [...availableRegions],
                                  )
                                }
                              >
                                All
                              </Badge>
                              {availableRegions.map((region) => {
                                const active = selectedRegions.includes(region);
                                return (
                                  <Badge
                                    key={region}
                                    variant={active ? 'default' : 'outline'}
                                    className="cursor-pointer text-xs"
                                    onClick={() =>
                                      setSelectedRegions((cur) =>
                                        active
                                          ? cur.filter((r) => r !== region)
                                          : [...cur, region],
                                      )
                                    }
                                  >
                                    {region}
                                  </Badge>
                                );
                              })}
                            </div>
                          </div>

                          <div className="space-y-1.5">
                            <Label>Services</Label>
                            <div className="flex flex-wrap gap-1.5 p-2 border rounded-md max-h-32 overflow-y-auto">
                              <Badge
                                variant={allServicesSelected ? 'default' : 'outline'}
                                className="cursor-pointer text-xs font-medium"
                                onClick={() =>
                                  setSelectedServices(
                                    allServicesSelected ? [] : [...availableServices],
                                  )
                                }
                              >
                                All
                              </Badge>
                              {availableServices.map((svc) => {
                                const active = selectedServices.includes(svc);
                                return (
                                  <Badge
                                    key={svc}
                                    variant={active ? 'default' : 'outline'}
                                    className="cursor-pointer text-xs"
                                    onClick={() =>
                                      setSelectedServices((cur) =>
                                        active
                                          ? cur.filter((s) => s !== svc)
                                          : [...cur, svc],
                                      )
                                    }
                                  >
                                    {svc}
                                  </Badge>
                                );
                              })}
                            </div>
                            {selectedServices.length === 0 && (
                              <p className="text-xs text-muted-foreground">
                                No services selected — recon will discover what
                                exists, no targeted exploit phase.
                              </p>
                            )}
                          </div>

                          {matchingClusters.length > 0 && (
                            <div className="space-y-1.5">
                              <Label>Kubernetes cluster (optional)</Label>
                              <Select
                                value={selectedClusterId}
                                onValueChange={setSelectedClusterId}
                              >
                                <SelectTrigger>
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value={NO_CLUSTER}>
                                    None
                                  </SelectItem>
                                  {matchingClusters.map((c) => (
                                    <SelectItem key={c.id} value={c.id}>
                                      <span className="font-mono">{c.id}</span>
                                      <span className="text-muted-foreground ml-2">
                                        {c.cluster}
                                      </span>
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                            </div>
                          )}
                        </>
                      )}
                    </>
                  )}

                </div>
              )}

              {/* Identity / IDP scope — opt-in per assessment (a toggle list).
                  Gated behind the Identity capability tile; selected targets are
                  threaded into the kickoff as an "Identity targets (in-scope):"
                  block so the identity surface (identity-recon / identity-exploit
                  / identity-analysis) runs against exactly the chosen IDPs. */}
              {needsIdentity && (
                <div className="space-y-1.5">
                  <Label>
                    Identity / IDP targets{' '}
                    <span className="text-destructive">*</span>
                  </Label>
                  {scopeLoading ? (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Loading identity scope…
                    </div>
                  ) : identityTargets.length === 0 ? (
                    <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                        <div>
                          <p className="font-medium text-amber-400">
                            No identity targets configured
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Add an AD / Entra / Okta / Google / Ping target under{' '}
                            <span className="font-mono">
                              Config → Identity Targets
                            </span>{' '}
                            before launching an identity assessment.
                          </p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="flex flex-col gap-1 p-2 border rounded-md max-h-56 overflow-y-auto">
                        {identityTargets.map((t) => {
                          const checked = selectedIdentityTargetIds.includes(t.id);
                          return (
                            <button
                              type="button"
                              key={t.id}
                              role="checkbox"
                              aria-checked={checked}
                              onClick={() =>
                                setSelectedIdentityTargetIds((prev) =>
                                  prev.includes(t.id)
                                    ? prev.filter((x) => x !== t.id)
                                    : [...prev, t.id],
                                )
                              }
                              className={`flex items-center justify-between gap-2 text-sm px-2 py-1 rounded-md border text-left transition-colors ${
                                checked
                                  ? 'border-primary bg-primary/5'
                                  : 'border-transparent hover:bg-muted/50'
                              }`}
                            >
                              <span className="flex items-center gap-2 truncate">
                                <span
                                  className={`h-3.5 w-3.5 rounded-sm border shrink-0 ${
                                    checked
                                      ? 'bg-primary border-primary'
                                      : 'border-muted-foreground/40'
                                  }`}
                                />
                                <span className="font-mono truncate">{t.id}</span>
                                {t.display_name && (
                                  <span className="text-muted-foreground ml-1 truncate">
                                    {t.display_name}
                                  </span>
                                )}
                              </span>
                              <Badge variant="outline" className="text-[10px] ml-2 shrink-0">
                                {t.kind}
                              </Badge>
                            </button>
                          );
                        })}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Selected IDPs run the identity surface (identity-recon /
                        identity-exploit / identity-analysis) — lockout-aware, fail-closed.
                        Manage the list under{' '}
                        <span className="font-mono">Config → Identity Targets</span>.
                      </p>
                    </>
                  )}
                </div>
              )}

              {/* AI / LLM scope — opt-in per assessment (a toggle list). Gated
                  behind the AI capability tile; selected targets are threaded
                  into the kickoff as an "AI targets (in-scope):" block so the AI
                  surface (ai-recon / ai-redteam / ai-analysis) runs against them. */}
              {needsAi && (
                <div className="space-y-1.5">
                  <Label>
                    AI / LLM targets{' '}
                    <span className="text-destructive">*</span>
                  </Label>
                  {scopeLoading ? (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Loading AI scope…
                    </div>
                  ) : aiTargets.length === 0 ? (
                    <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                        <div>
                          <p className="font-medium text-amber-400">
                            No AI targets configured
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Add a model / chat-app / agent / RAG / MCP target under{' '}
                            <span className="font-mono">
                              Config → AI Targets
                            </span>{' '}
                            before launching an AI assessment.
                          </p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="flex flex-col gap-1 p-2 border rounded-md max-h-56 overflow-y-auto">
                        {aiTargets.map((t) => {
                          const checked = selectedAiTargetIds.includes(t.id);
                          return (
                            <button
                              type="button"
                              key={t.id}
                              role="checkbox"
                              aria-checked={checked}
                              onClick={() =>
                                setSelectedAiTargetIds((prev) =>
                                  prev.includes(t.id)
                                    ? prev.filter((x) => x !== t.id)
                                    : [...prev, t.id],
                                )
                              }
                              className={`flex items-center justify-between gap-2 text-sm px-2 py-1 rounded-md border text-left transition-colors ${
                                checked
                                  ? 'border-primary bg-primary/5'
                                  : 'border-transparent hover:bg-muted/50'
                              }`}
                            >
                              <span className="flex items-center gap-2 truncate">
                                <span
                                  className={`h-3.5 w-3.5 rounded-sm border shrink-0 ${
                                    checked
                                      ? 'bg-primary border-primary'
                                      : 'border-muted-foreground/40'
                                  }`}
                                />
                                <span className="font-mono truncate">{t.id}</span>
                                {t.display_name && (
                                  <span className="text-muted-foreground ml-1 truncate">
                                    {t.display_name}
                                  </span>
                                )}
                              </span>
                              <Badge variant="outline" className="text-[10px] ml-2 shrink-0">
                                {t.kind}
                              </Badge>
                            </button>
                          );
                        })}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Selected AI systems run the AI surface (ai-recon / ai-redteam / ai-analysis) —
                        probe-only, capability-not-execution. Manage the list under{' '}
                        <span className="font-mono">Config → AI Targets</span>.
                      </p>
                    </>
                  )}
                </div>
              )}
            </>
          )}

          {/* ============ STEP 3: Options ============ */}
          {step === 3 && (
            <>
              <div className="space-y-1.5">
                <Label>Project</Label>
                <SearchableSelect
                  value={
                    projectChoice === NO_PROJECT ? '' : projectChoice
                  }
                  onChange={(v) => setProjectChoice(v || NO_PROJECT)}
                  options={[
                    ...projectOptions,
                    {
                      value: NEW_PROJECT,
                      label: '+ New project…',
                      hint: 'create one inline',
                    },
                  ]}
                  placeholder="No project"
                  searchPlaceholder="Search projects…"
                  allOptionLabel="No project"
                  width="w-full"
                />

                {projectChoice === NEW_PROJECT && (
                  <div className="pt-2 pl-3 border-l-2 border-primary/30">
                    <Label
                      htmlFor="new-project-name"
                      className="text-xs text-muted-foreground"
                    >
                      New project name
                    </Label>
                    <div className="flex items-center gap-2 mt-1">
                      <FolderPlus className="h-4 w-4 text-muted-foreground shrink-0" />
                      <Input
                        id="new-project-name"
                        placeholder="e.g. Acme · Q2 audits"
                        value={newProjectName}
                        onChange={(e) => setNewProjectName(e.target.value)}
                        maxLength={80}
                      />
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="credential-app">
                  Login credential (optional)
                </Label>
                <Select
                  value={credentialApp}
                  onValueChange={setCredentialApp}
                >
                  <SelectTrigger id="credential-app">
                    <SelectValue placeholder="None — run unauthenticated" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NO_CREDENTIAL}>
                      None — run unauthenticated
                    </SelectItem>
                    {credentialApps.map(([key, app]) => (
                      <SelectItem key={key} value={key}>
                        <span className="font-mono">{key}</span>
                        <span className="text-muted-foreground ml-2 text-xs">
                          {app.auth_type}
                          {app.environment && ` · ${app.environment}`}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Pick a saved credential app to authenticate against the
                  target. Edit the list under{' '}
                  <span className="font-mono">Config → Credentials</span>.
                </p>
              </div>

              <div className="space-y-1.5">
                <Label>Code repositories (optional)</Label>
                {reposLoading ? (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading repositories…
                  </div>
                ) : (repositories ?? []).length === 0 ? (
                  <div className="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
                    No repositories configured yet. Add one under{' '}
                    <span className="font-mono">Config → Code Repositories</span>{' '}
                    to enable SAST + IaC scanning in this assessment.
                  </div>
                ) : (
                  <div className="flex flex-col gap-1 p-2 border rounded-md max-h-48 overflow-y-auto">
                    {(repositories as Repository[]).map((r) => {
                      const active = selectedRepoIds.includes(r.id);
                      return (
                        <button
                          key={r.id}
                          type="button"
                          role="checkbox"
                          aria-checked={active}
                          onClick={() =>
                            setSelectedRepoIds((cur) =>
                              active
                                ? cur.filter((x) => x !== r.id)
                                : [...cur, r.id],
                            )
                          }
                          className={`flex items-center justify-between rounded-md border px-2.5 py-2 text-left text-sm transition-colors ${
                            active
                              ? 'border-primary bg-primary/5'
                              : 'border-transparent hover:bg-muted/50'
                          }`}
                        >
                          <span className="flex flex-col min-w-0">
                            <span className="font-medium truncate">
                              {r.name}
                            </span>
                            <span className="font-mono text-xs text-muted-foreground truncate">
                              {r.container_path}
                            </span>
                          </span>
                          <Badge
                            variant="outline"
                            className="text-[10px] ml-2 shrink-0"
                          >
                            {r.source_type === 'github' ? 'GitHub' : 'Local'}
                          </Badge>
                        </button>
                      );
                    })}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  Pick repos from your configured Code Repositories. Container
                  paths under{' '}
                  <span className="font-mono">/mnt/host-home/...</span> are
                  submitted for SAST + IaC checks.
                </p>
              </div>

              <div className="space-y-1.5">
                <Label>Imports to validate (optional)</Label>
                {importsLoading ? (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading imports…
                  </div>
                ) : (imports ?? []).length === 0 ? (
                  <div className="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
                    No imports yet. Add one on the{' '}
                    <span className="font-mono">Import</span> page to validate
                    prior-scan findings as part of an assessment.
                  </div>
                ) : (
                  <div className="flex flex-col gap-1 p-2 border rounded-md max-h-48 overflow-y-auto">
                    {(imports as Import[]).map((imp) => {
                      const active = selectedImportIds.includes(imp.id);
                      return (
                        <button
                          key={imp.id}
                          type="button"
                          role="checkbox"
                          aria-checked={active}
                          onClick={() =>
                            setSelectedImportIds((cur) =>
                              active
                                ? cur.filter((x) => x !== imp.id)
                                : [...cur, imp.id],
                            )
                          }
                          className={`flex items-center justify-between rounded-md border px-2.5 py-2 text-left text-sm transition-colors ${
                            active
                              ? 'border-primary bg-primary/5'
                              : 'border-transparent hover:bg-muted/50'
                          }`}
                        >
                          <span className="flex items-center gap-2 min-w-0">
                            <FileSpreadsheet className="h-4 w-4 shrink-0 text-muted-foreground" />
                            <span className="flex flex-col min-w-0">
                              <span className="font-medium truncate">
                                {imp.name}
                              </span>
                              <span className="text-xs text-muted-foreground truncate">
                                {imp.source} · {imp.findings_count} finding
                                {imp.findings_count === 1 ? '' : 's'}
                              </span>
                            </span>
                          </span>
                          <Badge
                            variant="outline"
                            className="text-[10px] ml-2 shrink-0"
                          >
                            {imp.findings_count}
                          </Badge>
                        </button>
                      );
                    })}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  Selected imports&apos; findings are folded into the run so the
                  harness validates each one and confirms or dismisses it. Add or
                  manage imports on the{' '}
                  <span className="font-mono">Import</span> page.
                </p>
              </div>

              {isCodexEnabled() && (
              <div className="space-y-1.5">
                <Label>Brain</Label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setBrain('claude')}
                    className={`flex items-center gap-2 rounded-lg border p-2.5 text-sm transition-colors ${
                      brain === 'claude'
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-primary/40 hover:bg-muted/50'
                    }`}
                  >
                    <Sparkles
                      className={`h-4 w-4 ${
                        brain === 'claude'
                          ? 'text-primary'
                          : 'text-muted-foreground'
                      }`}
                    />
                    Claude
                  </button>
                  <button
                    type="button"
                    onClick={() => setBrain('codex')}
                    className={`flex items-center gap-2 rounded-lg border p-2.5 text-sm transition-colors ${
                      brain === 'codex'
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-primary/40 hover:bg-muted/50'
                    }`}
                  >
                    <Bot
                      className={`h-4 w-4 ${
                        brain === 'codex'
                          ? 'text-primary'
                          : 'text-muted-foreground'
                      }`}
                    />
                    Codex
                  </button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Toggleable later from the assessment terminal.
                </p>
              </div>
              )}
            </>
          )}

          {createMutation.error && (
            <p className="text-sm text-destructive">
              {createMutation.error instanceof Error
                ? createMutation.error.message
                : 'Failed to create assessment'}
            </p>
          )}

          <DialogFooter className="sticky bottom-0 -mx-6 -mb-2 flex items-center justify-between gap-2 border-t bg-background px-6 pb-2 pt-3 sm:justify-between">
            {step === 1 ? (
              // Step 1 has no back action (it's the first step). Empty
              // span keeps the flex layout (Continue stays right-aligned).
              <span />
            ) : (
              <Button
                type="button"
                variant="ghost"
                onClick={goBack}
                disabled={isPending}
              >
                <ChevronLeft className="h-4 w-4 mr-1" />
                Back
              </Button>
            )}

            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!canAdvance}>
                {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {step === 3 ? 'Launch' : 'Next'}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
