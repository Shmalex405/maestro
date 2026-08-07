'use client';

import { useState } from 'react';
import type { ParsedBlock, ToolCallMetadata, FindingMetadata, CostMetadata } from '@/lib/terminal-parser';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  User,
  Bot,
  Wrench,
  ChevronDown,
  ChevronRight,
  Brain,
  AlertTriangle,
  AlertCircle,
  AlertOctagon,
  Info,
  DollarSign,
  Loader2,
  CheckCircle2,
  XCircle,
  KeyRound,
  HelpCircle,
  Cloud,
  Container,
  MapPin,
  Box,
  Copy,
  Check,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

// ─── Severity config ────────────────────────────────────────────────────────

const severityConfig = {
  critical: { icon: AlertOctagon, color: 'bg-red-500', textColor: 'text-red-500', borderColor: 'border-red-500/30' },
  high: { icon: AlertTriangle, color: 'bg-orange-500', textColor: 'text-orange-500', borderColor: 'border-orange-500/30' },
  medium: { icon: AlertCircle, color: 'bg-yellow-500', textColor: 'text-yellow-500', borderColor: 'border-yellow-500/30' },
  low: { icon: Info, color: 'bg-blue-500', textColor: 'text-blue-500', borderColor: 'border-blue-500/30' },
  info: { icon: Info, color: 'bg-gray-500', textColor: 'text-gray-500', borderColor: 'border-gray-500/30' },
} as const;

// ─── Cloud provider config ──────────────────────────────────────────────────
// Mirrors the colors used in config/cloud-accounts and the assessment header
// bar so a finding's provider chip matches the assessment's provider chip.

const providerConfig: Record<
  NonNullable<FindingMetadata['cloud_provider']>,
  { label: string; color: string; icon: typeof Cloud }
> = {
  aws: { label: 'AWS', color: 'bg-orange-500', icon: Cloud },
  azure: { label: 'Azure', color: 'bg-blue-500', icon: Cloud },
  gcp: { label: 'GCP', color: 'bg-red-500', icon: Cloud },
  k8s: { label: 'K8s', color: 'bg-cyan-600', icon: Container },
};

// ─── User Input Block ───────────────────────────────────────────────────────

function UserInputBlock({ block }: { block: ParsedBlock }) {
  return (
    <div className="flex gap-3 py-3">
      <div className="flex-shrink-0 mt-0.5">
        <div className="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center">
          <User className="h-3.5 w-3.5 text-primary" />
        </div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-xs text-muted-foreground mb-1">You</div>
        <div className="text-sm text-foreground whitespace-pre-wrap">{block.content}</div>
      </div>
    </div>
  );
}

// ─── Assistant Text Block ───────────────────────────────────────────────────

function AssistantTextBlock({ block }: { block: ParsedBlock }) {
  return (
    <div className="flex gap-3 py-3">
      <div className="flex-shrink-0 mt-0.5">
        <div className="h-7 w-7 rounded-full bg-emerald-500/10 flex items-center justify-center">
          <Bot className="h-3.5 w-3.5 text-emerald-500" />
        </div>
      </div>
      <div className="flex-1 min-w-0 prose prose-sm prose-invert max-w-none break-words overflow-hidden">
        <Markdown
          remarkPlugins={[remarkGfm]}
          components={{
            pre: ({ children }) => (
              <pre className="bg-zinc-900 border border-zinc-700 rounded-lg p-3 overflow-x-auto text-xs">
                {children}
              </pre>
            ),
            code: ({ children, className }) => {
              const isInline = !className;
              if (isInline) {
                return (
                  <code className="bg-zinc-800 px-1.5 py-0.5 rounded text-xs text-emerald-400">
                    {children}
                  </code>
                );
              }
              return <code className={className}>{children}</code>;
            },
            table: ({ children }) => (
              <div className="overflow-x-auto my-2">
                <table className="text-xs border-collapse w-full">{children}</table>
              </div>
            ),
            th: ({ children }) => (
              <th className="border border-zinc-700 bg-zinc-800/50 px-2 py-1 text-left text-xs font-medium">
                {children}
              </th>
            ),
            td: ({ children }) => (
              <td className="border border-zinc-700 px-2 py-1 text-xs">{children}</td>
            ),
          }}
        >
          {block.content}
        </Markdown>
      </div>
    </div>
  );
}

// ─── Tool Call Block ────────────────────────────────────────────────────────

function ToolCallBlock({ block }: { block: ParsedBlock }) {
  const [expanded, setExpanded] = useState(false);
  const meta = block.metadata as ToolCallMetadata | undefined;
  const toolName = meta?.toolName || 'Unknown Tool';
  const status = meta?.status || 'running';

  const StatusIcon = status === 'running' ? Loader2 :
    status === 'completed' ? CheckCircle2 : XCircle;
  const statusColor = status === 'running' ? 'text-blue-400' :
    status === 'completed' ? 'text-green-400' : 'text-red-400';

  // Clean tool name for display (remove mcp__kali-pentest__ prefix)
  const displayName = toolName.replace(/^mcp__kali-pentest__/, '').replace(/_/g, ' ');

  return (
    <div className="py-2">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 w-full text-left px-3 py-2 rounded-lg bg-zinc-900/50 border border-zinc-800 hover:border-zinc-700 transition-colors"
      >
        <Wrench className="h-3.5 w-3.5 text-zinc-400 flex-shrink-0" />
        <span className="text-xs font-mono text-zinc-300 flex-1 truncate">
          {displayName}
        </span>
        <StatusIcon className={cn('h-3.5 w-3.5 flex-shrink-0', statusColor, status === 'running' && 'animate-spin')} />
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 text-zinc-500" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />
        )}
      </button>
      {expanded && (
        <div className="mt-1 ml-6 p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-400 overflow-x-auto max-h-[300px] overflow-y-auto whitespace-pre-wrap">
          {block.content}
        </div>
      )}
    </div>
  );
}

// ─── Tool Result Block ──────────────────────────────────────────────────────

function ToolResultBlock({ block }: { block: ParsedBlock }) {
  const [expanded, setExpanded] = useState(false);
  const meta = block.metadata as { toolName?: string; status?: string } | undefined;
  const content = block.content;
  const preview = content.length > 120 ? content.slice(0, 120) + '...' : content;

  return (
    <div className="py-1 ml-6">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-start gap-2 w-full text-left"
      >
        <span className="text-xs text-zinc-500 flex-shrink-0 mt-0.5">
          {expanded ? '▼' : '▶'}
        </span>
        <span className="text-xs font-mono text-zinc-500 flex-1 truncate">
          {expanded ? `Result from ${meta?.toolName || 'tool'}:` : preview}
        </span>
      </button>
      {expanded && (
        <div className="mt-1 p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-400 overflow-x-auto max-h-[400px] overflow-y-auto whitespace-pre-wrap">
          {content}
        </div>
      )}
    </div>
  );
}

// ─── Thinking Block ─────────────────────────────────────────────────────────

function ThinkingBlock({ block }: { block: ParsedBlock }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="py-2">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 text-xs text-zinc-500 hover:text-zinc-400 transition-colors"
      >
        <Brain className="h-3.5 w-3.5" />
        <span>Thinking...</span>
        {expanded ? (
          <ChevronDown className="h-3 w-3" />
        ) : (
          <ChevronRight className="h-3 w-3" />
        )}
      </button>
      {expanded && block.content && (
        <div className="mt-1 ml-6 p-3 rounded-lg bg-zinc-950/50 border border-zinc-800/50 text-xs text-zinc-500 italic max-h-[200px] overflow-y-auto whitespace-pre-wrap">
          {block.content}
        </div>
      )}
    </div>
  );
}

// ─── System Message Block ───────────────────────────────────────────────────

function SystemBlock({ block }: { block: ParsedBlock }) {
  const variant = (block.metadata as { variant?: string })?.variant || 'info';
  const colors = {
    info: 'text-blue-400 bg-blue-500/5 border-blue-500/20',
    success: 'text-green-400 bg-green-500/5 border-green-500/20',
    warning: 'text-yellow-400 bg-yellow-500/5 border-yellow-500/20',
    error: 'text-red-400 bg-red-500/5 border-red-500/20',
  };
  const color = colors[variant as keyof typeof colors] || colors.info;

  return (
    <div className={cn('py-2 px-3 rounded-lg border text-xs', color)}>
      {block.content}
    </div>
  );
}

// ─── ARN Badge ──────────────────────────────────────────────────────────────
// Monospace pill with copy button. ARNs are long and copyable values that
// reviewers frequently paste into the AWS console — give them a one-click
// copy instead of triple-clicking through truncated text.

function ArnBadge({ arn }: { arn: string }) {
  const [copied, setCopied] = useState(false);

  const onCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(arn);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (err) {
      console.warn('[block-renderers] copy ARN failed', err);
    }
  };

  return (
    <button
      onClick={onCopy}
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-zinc-700 bg-zinc-900/50 hover:bg-zinc-900 transition-colors max-w-full"
      title={`Copy ARN: ${arn}`}
    >
      <span className="text-[10px] font-mono text-zinc-300 truncate max-w-[280px]">
        {arn}
      </span>
      {copied ? (
        <Check className="h-2.5 w-2.5 text-green-400 shrink-0" />
      ) : (
        <Copy className="h-2.5 w-2.5 text-zinc-500 shrink-0" />
      )}
    </button>
  );
}

// ─── Finding Detected Block ─────────────────────────────────────────────────

function FindingDetectedBlock({ block }: { block: ParsedBlock }) {
  const meta = block.metadata as FindingMetadata | undefined;
  const severity = (meta?.severity || 'info') as keyof typeof severityConfig;
  const config = severityConfig[severity] || severityConfig.info;
  const Icon = config.icon;
  const provider = meta?.cloud_provider
    ? providerConfig[meta.cloud_provider]
    : null;
  const ProviderIcon = provider?.icon;
  // Show resource chips row when any cloud-shaped metadata is present.
  const hasCloudChips =
    meta?.account_id || meta?.region || meta?.resource_type || meta?.k8s_cluster;

  return (
    <div className={cn('py-2 px-3 rounded-lg border', config.borderColor, 'bg-zinc-900/50')}>
      <div className="flex items-center gap-2 flex-wrap">
        <Badge className={cn(config.color, 'text-white text-[10px] px-1.5 py-0')}>
          {severity.toUpperCase()}
        </Badge>
        {provider && ProviderIcon && (
          <Badge className={cn(provider.color, 'text-white text-[10px] px-1.5 py-0 gap-1')}>
            <ProviderIcon className="h-2.5 w-2.5" />
            {provider.label}
          </Badge>
        )}
        <Icon className={cn('h-3.5 w-3.5', config.textColor)} />
        <span className="text-sm font-medium text-foreground">{meta?.title || block.content}</span>
      </div>

      {/* ARN badge — separate row so long ARNs don't squash the title */}
      {meta?.arn && (
        <div className="mt-1.5 ml-16">
          <ArnBadge arn={meta.arn} />
        </div>
      )}

      {/* Cloud resource chips — provider-agnostic */}
      {hasCloudChips && (
        <div className="mt-1.5 ml-16 flex items-center gap-1 flex-wrap">
          {meta?.account_id && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
              {meta.account_id}
            </Badge>
          )}
          {meta?.region && (
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 gap-1">
              <MapPin className="h-2.5 w-2.5" />
              {meta.region}
            </Badge>
          )}
          {meta?.resource_type && (
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 gap-1">
              <Box className="h-2.5 w-2.5" />
              {meta.resource_type}
            </Badge>
          )}
          {meta?.k8s_cluster && (
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 gap-1 font-mono">
              <Container className="h-2.5 w-2.5" />
              {meta.k8s_cluster}
              {meta.k8s_namespace && (
                <span className="text-muted-foreground">/{meta.k8s_namespace}</span>
              )}
            </Badge>
          )}
        </div>
      )}

      {/* Fallback target line — only shows when the finding doesn't have
          an ARN (which already includes resource info) and the target
          is meaningful (not empty). */}
      {meta?.target && !meta?.arn && (
        <div className="text-xs text-muted-foreground mt-1 ml-16">
          Target: {meta.target}
        </div>
      )}
    </div>
  );
}

// ─── Cost Info Block ────────────────────────────────────────────────────────

function CostInfoBlock({ block }: { block: ParsedBlock }) {
  const meta = block.metadata as CostMetadata | undefined;

  return (
    <div className="py-1 flex items-center gap-2 text-xs text-zinc-500">
      <DollarSign className="h-3 w-3" />
      {meta?.cost && <span>{meta.cost}</span>}
      {meta?.totalTokens && <span>{meta.totalTokens.toLocaleString()} tokens</span>}
      {!meta?.cost && !meta?.totalTokens && <span>{block.content}</span>}
    </div>
  );
}

// ─── Prompt Waiting Block ───────────────────────────────────────────────────

function PromptWaitingBlock({ block }: { block: ParsedBlock }) {
  const isOtp = (block.metadata as { isOtp?: boolean })?.isOtp;

  return (
    <div className="flex gap-3 py-3">
      <div className="flex-shrink-0 mt-1">
        <div className={cn(
          'h-8 w-8 rounded-full flex items-center justify-center animate-pulse',
          isOtp ? 'bg-amber-500/20' : 'bg-purple-500/20'
        )}>
          {isOtp ? (
            <KeyRound className="h-4 w-4 text-amber-500" />
          ) : (
            <HelpCircle className="h-4 w-4 text-purple-500" />
          )}
        </div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium">
            {isOtp ? 'OTP Code Required' : 'Input Required'}
          </span>
          <Badge
            variant="outline"
            className={cn(
              'text-xs animate-pulse',
              isOtp ? 'text-amber-500 border-amber-500/30' : 'text-purple-500 border-purple-500/30'
            )}
          >
            Action Required
          </Badge>
        </div>
        <div className="text-sm text-muted-foreground whitespace-pre-wrap">
          {block.content}
        </div>
      </div>
    </div>
  );
}

// ─── Block Renderer Dispatcher ──────────────────────────────────────────────

export function BlockRenderer({ block }: { block: ParsedBlock }) {
  switch (block.type) {
    case 'user_input':
      return <UserInputBlock block={block} />;
    case 'assistant_text':
      return <AssistantTextBlock block={block} />;
    case 'tool_call':
      return <ToolCallBlock block={block} />;
    case 'tool_result':
      return <ToolResultBlock block={block} />;
    case 'thinking':
      return <ThinkingBlock block={block} />;
    case 'system':
      return <SystemBlock block={block} />;
    case 'finding_detected':
      return <FindingDetectedBlock block={block} />;
    case 'cost_info':
      return <CostInfoBlock block={block} />;
    case 'prompt_waiting':
      return <PromptWaitingBlock block={block} />;
    default:
      return (
        <div className="py-1 text-xs text-zinc-500 font-mono whitespace-pre-wrap">
          {block.content}
        </div>
      );
  }
}
