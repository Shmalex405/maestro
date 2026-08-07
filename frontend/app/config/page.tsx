'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { isCodexEnabled } from '@/lib/codex-enabled';
import { getDataMode, dataModeLabel } from '@/lib/deployment-mode';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Target,
  Key,
  Wrench,
  Users,
  ArrowRight,
  Network,
  Globe,
  ShieldAlert,
  Shield,
  KeyRound,
  Cloud,
  RefreshCw,
  Puzzle,
  Github,
  Fingerprint,
  Bot,
  Database,
  HardDrive,
} from 'lucide-react';

export default function ConfigPage() {
  // Read after mount — getDataMode() touches localStorage, which the
  // static-export prerender does not have.
  const [dataMode, setLocalDataMode] = useState<'local' | 'cloud'>('cloud');
  useEffect(() => setLocalDataMode(getDataMode()), []);

  const { data: scope, isLoading: scopeLoading } = useQuery({
    queryKey: ['scope'],
    queryFn: () => api.config.scope.get(),
  });

  const { data: credentials, isLoading: credentialsLoading } = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.config.credentials.get(),
  });

  const { data: systemStatus, isLoading: statusLoading } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => api.system.getStatus(),
  });

  const { data: claudeAuth } = useQuery({
    queryKey: ['claude-auth-state'],
    queryFn: () => api.claude.getAuthState(),
    retry: 1,
  });

  const { data: codexAuth } = useQuery({
    queryKey: ['codex-auth-state'],
    queryFn: () => api.codex.getAuthState(),
    retry: 1,
  });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Configuration"
        description="Manage scope, credentials, and tool settings"
      />

      {/* System Status */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="text-sm font-medium">System Status</CardTitle>
        </CardHeader>
        <CardContent>
          {statusLoading ? (
            <div className="flex gap-4">
              <Skeleton className="h-8 w-32" />
              <Skeleton className="h-8 w-32" />
            </div>
          ) : (
            <div className="flex flex-wrap gap-4">
              <div className="flex items-center gap-2">
                <div
                  className={`h-3 w-3 rounded-full ${
                    systemStatus?.docker?.kali_running
                      ? 'bg-green-500'
                      : 'bg-red-500'
                  }`}
                />
                <span className="text-sm">
                  Kali Container: {systemStatus?.docker?.kali_running ? 'running' : 'stopped'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div
                  className={`h-3 w-3 rounded-full ${
                    systemStatus?.database_connected ? 'bg-green-500' : 'bg-red-500'
                  }`}
                />
                <span className="text-sm">
                  Database: {systemStatus?.database_connected ? 'connected' : 'disconnected'}
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Config Cards */}
      <div className="grid gap-4 md:grid-cols-2 stagger-children">
        {/* Data & Sync — first because it decides where all other data lands */}
        <Link href="/config/data-sync">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary text-primary-foreground">
                    {dataMode === 'local' ? (
                      <HardDrive className="h-5 w-5" />
                    ) : (
                      <Database className="h-5 w-5" />
                    )}
                  </div>
                  <CardTitle>Data &amp; Sync</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>
                {dataMode === 'local'
                  ? 'Storing findings on this machine'
                  : 'Syncing findings to a shared backend'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  {dataMode === 'local' ? (
                    <HardDrive className="h-3 w-3" />
                  ) : (
                    <Cloud className="h-3 w-3" />
                  )}
                  {dataModeLabel(dataMode)} mode
                </Badge>
                <Badge variant="secondary">
                  {dataMode === 'local' ? 'local SQLite' : 'shared Postgres'}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Scope */}
        <Link href="/config/scope">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary text-primary-foreground">
                    <Target className="h-5 w-5" />
                  </div>
                  <CardTitle>Scope</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Define allowed testing targets</CardDescription>
            </CardHeader>
            <CardContent>
              {scopeLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-4 w-24" />
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Network className="h-3 w-3" />
                    {scope?.networks?.length || 0} networks
                  </Badge>
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Globe className="h-3 w-3" />
                    {scope?.domains?.length || 0} domains
                  </Badge>
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <ShieldAlert className="h-3 w-3" />
                    {scope?.exclusions?.length || 0} exclusions
                  </Badge>
                </div>
              )}
            </CardContent>
          </Card>
        </Link>

        {/* Credentials */}
        <Link href="/config/credentials">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-green-500 text-white">
                    <Key className="h-5 w-5" />
                  </div>
                  <CardTitle>Credentials</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Manage application authentication</CardDescription>
            </CardHeader>
            <CardContent>
              {credentialsLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-4 w-24" />
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Key className="h-3 w-3" />
                    {Object.keys(credentials?.applications || {}).length} applications
                  </Badge>
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Users className="h-3 w-3" />
                    {Object.keys(credentials?.test_accounts || {}).length} test accounts
                  </Badge>
                </div>
              )}
            </CardContent>
          </Card>
        </Link>

        {/* Tools */}
        <Link href="/config/tools">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-amber-600 text-white">
                    <Wrench className="h-5 w-5" />
                  </div>
                  <CardTitle>Tools & Agents</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Configure tool parameters and agent settings</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary">nmap</Badge>
                <Badge variant="secondary">nuclei</Badge>
                <Badge variant="secondary">sqlmap</Badge>
                <Badge variant="secondary">+more</Badge>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Claude Authentication */}
        <Link href="/config/claude">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-orange-700 text-white">
                    <KeyRound className="h-5 w-5" />
                  </div>
                  <CardTitle>Claude</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Sign in with Claude or BYO API key</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  <KeyRound className="h-3 w-3" />
                  {claudeAuth?.mode === 'api_key'
                    ? 'API key'
                    : 'Sign in with Claude'}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Codex Authentication (parallel of Claude — OpenAI / GPT-5.5).
            Hidden unless NEXT_PUBLIC_CODEX_ENABLED; backend/proxy stay intact. */}
        {isCodexEnabled() && (
        <Link href="/config/codex">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-emerald-700 text-white">
                    <KeyRound className="h-5 w-5" />
                  </div>
                  <CardTitle>Codex</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Sign in with ChatGPT or BYO API key</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  <KeyRound className="h-3 w-3" />
                  {codexAuth?.mode === 'api_key'
                    ? 'API key'
                    : 'Sign in with ChatGPT'}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>
        )}

        {/* Integrations */}
        <Link href="/config/integrations">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-gray-700 text-white">
                    <Puzzle className="h-5 w-5" />
                  </div>
                  <CardTitle>Integrations</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Connect external services</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Github className="h-3 w-3" />
                  GitHub
                </Badge>
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Key className="h-3 w-3" />
                  Jira
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Cloud Accounts (Red Team) */}
        <Link href="/config/cloud-accounts">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-sky-600 text-white">
                    <Shield className="h-5 w-5" />
                  </div>
                  <CardTitle>Cloud Accounts</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>AWS, Azure, GCP and K8s scope for red teaming</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Cloud className="h-3 w-3" />
                  Cloud red team
                </Badge>
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Network className="h-3 w-3" />
                  K8s clusters
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Identity Targets (Red Team) */}
        <Link href="/config/identity-targets">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-indigo-600 text-white">
                    <Fingerprint className="h-5 w-5" />
                  </div>
                  <CardTitle>Identity Targets</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Entra, M365, Okta, Google Workspace, Ping and AD scope for red teaming</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Fingerprint className="h-3 w-3" />
                  Identity red team
                </Badge>
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Shield className="h-3 w-3" />
                  Lockout Mandate
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* AI Targets (Red Team) */}
        <Link href="/config/ai-targets">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-violet-600 text-white">
                    <Bot className="h-5 w-5" />
                  </div>
                  <CardTitle>AI Targets</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Chatbots, agents, RAG apps and model APIs for AI/LLM red teaming</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Bot className="h-3 w-3" />
                  AI red team
                </Badge>
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Shield className="h-3 w-3" />
                  Safety Mandate
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Cloud Sync */}
        <Link href="/config/cloud">
          <Card className="glass-card cursor-pointer hover-lift h-full">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-amber-700 text-white">
                    <Cloud className="h-5 w-5" />
                  </div>
                  <CardTitle>Cloud Sync</CardTitle>
                </div>
                <ArrowRight className="h-5 w-5 text-muted-foreground" />
              </div>
              <CardDescription>Sync data with self-hosted backend</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary" className="flex items-center gap-1">
                  <RefreshCw className="h-3 w-3" />
                  Multi-tenant sync
                </Badge>
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Cloud className="h-3 w-3" />
                  SSO support
                </Badge>
              </div>
            </CardContent>
          </Card>
        </Link>
      </div>
    </div>
  );
}
