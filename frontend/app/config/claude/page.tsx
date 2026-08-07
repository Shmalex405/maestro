'use client';

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  CheckCircle2,
  XCircle,
  Loader2,
  KeyRound,
  ShieldCheck,
  RefreshCw,
  Eye,
  EyeOff,
  AlertCircle,
} from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import type { ClaudeCredentialMode } from '@/lib/types';

// Pretty label helpers — keep wording consistent across status pills.
const MODE_LABEL: Record<ClaudeCredentialMode, string> = {
  oauth: 'Sign in with Claude',
  api_key: 'API key',
};

export default function ClaudeAuthPage() {
  const queryClient = useQueryClient();

  // Active state — polled every 10s so the UI reflects external changes
  // (a fresh OAuth login inside the Terminal pane, etc.).
  const { data: authState, isLoading: authLoading, refetch: refetchAuth } = useQuery({
    queryKey: ['claude-auth-state'],
    queryFn: () => api.claude.getAuthState(),
    refetchInterval: 10_000,
  });

  // BYO API key form state
  const [keyInput, setKeyInput] = useState('');
  const [keyVisible, setKeyVisible] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);

  const activeMode: ClaudeCredentialMode = authState?.mode ?? 'oauth';

  const handleSelectMode = async (mode: ClaudeCredentialMode) => {
    if (mode === activeMode) return;
    if (mode === 'api_key' && !authState?.api_key_present) {
      // Allow selecting API-key mode only after a key is saved — otherwise
      // the next assessment launch silently falls back to OAuth.
      toast.error('Add an Anthropic API key below before switching to API key mode.');
      return;
    }
    try {
      await api.claude.setMode(mode);
      toast.success(`Active mode set to ${MODE_LABEL[mode]}`);
      queryClient.invalidateQueries({ queryKey: ['claude-auth-state'] });
      queryClient.invalidateQueries({ queryKey: ['system-status-global'] });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  const handleTestKey = async () => {
    setKeyError(null);
    setTesting(true);
    try {
      await api.claude.testApiKey(keyInput.trim());
      toast.success('Key works — Anthropic accepted it');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setKeyError(msg);
    } finally {
      setTesting(false);
    }
  };

  const handleSaveKey = async () => {
    setKeyError(null);
    setSaving(true);
    try {
      // Always validate before persisting — saves a support ticket later.
      await api.claude.testApiKey(keyInput.trim());
      await api.claude.setApiKey(keyInput.trim());
      // Switch to API-key mode automatically — saving is the strongest
      // signal that this is what the user wants to use.
      await api.claude.setMode('api_key');
      toast.success('API key saved to Keychain. Active mode set to API key.');
      setKeyInput('');
      setKeyVisible(false);
      queryClient.invalidateQueries({ queryKey: ['claude-auth-state'] });
      queryClient.invalidateQueries({ queryKey: ['system-status-global'] });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setKeyError(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleClearKey = async () => {
    setClearing(true);
    try {
      await api.claude.clearApiKey();
      // If API-key was the active mode, fall back to OAuth so we don't
      // leave the system in an unusable state.
      if (activeMode === 'api_key') {
        await api.claude.setMode('oauth');
      }
      toast.success('API key removed from Keychain');
      queryClient.invalidateQueries({ queryKey: ['claude-auth-state'] });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Claude Authentication</h1>
        <p className="text-muted-foreground">
          Connect Claude Code so Maestro can run AI-powered security assessments.
        </p>
      </div>

      {/* Status / source-of-truth card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              Current Status
            </CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                refetchAuth();
                queryClient.invalidateQueries({ queryKey: ['system-status-global'] });
              }}
              disabled={authLoading}
            >
              <RefreshCw className={cn('h-4 w-4 mr-2', authLoading && 'animate-spin')} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {authLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Checking…
            </div>
          ) : (
            <div className="flex flex-col gap-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Active mode:</span>
                <Badge variant="secondary" className="font-medium">
                  {MODE_LABEL[activeMode]}
                </Badge>
              </div>
              <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs">
                <div className="flex items-center gap-1.5">
                  {authState?.oauth_authenticated ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                  )}
                  <span>OAuth session in container</span>
                </div>
                <div className="flex items-center gap-1.5">
                  {authState?.api_key_present ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                  )}
                  <span>API key in Keychain</span>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Mode 1 — OAuth (default) */}
      <ModeCard
        icon={<KeyRound className="h-5 w-5" />}
        title="Sign in with Claude"
        recommended
        active={activeMode === 'oauth'}
        onSelect={() => handleSelectMode('oauth')}
        description={
          <>
            Uses your personal Claude Pro or Max subscription. Best for individual
            pentesters — each user signs into their own account inside the Kali
            container. The terminal pane handles the OAuth flow.
          </>
        }
      >
        {authState?.oauth_authenticated ? (
          <div className="flex items-center gap-2 text-sm text-green-600">
            <CheckCircle2 className="h-4 w-4" />
            Signed in inside the Kali container
          </div>
        ) : (
          <div className="text-sm text-muted-foreground">
            Not signed in yet. Open the Terminal pane and click <strong>Connect Claude</strong> to start the sign-in flow.
          </div>
        )}
      </ModeCard>

      {/* Mode 2 — BYO API key */}
      <ModeCard
        icon={<KeyRound className="h-5 w-5" />}
        title="API key"
        active={activeMode === 'api_key'}
        onSelect={() => handleSelectMode('api_key')}
        description={
          <>
            Use an Anthropic Console API key — pay-per-use, no rate limits, ideal
            when one billing account covers multiple pentesters or for ZDR /
            compliance requirements. The key is stored in the macOS Keychain and
            never sent to Groovy Security.
          </>
        }
      >
        <div className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="anthropic-key">Anthropic API key</Label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Input
                  id="anthropic-key"
                  type={keyVisible ? 'text' : 'password'}
                  value={keyInput}
                  onChange={(e) => {
                    setKeyInput(e.target.value);
                    setKeyError(null);
                  }}
                  placeholder="sk-ant-..."
                  autoComplete="off"
                  spellCheck={false}
                />
                <button
                  type="button"
                  onClick={() => setKeyVisible((v) => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  tabIndex={-1}
                >
                  {keyVisible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              <Button
                variant="outline"
                onClick={handleTestKey}
                disabled={testing || saving || keyInput.trim().length === 0}
              >
                {testing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                Test
              </Button>
              <Button
                onClick={handleSaveKey}
                disabled={saving || testing || keyInput.trim().length === 0}
              >
                {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                Save
              </Button>
            </div>
            {keyError && (
              <p className="flex items-start gap-1.5 text-xs text-destructive">
                <AlertCircle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                {keyError}
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              Stored in your macOS Keychain. Never sent to Groovy Security.
            </p>
          </div>

          {authState?.api_key_present && (
            <div className="flex items-center justify-between rounded-md border border-border bg-muted/30 px-3 py-2 text-sm">
              <div className="flex items-center gap-2 text-green-600">
                <CheckCircle2 className="h-4 w-4" />
                Key saved in Keychain
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleClearKey}
                disabled={clearing}
              >
                {clearing ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : null}
                Clear
              </Button>
            </div>
          )}
        </div>
      </ModeCard>

      {/* Mutual exclusion hint */}
      <p className="text-xs text-muted-foreground">
        Only one mode is active at a time. Switching modes takes effect on the
        next launch of the Terminal pane.
      </p>
    </div>
  );
}

interface ModeCardProps {
  icon: React.ReactNode;
  title: string;
  description: React.ReactNode;
  active: boolean;
  recommended?: boolean;
  onSelect: () => void;
  children?: React.ReactNode;
}

function ModeCard({ icon, title, description, active, recommended, onSelect, children }: ModeCardProps) {
  return (
    <Card
      className={cn(
        'transition-colors',
        active ? 'border-primary ring-1 ring-primary/20' : 'border-border',
      )}
    >
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className={cn('p-2 rounded-md', active ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground')}>
              {icon}
            </div>
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                {title}
                {recommended && (
                  <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                    Recommended
                  </Badge>
                )}
              </CardTitle>
              <CardDescription className="mt-1 leading-relaxed">{description}</CardDescription>
            </div>
          </div>
          <Button
            size="sm"
            variant={active ? 'default' : 'outline'}
            onClick={onSelect}
            disabled={active}
          >
            {active ? (
              <>
                <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
                Active
              </>
            ) : (
              'Use this'
            )}
          </Button>
        </div>
      </CardHeader>
      {children && <CardContent className="pt-0">{children}</CardContent>}
    </Card>
  );
}
