'use client';

import { useState } from 'react';
import { api } from '@/lib/tauri-api';
import type { CloudAccountInput, CloudAuthProvider } from '@/lib/types';
import { AWS_REGIONS } from '@/lib/aws-regions';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { toast } from 'sonner';
import {
  Cloud,
  Server,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  AlertTriangle,
  Shield,
  User,
} from 'lucide-react';

/** Editable subset of CloudAccount — everything the user fills in on the
 *  create/edit page. The parent decides what to do on submit (POST a new
 *  account vs PUT an existing one). */
export interface CloudAccountFormProps {
  initial: CloudAccountInput;
  submitLabel: string;
  onSubmit: (input: CloudAccountInput) => Promise<void>;
  /** When set, the cancel button routes back to the list page. */
  showCancel?: boolean;
  onCancel?: () => void;
}

const defaultInput: CloudAccountInput = {
  name: '',
  enabled: true,
  api_url: '',
  auth_provider: 'cognito',
  email: undefined,
  cognito_region: undefined,
  cognito_user_pool_id: undefined,
  cognito_client_id: undefined,
  oidc_issuer: undefined,
  oidc_client_id: undefined,
  auto_sync: false,
  sync_interval_seconds: 300,
};

export function makeBlankAccountInput(): CloudAccountInput {
  return { ...defaultInput };
}

export function CloudAccountForm({
  initial,
  submitLabel,
  onSubmit,
  showCancel = false,
  onCancel,
}: CloudAccountFormProps) {
  const [name, setName] = useState(initial.name);
  const [apiUrl, setApiUrl] = useState(initial.api_url);
  const [authProvider, setAuthProvider] = useState<CloudAuthProvider>(initial.auth_provider);
  const [email, setEmail] = useState(initial.email ?? '');
  const [cognitoRegion, setCognitoRegion] = useState(initial.cognito_region ?? '');
  const [cognitoUserPoolId, setCognitoUserPoolId] = useState(initial.cognito_user_pool_id ?? '');
  const [cognitoClientId, setCognitoClientId] = useState(initial.cognito_client_id ?? '');
  const [oidcIssuer, setOidcIssuer] = useState(initial.oidc_issuer ?? '');
  const [oidcClientId, setOidcClientId] = useState(initial.oidc_client_id ?? '');
  const [autoSync, setAutoSync] = useState(initial.auto_sync);
  const [syncInterval, setSyncInterval] = useState(initial.sync_interval_seconds);

  const [isTesting, setIsTesting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message?: string } | null>(null);

  const collect = (): CloudAccountInput => ({
    name: name.trim(),
    enabled: true,
    api_url: apiUrl.trim(),
    auth_provider: authProvider,
    email: authProvider === 'local' ? email || undefined : undefined,
    cognito_region: authProvider === 'cognito' ? cognitoRegion || undefined : undefined,
    cognito_user_pool_id: authProvider === 'cognito' ? cognitoUserPoolId || undefined : undefined,
    cognito_client_id: authProvider === 'cognito' ? cognitoClientId || undefined : undefined,
    oidc_issuer: authProvider === 'oidc' ? oidcIssuer || undefined : undefined,
    oidc_client_id: authProvider === 'oidc' ? oidcClientId || undefined : undefined,
    auto_sync: autoSync,
    sync_interval_seconds: syncInterval,
  });

  const handleTestConnection = async () => {
    if (!apiUrl) {
      toast.error('Please enter an API URL');
      return;
    }
    setIsTesting(true);
    setTestResult(null);
    try {
      const result = await api.config.cloud.testConnection(apiUrl);
      setTestResult({
        success: result,
        message: result ? 'Connection successful' : 'Connection failed',
      });
      if (result) toast.success('Connection successful');
      else toast.error('Connection failed');
    } catch (error) {
      const msg =
        error instanceof Error
          ? error.message
          : typeof error === 'string'
            ? error
            : JSON.stringify(error);
      setTestResult({ success: false, message: msg || 'Connection test failed' });
      toast.error(`Connection test failed${msg ? `: ${msg}` : ''}`);
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = async () => {
    const input = collect();
    if (!input.name) {
      toast.error('Please enter an account name');
      return;
    }
    if (!input.api_url) {
      toast.error('Please enter an API URL');
      return;
    }
    setIsSaving(true);
    try {
      await onSubmit(input);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Identity */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Cloud className="h-5 w-5 text-primary" />
            <CardTitle>Account</CardTitle>
          </div>
          <CardDescription>
            A friendly name for this cloud connection — shown on the accounts list.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="account-name">Name</Label>
            <Input
              id="account-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Groovy Security"
            />
          </div>
        </CardContent>
      </Card>

      {/* Connection Test Result */}
      {testResult && (
        <Card className={testResult.success ? 'border-green-500' : 'border-red-500'}>
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              {testResult.success ? (
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              ) : (
                <XCircle className="h-5 w-5 text-red-500" />
              )}
              <p className="font-medium">{testResult.message}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Server Configuration */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5 text-primary" />
            <CardTitle>Server Configuration</CardTitle>
          </div>
          <CardDescription>Configure connection to your self-hosted backend</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="api-url">API URL</Label>
            <div className="flex gap-2">
              <Input
                id="api-url"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                placeholder="https://api.example.com"
                className="flex-1"
              />
              <Button variant="outline" onClick={handleTestConnection} disabled={isTesting}>
                {isTesting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Test'}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              The URL of your deployed backend API
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Authentication */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-purple-500" />
            <CardTitle>Authentication</CardTitle>
          </div>
          <CardDescription>How users sign in against this backend</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Authentication Method</Label>
            <div className="grid md:grid-cols-3 gap-3">
              <div
                onClick={() => setAuthProvider('local')}
                className={`p-3 rounded-lg border-2 cursor-pointer transition-all ${
                  authProvider === 'local'
                    ? 'border-primary bg-primary/5'
                    : 'border-muted hover:border-muted-foreground/50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <User className="h-4 w-4" />
                  <span className="font-medium">Email/Password</span>
                </div>
                <p className="text-xs text-muted-foreground">Built-in authentication</p>
              </div>

              <div
                onClick={() => setAuthProvider('cognito')}
                className={`p-3 rounded-lg border-2 cursor-pointer transition-all ${
                  authProvider === 'cognito'
                    ? 'border-primary bg-primary/5'
                    : 'border-muted hover:border-muted-foreground/50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Cloud className="h-4 w-4" />
                  <span className="font-medium">AWS Cognito</span>
                </div>
                <p className="text-xs text-muted-foreground">Enterprise SSO via Cognito</p>
              </div>

              <div
                onClick={() => setAuthProvider('oidc')}
                className={`p-3 rounded-lg border-2 cursor-pointer transition-all ${
                  authProvider === 'oidc'
                    ? 'border-primary bg-primary/5'
                    : 'border-muted hover:border-muted-foreground/50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="h-4 w-4" />
                  <span className="font-medium">OIDC / Okta</span>
                </div>
                <p className="text-xs text-muted-foreground">OpenID Connect provider</p>
              </div>
            </div>
          </div>

          {authProvider === 'local' && (
            <div className="space-y-4 pt-4 border-t">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="user@example.com"
                />
              </div>
            </div>
          )}

          {authProvider === 'cognito' && (
            <div className="space-y-4 pt-4 border-t">
              <div className="flex items-start gap-2 p-3 bg-yellow-500/10 rounded-lg border border-yellow-500/20">
                <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium text-yellow-600">Cognito Configuration</p>
                  <p className="text-muted-foreground">
                    These settings should match your AWS Cognito User Pool configuration.
                  </p>
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="cognito-region">Region</Label>
                  <Select value={cognitoRegion} onValueChange={setCognitoRegion}>
                    <SelectTrigger id="cognito-region">
                      <SelectValue placeholder="Select a region" />
                    </SelectTrigger>
                    <SelectContent>
                      {AWS_REGIONS.map((r) => (
                        <SelectItem key={r} value={r}>
                          {r}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="cognito-client-id">Client ID</Label>
                  <Input
                    id="cognito-client-id"
                    value={cognitoClientId}
                    onChange={(e) => setCognitoClientId(e.target.value)}
                    placeholder="abc123..."
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="cognito-pool-id">User Pool ID</Label>
                <Input
                  id="cognito-pool-id"
                  value={cognitoUserPoolId}
                  onChange={(e) => setCognitoUserPoolId(e.target.value)}
                  placeholder="us-east-1_abc123"
                />
              </div>
            </div>
          )}

          {authProvider === 'oidc' && (
            <div className="space-y-4 pt-4 border-t">
              <div className="flex items-start gap-2 p-3 bg-yellow-500/10 rounded-lg border border-yellow-500/20">
                <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium text-yellow-600">OIDC Configuration</p>
                  <p className="text-muted-foreground">
                    Configure your OpenID Connect provider (Okta, Auth0, etc.)
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="oidc-issuer">Issuer URL</Label>
                <Input
                  id="oidc-issuer"
                  value={oidcIssuer}
                  onChange={(e) => setOidcIssuer(e.target.value)}
                  placeholder="https://your-tenant.okta.com"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="oidc-client-id">Client ID</Label>
                <Input
                  id="oidc-client-id"
                  value={oidcClientId}
                  onChange={(e) => setOidcClientId(e.target.value)}
                  placeholder="0oa..."
                />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Sync Settings */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <RefreshCw className="h-5 w-5 text-green-500" />
            <CardTitle>Sync Settings</CardTitle>
          </div>
          <CardDescription>Configure automatic synchronization</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Auto Sync</Label>
              <p className="text-sm text-muted-foreground">
                Automatically sync data in the background
              </p>
            </div>
            <Switch checked={autoSync} onCheckedChange={setAutoSync} />
          </div>

          {autoSync && (
            <div className="space-y-2">
              <Label>Sync Interval</Label>
              <Select
                value={syncInterval.toString()}
                onValueChange={(v) => setSyncInterval(parseInt(v))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="60">Every minute</SelectItem>
                  <SelectItem value="300">Every 5 minutes</SelectItem>
                  <SelectItem value="600">Every 10 minutes</SelectItem>
                  <SelectItem value="1800">Every 30 minutes</SelectItem>
                  <SelectItem value="3600">Every hour</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Actions */}
      <div className="flex items-center justify-end gap-2">
        {showCancel && (
          <Button variant="outline" onClick={onCancel} disabled={isSaving}>
            Cancel
          </Button>
        )}
        <Button onClick={handleSave} disabled={isSaving}>
          {isSaving ? 'Saving...' : submitLabel}
        </Button>
      </div>
    </div>
  );
}
