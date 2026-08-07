'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type { CredentialsConfig, CredentialApp, AuthType, ScopeConfig } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { toast } from 'sonner';
import {
  ArrowLeft,
  Key,
  Shield,
  Globe,
  Lock,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  UserPlus,
  Edit,
} from 'lucide-react';

const authTypeIcons: Record<string, React.ElementType> = {
  session: Globe,
  basic: Lock,
  bearer: Shield,
  api_key: Key,
  oauth2: Shield,
  none: Lock,
  otp_email: Key,
};

const AUTH_TYPES: { value: AuthType; label: string; description: string }[] = [
  { value: 'none', label: 'None', description: 'No authentication required' },
  { value: 'basic', label: 'Basic Auth', description: 'HTTP Basic Authentication' },
  { value: 'bearer', label: 'Bearer Token', description: 'Authorization: Bearer token' },
  { value: 'api_key', label: 'API Key', description: 'Custom header with API key' },
  { value: 'session', label: 'Session/Cookie', description: 'Login form with session' },
  { value: 'oauth2', label: 'OAuth 2.0', description: 'OAuth 2.0 client credentials' },
  { value: 'otp_email', label: 'OTP (Email)', description: 'One-time password via email' },
];

// Intended privilege level of the credential's identity. The assessment uses this
// to tell expected-for-role behavior apart from a real access-control flaw — an
// admin creating users is expected and downgraded; a standard user creating users
// is a Critical finding. When unsure, pick the LOWER role — safer to over-report
// than to hide a finding. Unspecified ⇒ no downgrade (fail-safe).
const ROLE_TYPES: { value: string; label: string; description: string }[] = [
  { value: '', label: 'Unspecified', description: 'No role context — findings are not downgraded' },
  { value: 'admin', label: 'Administrator', description: 'Full control over the app/tenant (user, role, config CRUD)' },
  { value: 'privileged', label: 'Privileged', description: 'Elevated but scoped (org-admin, manager, moderator)' },
  { value: 'standard', label: 'Standard User', description: 'Normal end-user, no administrative capability' },
  { value: 'readonly', label: 'Read-only / Auditor', description: 'Authenticated but no writes intended' },
];

interface AppFormData {
  name: string;
  environment: string;
  base_url: string;
  auth_type: AuthType;
  role: string;
  username: string;
  password: string;
  token: string;
  header_name: string;
  login_url: string;
  client_id: string;
  client_secret: string;
  token_url: string;
}

const defaultAppForm: AppFormData = {
  name: '',
  environment: 'staging',
  base_url: '',
  auth_type: 'none',
  role: '',
  username: '',
  password: '',
  token: '',
  header_name: 'X-API-Key',
  login_url: '',
  client_id: '',
  client_secret: '',
  token_url: '',
};

interface TestAccountFormData {
  role: string;
  username: string;
  password: string;
}

const defaultTestAccountForm: TestAccountFormData = {
  role: '',
  username: '',
  password: '',
};

export default function CredentialsPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  // Dialog states
  const [appDialogOpen, setAppDialogOpen] = useState(false);
  const [accountDialogOpen, setAccountDialogOpen] = useState(false);
  const [editingApp, setEditingApp] = useState<string | null>(null);
  const [editingAccount, setEditingAccount] = useState<string | null>(null);

  // Form states
  const [appForm, setAppForm] = useState<AppFormData>(defaultAppForm);
  const [accountForm, setAccountForm] = useState<TestAccountFormData>(defaultTestAccountForm);

  // Password visibility
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});

  const { data: credentials, isLoading } = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.config.credentials.get(),
  });

  const { data: scope } = useQuery({
    queryKey: ['scope'],
    queryFn: () => api.config.scope.get(),
  });

  // Build list of scope targets for the dropdown
  const scopeTargets = [
    ...(scope?.domains?.map((d) => ({
      value: d.pattern.startsWith('http') ? d.pattern : `https://${d.pattern}`,
      label: d.pattern,
      environment: d.environment,
      type: 'domain' as const,
    })) || []),
    ...(scope?.networks?.map((n) => ({
      value: n.cidr,
      label: `${n.cidr}${n.notes ? ` (${n.notes})` : ''}`,
      environment: n.environment,
      type: 'network' as const,
    })) || []),
  ];

  const handleScopeSelection = (value: string) => {
    const selected = scopeTargets.find((t) => t.value === value);
    if (selected) {
      // Auto-generate app name from domain/network
      const autoName = selected.type === 'domain'
        ? selected.label.replace(/^\*\./, '').split('.')[0]
        : selected.label.split('/')[0].replace(/\./g, '-');

      setAppForm({
        ...appForm,
        base_url: selected.value,
        environment: selected.environment,
        name: appForm.name || autoName, // Only auto-fill if empty
      });
    }
  };

  const saveMutation = useMutation({
    mutationFn: (config: CredentialsConfig) => api.config.credentials.update(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      toast.success('Credentials saved');
    },
    onError: () => {
      toast.error('Failed to save credentials');
    },
  });

  const handleAddApp = () => {
    if (!appForm.name || !appForm.base_url) {
      toast.error('Name and Target are required');
      return;
    }

    const newApp: CredentialApp = {
      name: appForm.name,
      environment: appForm.environment,
      base_url: appForm.base_url,
      auth_type: appForm.auth_type,
    };
    if (appForm.role) newApp.role = appForm.role;

    // Add auth-specific fields
    switch (appForm.auth_type) {
      case 'basic':
        newApp.username = appForm.username;
        newApp.password = appForm.password;
        break;
      case 'bearer':
        newApp.token = appForm.token;
        break;
      case 'api_key':
        newApp.token = appForm.token;
        newApp.header_name = appForm.header_name;
        break;
      case 'session':
        newApp.login_url = appForm.login_url;
        newApp.username = appForm.username;
        newApp.password = appForm.password;
        break;
      case 'oauth2':
        newApp.client_id = appForm.client_id;
        newApp.client_secret = appForm.client_secret;
        newApp.token_url = appForm.token_url;
        break;
      case 'otp_email':
        newApp.login_url = appForm.login_url;
        newApp.username = appForm.username;
        break;
    }

    const updated: CredentialsConfig = {
      ...credentials,
      applications: {
        ...credentials?.applications,
        [appForm.name]: newApp,
      },
      test_accounts: credentials?.test_accounts || {},
    };

    // If editing, remove old key if name changed
    if (editingApp && editingApp !== appForm.name) {
      delete updated.applications[editingApp];
    }

    saveMutation.mutate(updated);
    setAppDialogOpen(false);
    setAppForm(defaultAppForm);
    setEditingApp(null);
  };

  const handleDeleteApp = (name: string) => {
    if (!credentials) return;

    const updated: CredentialsConfig = {
      ...credentials,
      applications: { ...credentials.applications },
    };
    delete updated.applications[name];

    saveMutation.mutate(updated);
  };

  const handleEditApp = (name: string) => {
    const app = credentials?.applications[name];
    if (!app) return;

    setAppForm({
      name,
      environment: app.environment || 'staging',
      base_url: app.base_url || '',
      auth_type: app.auth_type || 'none',
      role: app.role || '',
      username: app.username || '',
      password: app.password || '',
      token: app.token || '',
      header_name: app.header_name || 'X-API-Key',
      login_url: app.login_url || '',
      client_id: app.client_id || '',
      client_secret: app.client_secret || '',
      token_url: app.token_url || '',
    });
    setEditingApp(name);
    setAppDialogOpen(true);
  };

  const handleAddAccount = () => {
    if (!accountForm.role || !accountForm.username) {
      toast.error('Role and Username are required');
      return;
    }

    const updated: CredentialsConfig = {
      ...credentials,
      applications: credentials?.applications || {},
      test_accounts: {
        ...credentials?.test_accounts,
        [accountForm.role]: {
          username: accountForm.username,
          password: accountForm.password,
          role: accountForm.role,
        },
      },
    };

    // If editing, remove old key if role changed
    if (editingAccount && editingAccount !== accountForm.role) {
      delete updated.test_accounts![editingAccount];
    }

    saveMutation.mutate(updated);
    setAccountDialogOpen(false);
    setAccountForm(defaultTestAccountForm);
    setEditingAccount(null);
  };

  const handleDeleteAccount = (role: string) => {
    if (!credentials?.test_accounts) return;

    const updated: CredentialsConfig = {
      ...credentials,
      test_accounts: { ...credentials.test_accounts },
    };
    delete updated.test_accounts![role];

    saveMutation.mutate(updated);
  };

  const handleEditAccount = (role: string) => {
    const account = credentials?.test_accounts?.[role];
    if (!account) return;

    setAccountForm({
      role,
      username: account.username || '',
      password: account.password || '',
    });
    setEditingAccount(role);
    setAccountDialogOpen(true);
  };

  const togglePasswordVisibility = (key: string) => {
    setShowPasswords((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push('/config')}
          className="mb-2 -ml-2"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Configuration
        </Button>
        <h1 className="text-3xl font-bold">Credentials</h1>
        <p className="text-muted-foreground">
          Manage application authentication for authenticated testing
        </p>
      </div>

      {/* Applications */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Applications</CardTitle>
            <CardDescription>Configured application credentials for authenticated testing</CardDescription>
          </div>
          <Dialog open={appDialogOpen} onOpenChange={(open) => {
            setAppDialogOpen(open);
            if (!open) {
              setAppForm(defaultAppForm);
              setEditingApp(null);
            }
          }}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Add Application
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>{editingApp ? 'Edit Application' : 'Add Application'}</DialogTitle>
                <DialogDescription>
                  Configure authentication for an application
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4 max-h-[60vh] overflow-y-auto">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Application Name</Label>
                    <Input
                      placeholder="Auto-generated from target"
                      value={appForm.name}
                      onChange={(e) => setAppForm({ ...appForm, name: e.target.value })}
                      disabled={!!editingApp}
                    />
                    <p className="text-xs text-muted-foreground">Auto-filled when you select a target</p>
                  </div>
                  <div className="space-y-2">
                    <Label>Environment</Label>
                    <Input
                      value={appForm.environment || 'Select a target first'}
                      disabled
                      className="bg-muted"
                    />
                    <p className="text-xs text-muted-foreground">Set by the scope target</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Target (from Scope)</Label>
                  {scopeTargets.length > 0 ? (
                    <Select
                      value={appForm.base_url}
                      onValueChange={handleScopeSelection}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select a target from your scope" />
                      </SelectTrigger>
                      <SelectContent>
                        {scopeTargets.map((target) => (
                          <SelectItem key={target.value} value={target.value}>
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="text-xs">
                                {target.type === 'domain' ? 'Domain' : 'Network'}
                              </Badge>
                              <span>{target.label}</span>
                              <span className="text-muted-foreground text-xs">({target.environment})</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <div className="text-sm text-muted-foreground p-3 border rounded-md bg-muted/50">
                      No targets in scope. <a href="/config/scope" className="text-primary underline">Add domains or networks</a> to your scope first.
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <Label>Authentication Type</Label>
                  <Select
                    value={appForm.auth_type}
                    onValueChange={(v) => setAppForm({ ...appForm, auth_type: v as AuthType })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {AUTH_TYPES.map((type) => (
                        <SelectItem key={type.value} value={type.value}>
                          <div>
                            <span className="font-medium">{type.label}</span>
                            <span className="text-muted-foreground ml-2 text-xs">{type.description}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {appForm.auth_type !== 'none' && (
                  <div className="space-y-2">
                    <Label>Account Privilege</Label>
                    <Select
                      value={appForm.role || 'unspecified'}
                      onValueChange={(v) => setAppForm({ ...appForm, role: v === 'unspecified' ? '' : v })}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Unspecified" />
                      </SelectTrigger>
                      <SelectContent>
                        {ROLE_TYPES.map((r) => (
                          <SelectItem key={r.value || 'unspecified'} value={r.value || 'unspecified'}>
                            <div>
                              <span className="font-medium">{r.label}</span>
                              <span className="text-muted-foreground ml-2 text-xs">{r.description}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-muted-foreground text-xs">
                      The privilege this account is <em>intended</em> to have. Lets the assessment tell expected
                      admin behavior apart from a real access-control flaw. When unsure, pick the lower role.
                    </p>
                  </div>
                )}

                {/* Auth-specific fields */}
                {appForm.auth_type === 'basic' && (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Username</Label>
                      <Input
                        value={appForm.username}
                        onChange={(e) => setAppForm({ ...appForm, username: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Password</Label>
                      <div className="relative">
                        <Input
                          type={showPasswords['app-password'] ? 'text' : 'password'}
                          value={appForm.password}
                          onChange={(e) => setAppForm({ ...appForm, password: e.target.value })}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="absolute right-0 top-0 h-full px-3"
                          onClick={() => togglePasswordVisibility('app-password')}
                        >
                          {showPasswords['app-password'] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                      </div>
                    </div>
                  </div>
                )}

                {appForm.auth_type === 'bearer' && (
                  <div className="space-y-2">
                    <Label>Bearer Token</Label>
                    <div className="relative">
                      <Input
                        type={showPasswords['bearer'] ? 'text' : 'password'}
                        placeholder="your-bearer-token"
                        value={appForm.token}
                        onChange={(e) => setAppForm({ ...appForm, token: e.target.value })}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0 h-full px-3"
                        onClick={() => togglePasswordVisibility('bearer')}
                      >
                        {showPasswords['bearer'] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                )}

                {appForm.auth_type === 'api_key' && (
                  <>
                    <div className="space-y-2">
                      <Label>Header Name</Label>
                      <Input
                        placeholder="X-API-Key"
                        value={appForm.header_name}
                        onChange={(e) => setAppForm({ ...appForm, header_name: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>API Key</Label>
                      <div className="relative">
                        <Input
                          type={showPasswords['api-key'] ? 'text' : 'password'}
                          value={appForm.token}
                          onChange={(e) => setAppForm({ ...appForm, token: e.target.value })}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="absolute right-0 top-0 h-full px-3"
                          onClick={() => togglePasswordVisibility('api-key')}
                        >
                          {showPasswords['api-key'] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                      </div>
                    </div>
                  </>
                )}

                {(appForm.auth_type === 'session' || appForm.auth_type === 'otp_email') && (
                  <>
                    <div className="space-y-2">
                      <Label>Login URL</Label>
                      <Input
                        placeholder="https://example.com/login"
                        value={appForm.login_url}
                        onChange={(e) => setAppForm({ ...appForm, login_url: e.target.value })}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Username / Email</Label>
                        <Input
                          value={appForm.username}
                          onChange={(e) => setAppForm({ ...appForm, username: e.target.value })}
                        />
                      </div>
                      {appForm.auth_type === 'session' && (
                        <div className="space-y-2">
                          <Label>Password</Label>
                          <div className="relative">
                            <Input
                              type={showPasswords['session-password'] ? 'text' : 'password'}
                              value={appForm.password}
                              onChange={(e) => setAppForm({ ...appForm, password: e.target.value })}
                            />
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              className="absolute right-0 top-0 h-full px-3"
                              onClick={() => togglePasswordVisibility('session-password')}
                            >
                              {showPasswords['session-password'] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                )}

                {appForm.auth_type === 'oauth2' && (
                  <>
                    <div className="space-y-2">
                      <Label>Token URL</Label>
                      <Input
                        placeholder="https://example.com/oauth/token"
                        value={appForm.token_url}
                        onChange={(e) => setAppForm({ ...appForm, token_url: e.target.value })}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Client ID</Label>
                        <Input
                          value={appForm.client_id}
                          onChange={(e) => setAppForm({ ...appForm, client_id: e.target.value })}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Client Secret</Label>
                        <div className="relative">
                          <Input
                            type={showPasswords['client-secret'] ? 'text' : 'password'}
                            value={appForm.client_secret}
                            onChange={(e) => setAppForm({ ...appForm, client_secret: e.target.value })}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="absolute right-0 top-0 h-full px-3"
                            onClick={() => togglePasswordVisibility('client-secret')}
                          >
                            {showPasswords['client-secret'] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </Button>
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setAppDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleAddApp} disabled={!appForm.name || !appForm.base_url || scopeTargets.length === 0}>
                  {editingApp ? 'Save Changes' : 'Add Application'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Application</TableHead>
                <TableHead>Environment</TableHead>
                <TableHead>Auth Type</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Base URL</TableHead>
                <TableHead className="w-[100px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {credentials?.applications && Object.keys(credentials.applications).length > 0 ? (
                Object.entries(credentials.applications).map(([name, app]) => {
                  const Icon = authTypeIcons[app.auth_type] || Key;
                  return (
                    <TableRow key={name}>
                      <TableCell className="font-medium">{name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{app.environment}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Icon className="h-4 w-4 text-muted-foreground" />
                          {app.auth_type}
                        </div>
                      </TableCell>
                      <TableCell>
                        {app.role ? (
                          <Badge variant="secondary">
                            {ROLE_TYPES.find((r) => r.value === app.role)?.label || app.role}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground text-sm">—</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-sm text-muted-foreground">
                        {app.base_url}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleEditApp(name)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDeleteApp(name)}
                            className="text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    No applications configured. Click &quot;Add Application&quot; to get started.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Test Accounts */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Test Accounts</CardTitle>
            <CardDescription>User accounts for authorization boundary testing</CardDescription>
          </div>
          <Dialog open={accountDialogOpen} onOpenChange={(open) => {
            setAccountDialogOpen(open);
            if (!open) {
              setAccountForm(defaultTestAccountForm);
              setEditingAccount(null);
            }
          }}>
            <DialogTrigger asChild>
              <Button>
                <UserPlus className="mr-2 h-4 w-4" />
                Add Test Account
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{editingAccount ? 'Edit Test Account' : 'Add Test Account'}</DialogTitle>
                <DialogDescription>
                  Add a test account for authorization testing
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label>Role</Label>
                  <Input
                    placeholder="admin, user, viewer, etc."
                    value={accountForm.role}
                    onChange={(e) => setAccountForm({ ...accountForm, role: e.target.value })}
                    disabled={!!editingAccount}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Username / Email</Label>
                  <Input
                    placeholder="testuser@example.com"
                    value={accountForm.username}
                    onChange={(e) => setAccountForm({ ...accountForm, username: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Password</Label>
                  <div className="relative">
                    <Input
                      type={showPasswords['account-password'] ? 'text' : 'password'}
                      value={accountForm.password}
                      onChange={(e) => setAccountForm({ ...accountForm, password: e.target.value })}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => togglePasswordVisibility('account-password')}
                    >
                      {showPasswords['account-password'] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setAccountDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleAddAccount} disabled={!accountForm.role || !accountForm.username}>
                  {editingAccount ? 'Save Changes' : 'Add Account'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Role</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Password</TableHead>
                <TableHead className="w-[100px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {credentials?.test_accounts && Object.keys(credentials.test_accounts).length > 0 ? (
                Object.entries(credentials.test_accounts).map(([role, account]) => (
                  <TableRow key={role}>
                    <TableCell>
                      <Badge variant="secondary">{role}</Badge>
                    </TableCell>
                    <TableCell className="font-mono">{account.username}</TableCell>
                    <TableCell>
                      <span className="text-muted-foreground">
                        {account.password ? '••••••••' : '-'}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleEditAccount(role)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleDeleteAccount(role)}
                          className="text-destructive"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                    No test accounts configured. Click &quot;Add Test Account&quot; to get started.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
