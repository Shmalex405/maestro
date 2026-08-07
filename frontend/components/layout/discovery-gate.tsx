'use client';

import { useState, type FormEvent } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Mail, Loader2, AlertCircle } from 'lucide-react';
import { discover, saveBootstrap, PLATFORM_URL } from '@/lib/desktop-bootstrap';
import { api } from '@/lib/tauri-api';

interface DiscoveryGateProps {
  onSuccess: () => void;
}

// First-launch onboarding. Takes an email, asks the Groovy platform which
// customer the user belongs to, saves the resulting backend URL + Cognito
// settings, and hands off to the normal auth gate.

export function DiscoveryGate({ onSuccess }: DiscoveryGateProps) {
  const [email, setEmail] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setPending(true);
    setError(null);

    try {
      const normalized = email.trim().toLowerCase();
      if (!normalized.includes('@')) {
        throw new Error('Enter a valid email address.');
      }

      const result = await discover(normalized);

      if (!result.recognized) {
        throw new Error(
          "We don't recognize this email. Contact your Maestro administrator to confirm your account has been set up."
        );
      }

      // Persist Cognito config for the login gate.
      saveBootstrap({
        orgId: result.orgId,
        customerName: result.customerName,
        backendUrl: result.backendUrl,
        cognitoRegion: result.cognitoRegion,
        cognitoUserPoolId: result.cognitoUserPoolId,
        cognitoClientId: result.cognitoClientId,
        cognitoDomain: result.cognitoDomain,
        discoveredAt: new Date().toISOString(),
        email: normalized,
      });

      // Persist cloud sync config so the desktop immediately syncs against
      // the right backend after login.
      try {
        await api.config.cloud.update({
          enabled: true,
          api_url: result.backendUrl,
          auth_provider: 'cognito',
          email: normalized,
          cognito_region: result.cognitoRegion,
          cognito_user_pool_id: result.cognitoUserPoolId,
          cognito_client_id: result.cognitoClientId,
          auto_sync: true,
          sync_interval_seconds: 60,
        } as Parameters<typeof api.config.cloud.update>[0]);
      } catch (err) {
        // Non-fatal — user can re-save from /config/cloud if needed.
        console.warn('[discovery] failed to persist cloud config:', err);
      }

      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-8rem)]">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-xl">Welcome to Maestro</CardTitle>
          <CardDescription>
            Enter your work email so we can connect this device to your organization's backend.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Work email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  placeholder="you@yourcompany.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={pending}
                  required
                  autoFocus
                  autoComplete="email"
                  className="pl-10"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 text-sm text-destructive">
                <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <Button type="submit" className="w-full" disabled={pending || !email}>
              {pending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Looking up your organization…
                </>
              ) : (
                'Continue'
              )}
            </Button>

            <p className="text-xs text-muted-foreground text-center pt-2">
              Maestro will contact <code className="rounded bg-muted px-1 py-0.5">{PLATFORM_URL}</code> to
              find your backend. Nothing is logged in.
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
