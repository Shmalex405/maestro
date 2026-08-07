'use client';

/**
 * Setup-credentials wizard, rendered inline inside the Add Cloud Account
 * dialog when the AssumeRole probe fails with "Unable to locate
 * credentials." Lets the user pick how Maestro should authenticate
 * before assuming the target role, walks them through whichever flow
 * they pick, and caches the resolved source credentials in the macOS
 * keyring (`aws_source` blob) so the next probe attempt — and all
 * future assessments — succeed.
 *
 * The three supported source-credential modes mirror the AWS auth
 * landscape on a typical Mac dev machine:
 *
 *  - **SSO** — by far the most common in 2026. Runs the AWS OIDC
 *    device-code flow against the user's SSO start URL, mints
 *    short-lived IAM creds, caches the access token + (account, role)
 *    pair so subsequent probes don't require re-signin until the
 *    token expires (typically 8h).
 *  - **Access keys** — long-lived IAM user keys (AKIA…). Cached
 *    verbatim in the keyring; the probe injects them as env vars.
 *  - **Profile** — a named entry from `~/.aws/credentials` /
 *    `~/.aws/config`. The probe passes `--profile <name>` through to
 *    the AWS CLI so any chained SSO/AssumeRole resolution in the
 *    profile is honored.
 *
 * On successful setup, `onCompleted` fires — the parent dialog calls
 * `handleVerifyConnection()` again, the probe finds the new
 * `aws_source` blob, and the user sees the green card.
 */

import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/tauri-api';
import type {
  AwsSourceCredentialsBlob,
  AwsSsoAccount,
  AwsSsoAccountRole,
  AwsSsoDeviceAuthSession,
} from '@/lib/tauri-api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2, KeyRound, FileKey2, Globe, Copy, ExternalLink } from 'lucide-react';
import { toast } from 'sonner';

export interface SetupCredentialsWizardProps {
  /**
   * Target AssumeRole ARN — used to auto-pick the same account as the
   * source account for the SSO flow. We assume by default the user
   * has SSO access to the same account they want to assess; if not,
   * the account picker step lets them choose differently.
   */
  targetRoleArn: string;
  /** Fires after the wizard writes `aws_source` to the keyring. The
   *  parent should re-run the credential probe at this point. */
  onCompleted: () => void;
  /** Fires when the user clicks the cancel button or backs out of the
   *  wizard mid-flow. Resets the parent's verify state to idle. */
  onCancel: () => void;
  /**
   * Optional override for where the resolved credential blob is stored.
   * Defaults to writing the single legacy `aws_source` keyring slot
   * (back-compat with the Add-Account probe flow). The Source Credentials
   * library passes a handler that appends the blob to the named
   * `aws_sources` collection instead.
   */
  persist?: (blob: AwsSourceCredentialsBlob) => Promise<void>;
}

type Method = 'sso' | 'access_keys' | 'profile';

type SsoSubStage =
  | { kind: 'collecting' } // entering start URL + region
  | { kind: 'starting' } // calling start_device_auth
  | { kind: 'awaiting'; session: AwsSsoDeviceAuthSession } // user code shown, polling
  | { kind: 'discovering'; accessToken: string; region: string } // auto-picking account+role
  | { kind: 'choosing_account'; accessToken: string; region: string; accounts: AwsSsoAccount[] }
  | {
      kind: 'choosing_role';
      accessToken: string;
      region: string;
      accountId: string;
      roles: AwsSsoAccountRole[];
    }
  | { kind: 'persisting' } // writing to keyring
  | { kind: 'error'; message: string };

export function SetupCredentialsWizard({
  targetRoleArn,
  onCompleted,
  onCancel,
  persist,
}: SetupCredentialsWizardProps) {
  // Where a resolved blob gets stored. Defaults to the legacy single
  // slot; the library overrides this to append a named entry.
  const persistBlob = (blob: AwsSourceCredentialsBlob): Promise<void> =>
    persist ? persist(blob) : api.config.scope.setAwsSourceCredentials(blob);
  const [method, setMethod] = useState<Method>('sso');

  // SSO inputs
  const [ssoStartUrl, setSsoStartUrl] = useState('');
  const [ssoRegion, setSsoRegion] = useState('us-east-1');
  const [ssoStage, setSsoStage] = useState<SsoSubStage>({ kind: 'collecting' });

  // Access keys inputs
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');

  // Profile input
  const [profileName, setProfileName] = useState('');

  // Tracks the active SSO poll loop so the unmount cleanup can stop it
  // — re-renders mid-poll would otherwise leave a zombie setInterval
  // making network calls to the token endpoint after the wizard closes.
  const ssoPollTimer = useRef<NodeJS.Timeout | null>(null);
  // Captured when the device-code flow authorizes — carries the refresh
  // token + registered client creds + real expiry through to persist, so
  // the backend can silently refresh later (auth-handler pattern).
  const ssoBundle = useRef<{
    refreshToken: string | null;
    clientId: string;
    clientSecret: string;
    expiresAt: number;
  } | null>(null);

  useEffect(() => {
    return () => {
      if (ssoPollTimer.current) clearInterval(ssoPollTimer.current);
    };
  }, []);

  // Pull the target account ID out of the role ARN so the SSO flow can
  // default to it. `arn:aws:iam::123456789012:role/Foo` → "123456789012".
  const targetAccountId = (() => {
    const parts = targetRoleArn.split(':');
    return parts.length >= 5 ? parts[4] : null;
  })();

  // -------------------------------------------------------------------
  // SSO flow
  // -------------------------------------------------------------------

  const startSsoFlow = async () => {
    if (!ssoStartUrl.trim()) {
      toast.error('AWS SSO start URL is required');
      return;
    }
    setSsoStage({ kind: 'starting' });
    try {
      const session = await api.config.scope.startAwsSsoDeviceAuth(
        ssoStartUrl.trim(),
        ssoRegion,
      );
      setSsoStage({ kind: 'awaiting', session });
      beginPollingForToken(session);
    } catch (e) {
      setSsoStage({
        kind: 'error',
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  const beginPollingForToken = (session: AwsSsoDeviceAuthSession) => {
    // Respect AWS's documented poll interval — shorter intervals get
    // SlowDown errors and don't materialize tokens any faster.
    const intervalMs = Math.max(1, session.interval) * 1000;
    if (ssoPollTimer.current) clearInterval(ssoPollTimer.current);
    ssoPollTimer.current = setInterval(async () => {
      try {
        const result = await api.config.scope.pollAwsSsoDeviceAuth(session);
        if (result.status === 'authorized') {
          if (ssoPollTimer.current) {
            clearInterval(ssoPollTimer.current);
            ssoPollTimer.current = null;
          }
          // Stash refresh material for persist (silent-refresh later).
          ssoBundle.current = {
            refreshToken: result.refresh_token,
            clientId: session.clientId,
            clientSecret: session.clientSecret,
            expiresAt: result.expires_at,
          };
          await discoverAccountAndRole(result.access_token, session.region);
        }
        // pending → keep polling (no state change needed)
      } catch (e) {
        if (ssoPollTimer.current) {
          clearInterval(ssoPollTimer.current);
          ssoPollTimer.current = null;
        }
        setSsoStage({
          kind: 'error',
          message: e instanceof Error ? e.message : String(e),
        });
      }
    }, intervalMs);
  };

  /**
   * After the user has approved in the browser and we have an access
   * token, discover which (account, role) pair to use as the AssumeRole
   * source. Auto-pick when:
   *  - there's exactly one account reachable, OR
   *  - the target Role ARN points at an account the SSO session can see
   *    (most common — user is auditing the same account they signed
   *    into).
   * Falls through to a picker when the heuristic can't pick uniquely.
   */
  const discoverAccountAndRole = async (accessToken: string, region: string) => {
    setSsoStage({ kind: 'discovering', accessToken, region });
    try {
      const accounts = await api.config.scope.listAwsSsoAccounts(accessToken, region);
      if (accounts.length === 0) {
        setSsoStage({
          kind: 'error',
          message:
            'No AWS accounts reachable from this SSO session. Check that your IAM Identity Center user has at least one account assigned.',
        });
        return;
      }

      // Prefer the account whose ID matches the target Role ARN.
      let chosenAccount: AwsSsoAccount | null = null;
      if (targetAccountId) {
        chosenAccount =
          accounts.find((a) => a.accountId === targetAccountId) ?? null;
      }
      if (!chosenAccount && accounts.length === 1) {
        chosenAccount = accounts[0];
      }
      if (!chosenAccount) {
        setSsoStage({
          kind: 'choosing_account',
          accessToken,
          region,
          accounts,
        });
        return;
      }
      await pickRoleForAccount(accessToken, region, chosenAccount.accountId);
    } catch (e) {
      setSsoStage({
        kind: 'error',
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  const pickRoleForAccount = async (
    accessToken: string,
    region: string,
    accountId: string,
  ) => {
    try {
      const roles = await api.config.scope.listAwsSsoAccountRoles(
        accessToken,
        region,
        accountId,
      );
      if (roles.length === 0) {
        setSsoStage({
          kind: 'error',
          message: `No SSO roles available in account ${accountId}.`,
        });
        return;
      }
      // Auto-pick when there's only one (most cases). Multi-role users
      // get a chooser — typically they want an Administrator-flavored
      // role since AssumeRole into a separate audit role requires the
      // source to have at least sts:AssumeRole, which Administrator
      // role gives, but ReadOnlyAccess might not (depending on org).
      if (roles.length === 1) {
        await persistSsoCreds(accessToken, region, accountId, roles[0].roleName);
        return;
      }
      setSsoStage({
        kind: 'choosing_role',
        accessToken,
        region,
        accountId,
        roles,
      });
    } catch (e) {
      setSsoStage({
        kind: 'error',
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  const persistSsoCreds = async (
    accessToken: string,
    region: string,
    accountId: string,
    roleName: string,
  ) => {
    setSsoStage({ kind: 'persisting' });
    try {
      // Prefer the real expiry from the authorized poll result; fall back
      // to a conservative 7h if (somehow) the bundle is missing.
      const bundle = ssoBundle.current;
      const expiresAt = bundle?.expiresAt ?? Math.floor(Date.now() / 1000) + 7 * 3600;
      const blob: AwsSourceCredentialsBlob = {
        kind: 'sso',
        sso: {
          start_url: ssoStartUrl.trim(),
          region,
          access_token: accessToken,
          expires_at: expiresAt,
          source_account_id: accountId,
          source_role_name: roleName,
          // Refresh material — enables silent renewal for the SSO session
          // window. Omitted if unavailable (older flow).
          refresh_token: bundle?.refreshToken ?? null,
          client_id: bundle?.clientId,
          client_secret: bundle?.clientSecret,
        },
      };
      await persistBlob(blob);
      toast.success(`Signed in via SSO (${accountId}/${roleName})`);
      onCompleted();
    } catch (e) {
      setSsoStage({
        kind: 'error',
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  // -------------------------------------------------------------------
  // Access keys + Profile flows (both are synchronous saves)
  // -------------------------------------------------------------------

  const saveAccessKeys = async () => {
    if (!accessKeyId.trim() || !secretAccessKey.trim()) {
      toast.error('Both Access Key ID and Secret Access Key are required');
      return;
    }
    try {
      const blob: AwsSourceCredentialsBlob = {
        kind: 'access_keys',
        access_keys: {
          access_key_id: accessKeyId.trim(),
          secret_access_key: secretAccessKey.trim(),
        },
      };
      await persistBlob(blob);
      toast.success('Access keys saved to keychain');
      onCompleted();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  const saveProfile = async () => {
    if (!profileName.trim()) {
      toast.error('Profile name is required');
      return;
    }
    try {
      const blob: AwsSourceCredentialsBlob = {
        kind: 'profile',
        profile: { name: profileName.trim() },
      };
      await persistBlob(blob);
      toast.success(`Saved profile reference: ${profileName.trim()}`);
      onCompleted();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  // -------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------

  const ssoActive =
    ssoStage.kind !== 'collecting' && ssoStage.kind !== 'error';

  return (
    <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 space-y-3 text-xs">
      <div>
        <div className="font-medium text-amber-300 text-sm">
          Source credentials needed
        </div>
        <p className="text-muted-foreground mt-0.5">
          Assume Role needs existing AWS credentials to authenticate from
          {targetRoleArn ? (
            <>
              {' '}before it can assume <code className="font-mono">{targetRoleArn}</code>.
            </>
          ) : (
            ' before it can assume any target role.'
          )}{' '}
          Pick how Maestro should sign you in — we&apos;ll cache the result so
          you only do this once.
        </p>
      </div>

      {/* Method picker — only shown when SSO isn't mid-flow */}
      {!ssoActive && (
        <div className="grid grid-cols-3 gap-2">
          <MethodTile
            active={method === 'sso'}
            icon={Globe}
            label="AWS SSO"
            description="Sign in via your IAM Identity Center start URL."
            onClick={() => setMethod('sso')}
          />
          <MethodTile
            active={method === 'access_keys'}
            icon={KeyRound}
            label="Access keys"
            description="Paste a long-term IAM user access key + secret."
            onClick={() => setMethod('access_keys')}
          />
          <MethodTile
            active={method === 'profile'}
            icon={FileKey2}
            label="CLI profile"
            description="Reference a profile from your ~/.aws/config."
            onClick={() => setMethod('profile')}
          />
        </div>
      )}

      {method === 'sso' && (
        <SsoFlowSection
          ssoStartUrl={ssoStartUrl}
          ssoRegion={ssoRegion}
          ssoStage={ssoStage}
          onChangeStartUrl={setSsoStartUrl}
          onChangeRegion={setSsoRegion}
          onStart={startSsoFlow}
          onPickAccount={(accountId) => {
            if (ssoStage.kind === 'choosing_account') {
              pickRoleForAccount(ssoStage.accessToken, ssoStage.region, accountId);
            }
          }}
          onPickRole={(roleName) => {
            if (ssoStage.kind === 'choosing_role') {
              persistSsoCreds(
                ssoStage.accessToken,
                ssoStage.region,
                ssoStage.accountId,
                roleName,
              );
            }
          }}
          onReset={() => setSsoStage({ kind: 'collecting' })}
        />
      )}

      {method === 'access_keys' && (
        <div className="space-y-2">
          <div className="space-y-1">
            <Label className="text-xs">Access Key ID</Label>
            <Input
              value={accessKeyId}
              onChange={(e) => setAccessKeyId(e.target.value)}
              placeholder="AKIAIOSFODNN7EXAMPLE"
              className="font-mono"
              autoComplete="off"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Secret Access Key</Label>
            <Input
              type="password"
              value={secretAccessKey}
              onChange={(e) => setSecretAccessKey(e.target.value)}
              placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              className="font-mono"
              autoComplete="off"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" size="sm" onClick={onCancel}>
              Cancel
            </Button>
            <Button size="sm" onClick={saveAccessKeys}>
              Save &amp; verify
            </Button>
          </div>
        </div>
      )}

      {method === 'profile' && (
        <div className="space-y-2">
          <div className="space-y-1">
            <Label className="text-xs">Profile name</Label>
            <Input
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
              placeholder="whiteout-us"
              className="font-mono"
            />
            <p className="text-[10px] text-muted-foreground">
              Must match an entry in <code>~/.aws/credentials</code> or
              <code> ~/.aws/config</code>. The probe will pass
              <code> --profile &lt;name&gt;</code> to the AWS CLI inside the
              container, so any chained SSO/AssumeRole the profile prescribes
              is honored.
            </p>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" size="sm" onClick={onCancel}>
              Cancel
            </Button>
            <Button size="sm" onClick={saveProfile}>
              Save &amp; verify
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// =============================================================================
// Sub-components
// =============================================================================

function MethodTile({
  active,
  icon: Icon,
  label,
  description,
  onClick,
}: {
  active: boolean;
  icon: typeof Globe;
  label: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      onClick={onClick}
      className={`text-left rounded border p-2 transition-colors ${
        active
          ? 'border-primary bg-primary/5'
          : 'border-border hover:border-primary/40 hover:bg-muted/50'
      }`}
    >
      <div className="flex items-center gap-1.5">
        <Icon className={`h-3.5 w-3.5 ${active ? 'text-primary' : 'text-muted-foreground'}`} />
        <span className="font-medium text-xs">{label}</span>
      </div>
      <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">
        {description}
      </p>
    </button>
  );
}

function SsoFlowSection({
  ssoStartUrl,
  ssoRegion,
  ssoStage,
  onChangeStartUrl,
  onChangeRegion,
  onStart,
  onPickAccount,
  onPickRole,
  onReset,
}: {
  ssoStartUrl: string;
  ssoRegion: string;
  ssoStage: SsoSubStage;
  onChangeStartUrl: (v: string) => void;
  onChangeRegion: (v: string) => void;
  onStart: () => void;
  onPickAccount: (id: string) => void;
  onPickRole: (name: string) => void;
  onReset: () => void;
}) {
  if (ssoStage.kind === 'collecting' || ssoStage.kind === 'error') {
    return (
      <div className="space-y-2">
        <div className="space-y-1">
          <Label className="text-xs">SSO Start URL</Label>
          <Input
            value={ssoStartUrl}
            onChange={(e) => onChangeStartUrl(e.target.value)}
            placeholder="https://<org>.awsapps.com/start"
            className="font-mono"
          />
          <p className="text-[10px] text-muted-foreground">
            Find this in your AWS IAM Identity Center portal — usually the URL you bookmark to log in.
          </p>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">SSO Region</Label>
          <Select value={ssoRegion} onValueChange={onChangeRegion}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="us-east-1">us-east-1 (N. Virginia)</SelectItem>
              <SelectItem value="us-east-2">us-east-2 (Ohio)</SelectItem>
              <SelectItem value="us-west-2">us-west-2 (Oregon)</SelectItem>
              <SelectItem value="eu-central-1">eu-central-1 (Frankfurt)</SelectItem>
              <SelectItem value="eu-west-1">eu-west-1 (Ireland)</SelectItem>
              <SelectItem value="ap-southeast-2">ap-southeast-2 (Sydney)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {ssoStage.kind === 'error' && (
          <div className="rounded border border-destructive/40 bg-destructive/10 p-2 text-destructive">
            {ssoStage.message}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <Button size="sm" onClick={onStart}>
            <Globe className="h-3 w-3 mr-1.5" />
            Sign in with AWS
          </Button>
        </div>
      </div>
    );
  }

  if (ssoStage.kind === 'starting') {
    return (
      <div className="flex items-center gap-2 text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Starting device-code flow…
      </div>
    );
  }

  if (ssoStage.kind === 'awaiting') {
    return (
      <div className="space-y-3">
        <div className="rounded border border-blue-500/30 bg-blue-500/5 p-3 space-y-2">
          <div className="font-medium text-blue-300">Verify in your browser</div>
          <ol className="text-muted-foreground space-y-1 list-decimal list-inside">
            <li>
              Open{' '}
              <a
                href={ssoStage.session.verificationUriComplete}
                target="_blank"
                rel="noreferrer"
                className="text-primary underline inline-flex items-center gap-0.5"
              >
                {ssoStage.session.verificationUri}
                <ExternalLink className="h-2.5 w-2.5" />
              </a>{' '}
              in a browser.
            </li>
            <li>
              Confirm the code on screen matches{' '}
              <code className="font-mono text-foreground bg-muted/60 px-1 rounded">
                {ssoStage.session.userCode}
              </code>{' '}
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(ssoStage.session.userCode);
                  toast.success('Code copied');
                }}
                className="inline-flex items-center text-primary hover:underline"
              >
                <Copy className="h-2.5 w-2.5 ml-0.5" />
              </button>
            </li>
            <li>Sign in + approve.</li>
          </ol>
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Waiting for approval…
          </div>
        </div>
        <div className="flex justify-end">
          <Button variant="ghost" size="sm" onClick={onReset}>
            Cancel sign-in
          </Button>
        </div>
      </div>
    );
  }

  if (ssoStage.kind === 'discovering' || ssoStage.kind === 'persisting') {
    return (
      <div className="flex items-center gap-2 text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        {ssoStage.kind === 'discovering'
          ? 'Discovering accounts + roles…'
          : 'Saving credentials…'}
      </div>
    );
  }

  if (ssoStage.kind === 'choosing_account') {
    return (
      <div className="space-y-2">
        <p className="text-muted-foreground">
          Your SSO session can reach multiple accounts. Pick the one Maestro should sign in as before assuming the target role.
        </p>
        <div className="space-y-1 max-h-48 overflow-y-auto">
          {ssoStage.accounts.map((a) => (
            <button
              key={a.accountId}
              type="button"
              onClick={() => onPickAccount(a.accountId)}
              className="w-full text-left rounded border border-border hover:border-primary/40 hover:bg-muted/50 px-2 py-1.5"
            >
              <div className="font-mono">{a.accountId}</div>
              {a.accountName && (
                <div className="text-[10px] text-muted-foreground">
                  {a.accountName}
                </div>
              )}
            </button>
          ))}
        </div>
      </div>
    );
  }

  if (ssoStage.kind === 'choosing_role') {
    return (
      <div className="space-y-2">
        <p className="text-muted-foreground">
          Pick which permission-set role Maestro should use as the source identity for AssumeRole.
        </p>
        <div className="space-y-1 max-h-48 overflow-y-auto">
          {ssoStage.roles.map((r) => (
            <button
              key={r.roleName}
              type="button"
              onClick={() => onPickRole(r.roleName)}
              className="w-full text-left rounded border border-border hover:border-primary/40 hover:bg-muted/50 px-2 py-1.5 font-mono"
            >
              {r.roleName}
            </button>
          ))}
        </div>
      </div>
    );
  }

  return null;
}
