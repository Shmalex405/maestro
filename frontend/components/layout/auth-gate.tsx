'use client';

import { useState, type FormEvent } from 'react';
import Image from 'next/image';
import {
  signIn,
  completeNewPassword,
  forgotPassword,
  confirmPasswordReset,
  getUserFromToken,
  isBrowserOAuthConfigured,
  type SignInResult,
} from '@/lib/cognito-auth';
import {
  startBrowserLogin,
  cancelBrowserLogin,
  reopenAuthorizeUrl,
} from '@/lib/oauth-pkce';
import type { CognitoUser, CognitoUserSession } from 'amazon-cognito-identity-js';
import { useAuthStore } from '@/lib/stores/auth-store';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Lock, Mail, Loader2, KeyRound, ArrowLeft, ShieldCheck, Check, X, Eye, EyeOff, Globe, ExternalLink } from 'lucide-react';

interface AuthGateProps {
  onSuccess: () => void;
}

function mapCognitoError(err: unknown): string {
  if (err instanceof Error || (err && typeof err === 'object' && 'code' in err)) {
    const error = err as Error & { code?: string };
    const code = error.code || '';
    const message = error.message || '';

    if (code === 'NotAuthorizedException') {
      if (message.toLowerCase().includes('disabled')) {
        return 'Your account has been disabled. Contact your administrator.';
      }
      return 'Incorrect email or password.';
    }
    if (code === 'UserNotConfirmedException') {
      return 'Please confirm your email first.';
    }
    if (code === 'UserNotFoundException') {
      return 'Incorrect email or password.';
    }
    if (message === 'MFA_REQUIRED') {
      return 'MFA is not yet supported in the desktop app.';
    }
    if (code === 'InvalidPasswordException') {
      return message.replace('Password did not conform with policy: ', '');
    }
    if (code === 'CodeMismatchException') {
      return 'Incorrect verification code.';
    }
    if (code === 'ExpiredCodeException') {
      return 'This code has expired. Request a new one.';
    }
    if (code === 'LimitExceededException') {
      return 'Too many attempts. Wait a few minutes and try again.';
    }
    if (code === 'NetworkError' || message.includes('NetworkError') || message.includes('fetch')) {
      return 'Unable to connect. Check your internet connection.';
    }
  }
  return 'Unable to connect. Check your internet connection.';
}

// Shared sink for both login paths — populate the store identically regardless
// of how the tokens were obtained (SRP or browser OAuth).
function completeAuthWithTokens(
  user: ReturnType<typeof getUserFromToken>,
  tokens: { accessToken: string; idToken: string; refreshToken: string; expiresIn: number },
  onSuccess: () => void,
  rememberMe: boolean,
) {
  useAuthStore.getState().setAuth(user, tokens, rememberMe);
  onSuccess();
}

function completeAuth(
  session: CognitoUserSession,
  onSuccess: () => void,
  rememberMe: boolean,
) {
  const idJwt = session.getIdToken().getJwtToken();
  completeAuthWithTokens(
    getUserFromToken(idJwt),
    {
      accessToken: session.getAccessToken().getJwtToken(),
      idToken: idJwt,
      refreshToken: session.getRefreshToken().getToken(),
      expiresIn: 86400,
    },
    onSuccess,
    rememberMe,
  );
}

// Single source of truth for the Cognito password policy, mirrored as live UI
// hints below. `test` runs against the candidate password as the user types.
const PASSWORD_RULES: { label: string; test: (pw: string) => boolean }[] = [
  { label: 'At least 12 characters', test: (pw) => pw.length >= 12 },
  { label: 'An uppercase letter', test: (pw) => /[A-Z]/.test(pw) },
  { label: 'A lowercase letter', test: (pw) => /[a-z]/.test(pw) },
  { label: 'A number', test: (pw) => /[0-9]/.test(pw) },
  { label: 'A symbol', test: (pw) => /[^A-Za-z0-9]/.test(pw) },
];

function RequirementRow({ met, label }: { met: boolean; label: string }) {
  return (
    <li
      className={`flex items-center gap-2 ${
        met ? 'text-emerald-600 dark:text-emerald-500' : 'text-muted-foreground'
      }`}
    >
      {met ? (
        <Check className="h-3.5 w-3.5 shrink-0" />
      ) : (
        <X className="h-3.5 w-3.5 shrink-0 opacity-60" />
      )}
      {label}
    </li>
  );
}

// Live password-policy checklist + confirm-match indicator. Shown beneath the
// password inputs in every set-password form (new-password challenge + reset).
function PasswordRequirements({
  password,
  confirmPassword,
}: {
  password: string;
  confirmPassword: string;
}) {
  return (
    <ul className="space-y-1 text-xs">
      {PASSWORD_RULES.map((rule) => (
        <RequirementRow key={rule.label} met={rule.test(password)} label={rule.label} />
      ))}
      {confirmPassword.length > 0 && (
        <RequirementRow
          met={password === confirmPassword}
          label={password === confirmPassword ? 'Passwords match' : "Passwords don't match"}
        />
      )}
    </ul>
  );
}

type View = 'signin' | 'new_password' | 'forgot_request' | 'forgot_confirm';

export function AuthGate({ onSuccess }: AuthGateProps) {
  const [view, setView] = useState<View>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  // Seed from the persisted preference so the box reflects the last choice.
  const [rememberMe, setRememberMe] = useState(
    () => useAuthStore.getState().rememberMe,
  );
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Browser-OAuth path (Hosted UI + PKCE). Falls back to the password form when
  // no Hosted UI domain is configured, or when the user opts into it.
  const [browserOAuth] = useState(() => isBrowserOAuthConfigured());
  const [usePassword, setUsePassword] = useState(false);
  const [browserPending, setBrowserPending] = useState(false);

  // New-password challenge state
  const [challengeUser, setChallengeUser] = useState<CognitoUser | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Forgot-password state
  const [resetCode, setResetCode] = useState('');
  const [resetSentTo, setResetSentTo] = useState('');

  const goToSignIn = () => {
    setView('signin');
    setError('');
    setPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setResetCode('');
  };

  // Launch the system-browser OAuth sign-in (password managers work natively;
  // Cognito Hosted UI handles MFA/SSO). On success the shared sink populates the
  // store exactly like the SRP path and re-runs startup via onSuccess.
  const handleBrowserSignIn = async () => {
    setError('');
    setBrowserPending(true);
    try {
      const { user, tokens } = await startBrowserLogin();
      completeAuthWithTokens(user, tokens, onSuccess, rememberMe);
    } catch (err) {
      if (!(err instanceof Error && err.message === 'cancelled')) {
        setError(err instanceof Error ? err.message : 'Sign-in failed. Please try again.');
      }
      setBrowserPending(false);
    }
  };

  const handleCancelBrowser = () => {
    cancelBrowserLogin();
    setBrowserPending(false);
    setError('');
  };

  const handleSignIn = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    // Password managers (and macOS Keychain in the Tauri webview) often set the
    // input value directly without firing React's onChange, leaving `email` /
    // `password` state empty. Read the actual submitted form values so an
    // autofilled login still works, then sync them back into state.
    const fd = new FormData(e.currentTarget);
    const emailVal = ((fd.get('email') as string | null) ?? email).trim();
    const passwordVal = (fd.get('password') as string | null) ?? password;
    if (!emailVal || !passwordVal) return;
    if (emailVal !== email) setEmail(emailVal);
    if (passwordVal !== password) setPassword(passwordVal);

    setError('');
    setLoading(true);

    try {
      const result: SignInResult = await signIn(emailVal, passwordVal);

      if (result.type === 'new_password_required') {
        setChallengeUser(result.cognitoUser);
        setPassword('');
        setView('new_password');
        setLoading(false);
        return;
      }

      completeAuth(result.session, onSuccess, rememberMe);
    } catch (err) {
      setError(mapCognitoError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleSetPassword = async (e: FormEvent) => {
    e.preventDefault();
    if (!newPassword || !confirmPassword || !challengeUser) return;

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const session = await completeNewPassword(challengeUser, newPassword);
      completeAuth(session, onSuccess, rememberMe);
    } catch (err) {
      setError(mapCognitoError(err));
      setLoading(false);
    }
  };

  const handleRequestReset = async (e: FormEvent) => {
    e.preventDefault();
    if (!email) return;

    setError('');
    setLoading(true);

    try {
      await forgotPassword(email);
    } catch (err) {
      const error = err as Error & { code?: string };
      const message = error.message || '';
      // Only surface true connectivity failures. For every other error
      // (UserNotFoundException, LimitExceededException, etc.) we advance
      // to the confirm step so an attacker can't probe which emails exist.
      if (
        error.code === 'NetworkError' ||
        message.includes('NetworkError') ||
        message.includes('fetch')
      ) {
        setError('Unable to connect. Check your internet connection.');
        setLoading(false);
        return;
      }
    }
    setResetSentTo(email);
    setView('forgot_confirm');
    setLoading(false);
  };

  const handleConfirmReset = async (e: FormEvent) => {
    e.preventDefault();
    if (!resetCode || !newPassword || !confirmPassword) return;

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }

    setError('');
    setLoading(true);

    try {
      await confirmPasswordReset(resetSentTo, resetCode.trim(), newPassword);
      // Auto-sign-in with the new password.
      const result: SignInResult = await signIn(resetSentTo, newPassword);
      if (result.type === 'success') {
        completeAuth(result.session, onSuccess, rememberMe);
        return;
      }
      // Edge case: Cognito demanded a new password challenge again.
      goToSignIn();
    } catch (err) {
      setError(mapCognitoError(err));
      setLoading(false);
    }
  };

  // ── Set New Password form ──
  if (view === 'new_password' && challengeUser) {
    return (
      <div className="flex items-center justify-center min-h-[calc(100vh-8rem)]">
        <Card className="w-full max-w-sm">
          <CardHeader className="items-center space-y-3 pb-2">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
              <KeyRound className="h-7 w-7 text-primary" />
            </div>
            <div className="text-center">
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                Set Your Password
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                Welcome to Maestro. Choose a permanent password for your account.
              </p>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSetPassword} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="new-password">
                  <Lock className="h-3.5 w-3.5" />
                  New password
                </Label>
                <Input
                  id="new-password"
                  type="password"
                  placeholder="At least 12 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  disabled={loading}
                  autoFocus
                  autoComplete="new-password"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirm-password">
                  <Lock className="h-3.5 w-3.5" />
                  Confirm password
                </Label>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder="Type it again"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={loading}
                  autoComplete="new-password"
                />
              </div>

              <PasswordRequirements password={newPassword} confirmPassword={confirmPassword} />

              {error && (
                <p className="text-sm text-destructive">{error}</p>
              )}

              <Button
                type="submit"
                className="w-full"
                disabled={loading || !newPassword || !confirmPassword}
              >
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Setting password...
                  </>
                ) : (
                  'Set Password & Continue'
                )}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── Forgot Password: request code ──
  if (view === 'forgot_request') {
    return (
      <div className="flex items-center justify-center min-h-[calc(100vh-8rem)]">
        <Card className="w-full max-w-sm">
          <CardHeader className="items-center space-y-3 pb-2">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
              <ShieldCheck className="h-7 w-7 text-primary" />
            </div>
            <div className="text-center">
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                Reset Password
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                Enter your email. If we have an account on file, we&apos;ll send
                you a verification code.
              </p>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleRequestReset} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="reset-email">
                  <Mail className="h-3.5 w-3.5" />
                  Email
                </Label>
                <Input
                  id="reset-email"
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loading}
                  autoFocus
                  autoComplete="email"
                />
              </div>

              {error && (
                <p className="text-sm text-destructive">{error}</p>
              )}

              <Button
                type="submit"
                className="w-full"
                disabled={loading || !email}
              >
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Sending code...
                  </>
                ) : (
                  'Send Verification Code'
                )}
              </Button>

              <button
                type="button"
                onClick={goToSignIn}
                disabled={loading}
                className="flex w-full items-center justify-center gap-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
              >
                <ArrowLeft className="h-3 w-3" />
                Back to sign in
              </button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── Forgot Password: confirm code + set new password ──
  if (view === 'forgot_confirm') {
    return (
      <div className="flex items-center justify-center min-h-[calc(100vh-8rem)]">
        <Card className="w-full max-w-sm">
          <CardHeader className="items-center space-y-3 pb-2">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
              <KeyRound className="h-7 w-7 text-primary" />
            </div>
            <div className="text-center">
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                Check Your Email
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                If an account exists for{' '}
                <span className="text-foreground">{resetSentTo}</span>, a
                verification code has been sent.
              </p>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleConfirmReset} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="reset-code">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  Verification code
                </Label>
                <Input
                  id="reset-code"
                  type="text"
                  inputMode="numeric"
                  placeholder="6-digit code"
                  value={resetCode}
                  onChange={(e) => setResetCode(e.target.value)}
                  disabled={loading}
                  autoFocus
                  autoComplete="one-time-code"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="reset-new-password">
                  <Lock className="h-3.5 w-3.5" />
                  New password
                </Label>
                <Input
                  id="reset-new-password"
                  type="password"
                  placeholder="At least 12 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  disabled={loading}
                  autoComplete="new-password"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="reset-confirm-password">
                  <Lock className="h-3.5 w-3.5" />
                  Confirm new password
                </Label>
                <Input
                  id="reset-confirm-password"
                  type="password"
                  placeholder="Type it again"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={loading}
                  autoComplete="new-password"
                />
              </div>

              <PasswordRequirements password={newPassword} confirmPassword={confirmPassword} />

              {error && (
                <p className="text-sm text-destructive">{error}</p>
              )}

              <Button
                type="submit"
                className="w-full"
                disabled={loading || !resetCode || !newPassword || !confirmPassword}
              >
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Resetting password...
                  </>
                ) : (
                  'Reset Password & Sign In'
                )}
              </Button>

              <button
                type="button"
                onClick={goToSignIn}
                disabled={loading}
                className="flex w-full items-center justify-center gap-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
              >
                <ArrowLeft className="h-3 w-3" />
                Back to sign in
              </button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── Sign In form ──
  return (
    <div className="flex flex-col items-center justify-center gap-4 min-h-[calc(100vh-8rem)]">
      <Card className="w-full max-w-sm shadow-xl">
        <CardHeader className="items-center space-y-3 pb-3">
          <Image
            src="/maestro-icon.png"
            alt="Maestro"
            width={64}
            height={64}
            className="h-16 w-16"
            priority
          />
          <div className="text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">
              Maestro
            </h1>
            <p className="text-sm text-muted-foreground">Security Platform</p>
          </div>
        </CardHeader>
        <CardContent>
          {browserOAuth && !usePassword ? (
            <div className="space-y-4">
              {browserPending ? (
                <div className="space-y-3 py-2 text-center">
                  <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                  <p className="text-sm font-medium text-foreground">
                    Waiting for you to finish signing in…
                  </p>
                  <p className="text-xs text-muted-foreground">
                    A secure sign-in page opened in your browser. Complete it there
                    (your password manager works), then return here.
                  </p>
                  {error && <p className="text-sm text-destructive">{error}</p>}
                  <div className="flex items-center justify-center gap-2 pt-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        void reopenAuthorizeUrl();
                      }}
                    >
                      <ExternalLink className="mr-1.5 h-3.5 w-3.5" />
                      Open page again
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={handleCancelBrowser}
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="space-y-1 pb-1 text-center">
                    <h2 className="text-base font-semibold text-foreground">
                      Welcome back
                    </h2>
                    <p className="text-xs text-muted-foreground">
                      Sign in to continue to your security workspace.
                    </p>
                  </div>
                  <Button
                    type="button"
                    size="lg"
                    className="w-full"
                    onClick={handleBrowserSignIn}
                  >
                    <Globe className="mr-2 h-4 w-4" />
                    Sign in
                  </Button>
                  <p className="text-center text-[11px] text-muted-foreground">
                    Opens a secure browser window — your password manager works there.
                  </p>
                  <label className="flex items-center justify-center gap-2 text-sm text-muted-foreground cursor-pointer select-none">
                    <Checkbox
                      checked={rememberMe}
                      onCheckedChange={(v) => setRememberMe(v === true)}
                    />
                    Remember me on this device
                  </label>
                  {error && (
                    <p className="text-center text-sm text-destructive">{error}</p>
                  )}
                  <div className="relative py-0.5">
                    <div className="absolute inset-0 flex items-center">
                      <span className="w-full border-t border-border/60" />
                    </div>
                    <div className="relative flex justify-center">
                      <span className="bg-card px-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                        or
                      </span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setError('');
                      setUsePassword(true);
                    }}
                    className="flex w-full items-center justify-center text-xs text-muted-foreground transition-colors hover:text-foreground"
                  >
                    Sign in with password instead
                  </button>
                </>
              )}
            </div>
          ) : (
          <form onSubmit={handleSignIn} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="auth-email">
                <Mail className="h-3.5 w-3.5" />
                Email
              </Label>
              <Input
                id="auth-email"
                name="email"
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
                autoFocus
                autoComplete="email"
              />
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="auth-password">
                  <Lock className="h-3.5 w-3.5" />
                  Password
                </Label>
                <button
                  type="button"
                  onClick={() => {
                    setError('');
                    setPassword('');
                    setView('forgot_request');
                  }}
                  disabled={loading}
                  className="text-xs text-muted-foreground hover:text-primary hover:underline disabled:opacity-50"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Input
                  id="auth-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                  autoComplete="current-password"
                  className="pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  tabIndex={-1}
                  className="absolute right-0 top-0 h-full px-3 text-muted-foreground"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer select-none">
              <Checkbox
                checked={rememberMe}
                onCheckedChange={(v) => setRememberMe(v === true)}
                disabled={loading}
              />
              Remember me on this device
            </label>

            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}

            <Button
              type="submit"
              className="w-full"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                'Sign In'
              )}
            </Button>

            {browserOAuth && (
              <button
                type="button"
                onClick={() => {
                  setError('');
                  setUsePassword(false);
                }}
                className="flex w-full items-center justify-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              >
                <ArrowLeft className="h-3 w-3" />
                Back to browser sign-in
              </button>
            )}
          </form>
          )}
        </CardContent>
      </Card>
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground/80">
        <ShieldCheck className="h-3.5 w-3.5" />
        Secured by Groovy Security
      </p>
    </div>
  );
}
