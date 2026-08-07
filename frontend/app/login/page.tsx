'use client';

import { signIn } from 'next-auth/react';
import { useSearchParams } from 'next/navigation';
import Image from 'next/image';
import { Suspense } from 'react';

function LoginContent() {
  const searchParams = useSearchParams();
  const error = searchParams.get('error');

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm rounded-xl border border-border bg-card p-8 shadow-xl">
        <div className="flex flex-col items-center gap-4">
          {/* Logo */}
          <Image
            src="/maestro-icon.png"
            alt="Maestro"
            width={64}
            height={64}
            className="h-16 w-16"
          />

          {/* Title */}
          <div className="text-center">
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              Maestro Security Platform
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Sign in to continue
            </p>
          </div>

          {/* Error message */}
          {error && (
            <div className="w-full rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
              {error === 'OAuthSignin' && 'Error starting the sign-in flow. Please try again.'}
              {error === 'OAuthCallback' && 'Error during authentication callback.'}
              {error === 'OAuthAccountNotLinked' && 'This account is linked to a different provider.'}
              {error === 'Callback' && 'Authentication callback error. Please try again.'}
              {!['OAuthSignin', 'OAuthCallback', 'OAuthAccountNotLinked', 'Callback'].includes(error) &&
                'An authentication error occurred. Please try again.'}
            </div>
          )}

          {/* Sign in button */}
          <button
            onClick={() => signIn('cognito', { callbackUrl: '/' })}
            className="mt-2 w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary/50 focus:ring-offset-2 focus:ring-offset-background"
          >
            Sign in with SSO
          </button>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center">
          <p className="text-xs text-muted-foreground">Groovy Security</p>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    }>
      <LoginContent />
    </Suspense>
  );
}
