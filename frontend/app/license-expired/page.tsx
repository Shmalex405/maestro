'use client';

import { signOut } from 'next-auth/react';
import { useSearchParams } from 'next/navigation';
import Image from 'next/image';
import { Suspense } from 'react';

function LicenseExpiredContent() {
  const searchParams = useSearchParams();
  const reason = searchParams.get('reason') || 'expired';

  const messages: Record<string, { title: string; description: string }> = {
    expired: {
      title: 'License Expired',
      description: 'Your organization\'s license has expired. Please contact your account manager or sales@groovysec.com to renew.',
    },
    suspended: {
      title: 'Account Suspended',
      description: 'Your organization\'s account has been suspended. Please contact support@groovysec.com for assistance.',
    },
    no_license: {
      title: 'No Active License',
      description: 'No active license was found for your organization. Please contact sales@groovysec.com to get started.',
    },
    not_found: {
      title: 'Organization Not Found',
      description: 'Your email is not associated with a registered organization. Please contact support@groovysec.com.',
    },
  };

  const { title, description } = messages[reason] || messages.expired;

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-8 shadow-xl">
        <div className="flex flex-col items-center gap-4">
          <Image
            src="/maestro-icon.png"
            alt="Maestro"
            width={64}
            height={64}
            className="h-16 w-16 opacity-50"
          />

          <div className="text-center">
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              {title}
            </h1>
            <p className="mt-2 text-sm text-muted-foreground">
              {description}
            </p>
          </div>

          <div className="mt-4 flex w-full flex-col gap-2">
            <a
              href="mailto:sales@groovysec.com"
              className="w-full rounded-lg bg-primary px-4 py-2.5 text-center text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              Contact Sales
            </a>
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className="w-full rounded-lg border border-border px-4 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent"
            >
              Sign Out
            </button>
          </div>
        </div>

        <div className="mt-8 text-center">
          <p className="text-xs text-muted-foreground">Groovy Security</p>
        </div>
      </div>
    </div>
  );
}

export default function LicenseExpiredPage() {
  return (
    <Suspense fallback={
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    }>
      <LicenseExpiredContent />
    </Suspense>
  );
}
