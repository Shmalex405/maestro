'use client';

import { Eye } from 'lucide-react';
import { useIsReadOnly } from '@/lib/read-only';

/**
 * Sticky notice shown to read-only users so the disabled write actions across
 * the app read as intentional ("you can view but not change") rather than
 * broken. Renders nothing for everyone else.
 */
export function ReadOnlyBanner() {
  const readOnly = useIsReadOnly();
  if (!readOnly) return null;

  return (
    <div className="flex items-center justify-center gap-2 border-b border-amber-500/30 bg-amber-500/10 px-4 py-1.5 text-xs font-medium text-amber-600 dark:text-amber-400">
      <Eye className="h-3.5 w-3.5 shrink-0" />
      <span>
        Read-only access — you can view everything but can&apos;t make changes.
        Contact an admin to change your role.
      </span>
    </div>
  );
}
