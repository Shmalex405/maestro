'use client';

import { useRouter } from 'next/navigation';
import type { LucideIcon } from 'lucide-react';
import { ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface PageHeaderProps {
  /** The page title. */
  title: React.ReactNode;
  /** Optional one-line description shown under the title. */
  description?: React.ReactNode;
  /** Optional leading icon, rendered in the brand accent. */
  icon?: LucideIcon;
  /** When set, renders a back button that navigates here. */
  backHref?: string;
  /** Right-aligned actions (buttons, filters). */
  actions?: React.ReactNode;
  className?: string;
}

/**
 * The single page-title primitive. Standardizes the title scale, subtitle
 * treatment, icon accent, back affordance, and action layout so every page
 * reads as one product. Change the type scale here, not in 50 pages.
 */
export function PageHeader({ title, description, icon: Icon, backHref, actions, className }: PageHeaderProps) {
  const router = useRouter();
  return (
    <div className={cn('flex items-start justify-between gap-4', className)}>
      <div className="flex min-w-0 items-start gap-3">
        {backHref && (
          <Button
            variant="ghost"
            size="icon"
            className="mt-0.5 shrink-0"
            onClick={() => router.push(backHref)}
            aria-label="Back"
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
        )}
        <div className="min-w-0">
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
            {Icon && <Icon className="h-6 w-6 shrink-0 text-primary" />}
            <span className="truncate">{title}</span>
          </h1>
          {description && <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}
