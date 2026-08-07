'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api, isTauri, type UserGuideEntry } from '@/lib/tauri-api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ArrowRight, BookOpen, ChevronRight } from 'lucide-react';

/** A single navigable doc rendered as a clickable card. */
function DocCard({ doc, compact = false }: { doc: UserGuideEntry; compact?: boolean }) {
  return (
    <Link href={`/docs/${doc.slug}`} className="block group">
      <Card className="transition-colors group-hover:border-primary/40 group-hover:bg-primary/5">
        <CardHeader className={compact ? 'py-3' : 'pb-3'}>
          <CardTitle className={`flex items-center justify-between ${compact ? 'text-sm' : 'text-base'}`}>
            <span>{doc.title}</span>
            <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
          </CardTitle>
          {doc.summary && (
            <CardDescription className="text-sm">{doc.summary}</CardDescription>
          )}
        </CardHeader>
      </Card>
    </Link>
  );
}

/**
 * A folder/section rendered as a collapsible group: click the header to
 * open/close its child pages. Collapsed by default so the index stays tidy.
 */
function DocSection({ section }: { section: UserGuideEntry }) {
  const [open, setOpen] = useState(false);
  const children = section.children ?? [];
  return (
    <Card className="overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-6 py-4 text-left transition-colors hover:bg-primary/5"
      >
        <ChevronRight
          className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-90' : ''}`}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-base font-semibold tracking-tight">{section.title}</span>
            <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
              {children.length}
            </span>
          </div>
          {section.summary && (
            <p className="text-sm text-muted-foreground mt-0.5 truncate">{section.summary}</p>
          )}
        </div>
      </button>
      {open && (
        <div className="grid gap-2 border-t border-border/40 bg-muted/20 px-4 py-3">
          {children.map((child) => (
            <DocCard key={child.slug} doc={child} compact />
          ))}
        </div>
      )}
    </Card>
  );
}

export default function DocsIndexPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['user-guide-index'],
    queryFn: () => api.help.listUserGuide(),
    // Embedded resources don't change at runtime — cache the list.
    staleTime: Infinity,
    enabled: isTauri(),
  });

  if (!isTauri()) {
    return (
      <div className="p-6">
        <Card>
          <CardHeader>
            <CardTitle>Docs</CardTitle>
            <CardDescription>
              The user guide is only available in the Maestro desktop app.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div className="flex items-start gap-3">
        <div className="rounded-lg bg-primary/10 p-2.5">
          <BookOpen className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Documentation</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Walkthroughs and reference for using Maestro day-to-day. Same content shipped with this app version — no internet required.
          </p>
        </div>
      </div>

      {isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      )}

      {error && (
        <Card>
          <CardContent className="pt-6 text-destructive text-sm">
            Failed to load docs index: {String((error as Error).message ?? error)}
          </CardContent>
        </Card>
      )}

      {data && (
        <div className="grid gap-4">
          {data.map((doc) =>
            doc.is_section ? (
              <DocSection key={doc.slug} section={doc} />
            ) : (
              <DocCard key={doc.slug} doc={doc} />
            ),
          )}
        </div>
      )}
    </div>
  );
}
