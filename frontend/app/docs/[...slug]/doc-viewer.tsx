'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import ReactMarkdown from 'react-markdown';
import type { Components } from 'react-markdown';
import type { ReactNode } from 'react';
import remarkGfm from 'remark-gfm';
import { api, isTauri } from '@/lib/tauri-api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ArrowLeft, Info, Lightbulb, TriangleAlert, OctagonAlert, Sparkles } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';

/**
 * In-line tab block syntax for embedded user-guide docs. Each user-guide
 * doc is plain markdown, but some pages want a "Terraform vs Manual"
 * style picker inline with the surrounding prose. To keep the docs
 * authorable as a single .md file, we use a fenced-divs style marker:
 *
 *   ::: tabs
 *   ::: tab Terraform
 *   ```hcl
 *   ...
 *   ```
 *   ::: tab Manual
 *   1. Open the AWS Console.
 *   2. ...
 *   :::
 *
 * The opening fence is `::: tabs` on its own line, each tab inside opens
 * with `::: tab <label>`, and the block closes with `:::` on its own line.
 * Markers must be alone on their line — leading/trailing whitespace OK.
 *
 * Why not a remark plugin: react-markdown's plugin API is fine for inline
 * transformations but rendering a stateful Tabs component mid-stream is
 * awkward. Pre-splitting the source into "plain markdown segment" and
 * "tabs block" segments and rendering each appropriately is simpler.
 *
 * Callouts (admonitions) use GitHub's alert syntax, extended with an
 * optional title on the marker line:
 *
 *   > [!TIP] Save yourself a step
 *   > You can paste an SSO profile name straight into the form.
 *
 * Supported variants: NOTE, TIP, WARNING, IMPORTANT, CAUTION. The body is
 * every following line that begins with `>`; the block ends at the first
 * line that doesn't. The body is itself rendered as markdown, so lists,
 * code, and links inside a callout work. Same rationale as tabs for why
 * this is a pre-split segment rather than a `blockquote` component override:
 * inspecting react-markdown's child nodes to detect the `[!TYPE]` marker is
 * far more brittle than splitting the raw source line-by-line.
 */
type CalloutVariant = 'note' | 'tip' | 'warning' | 'important' | 'caution';

type DocSegment =
  | { kind: 'markdown'; content: string }
  | { kind: 'tabs'; tabs: Array<{ label: string; content: string }> }
  | { kind: 'callout'; variant: CalloutVariant; title?: string; content: string };

const TABS_OPEN = '::: tabs';
const TAB_OPEN_PREFIX = '::: tab ';
const TABS_CLOSE = ':::';

// `> [!TIP] Optional title` — variant is required, title is optional.
const CALLOUT_RE = /^>\s?\[!(NOTE|TIP|WARNING|IMPORTANT|CAUTION)\]\s*(.*)$/i;

// Tuned for the white "sheet" the docs render on — light tinted backgrounds
// with darker accent text so they stay legible on black-on-white pages.
const CALLOUT_STYLES: Record<
  CalloutVariant,
  { icon: LucideIcon; label: string; box: string; iconColor: string; titleColor: string }
> = {
  note: {
    icon: Info,
    label: 'Note',
    box: 'border-sky-200 bg-sky-50',
    iconColor: 'text-sky-600',
    titleColor: 'text-sky-800',
  },
  tip: {
    icon: Lightbulb,
    label: 'Tip',
    box: 'border-emerald-200 bg-emerald-50',
    iconColor: 'text-emerald-600',
    titleColor: 'text-emerald-800',
  },
  important: {
    icon: Sparkles,
    label: 'Important',
    box: 'border-violet-200 bg-violet-50',
    iconColor: 'text-violet-600',
    titleColor: 'text-violet-800',
  },
  warning: {
    icon: TriangleAlert,
    label: 'Warning',
    box: 'border-amber-200 bg-amber-50',
    iconColor: 'text-amber-600',
    titleColor: 'text-amber-800',
  },
  caution: {
    icon: OctagonAlert,
    label: 'Caution',
    box: 'border-red-200 bg-red-50',
    iconColor: 'text-red-600',
    titleColor: 'text-red-800',
  },
};

/**
 * Resolve a relative markdown link (`./aws.md`, `../architecture.md`) against
 * the current doc's slug into an in-app route (`/docs/cloud-accounts/aws`).
 * Returns null for anything that isn't a relative `.md` link — external URLs,
 * in-page anchors, and absolute paths are left untouched.
 */
function resolveDocHref(currentSlug: string, href: string): string | null {
  if (/^[a-z]+:/i.test(href) || href.startsWith('#') || href.startsWith('/')) {
    return null;
  }
  const [pathPart, anchor = ''] = href.split('#');
  if (!pathPart.endsWith('.md')) return null;

  // Start from the directory of the current doc, then apply the relative path.
  const stack = currentSlug.split('/').slice(0, -1);
  for (const part of pathPart.replace(/\.md$/, '').split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  const target = stack.join('/');
  if (!target) return null;
  return `/docs/${target}${anchor ? `#${anchor}` : ''}`;
}

/** Title-case one slug segment: "cloud-accounts" → "Cloud Accounts". */
function humanizeSegment(seg: string): string {
  return seg
    .split('-')
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(' ');
}

/**
 * Markdown component overrides for a given doc slug. The only override is
 * `a`: relative cross-doc links become client-side `<Link>` navigations to
 * the right route; everything else renders as a normal anchor (external
 * links open in the browser).
 */
function makeMarkdownComponents(slug: string): Components {
  return {
    a: ({ href, children }: { href?: string; children?: ReactNode }) => {
      const resolved = href ? resolveDocHref(slug, href) : null;
      if (resolved) {
        return <Link href={resolved}>{children}</Link>;
      }
      return (
        <a href={href} target="_blank" rel="noreferrer">
          {children}
        </a>
      );
    },
  };
}

function parseDocSegments(source: string): DocSegment[] {
  const segments: DocSegment[] = [];
  const lines = source.split('\n');
  let mdBuf: string[] = [];
  let inTabs = false;
  let tabs: Array<{ label: string; content: string }> = [];
  let currentTab: { label: string; content: string } | null = null;

  // Callout (admonition) state.
  let inCallout = false;
  let calloutVariant: CalloutVariant = 'note';
  let calloutTitle: string | undefined;
  let calloutBuf: string[] = [];

  const flushMarkdown = () => {
    if (mdBuf.length === 0) return;
    const content = mdBuf.join('\n');
    // Skip pure-whitespace flushes; they only add empty <p> tags.
    if (content.trim().length > 0) {
      segments.push({ kind: 'markdown', content });
    }
    mdBuf = [];
  };

  const flushCallout = () => {
    segments.push({
      kind: 'callout',
      variant: calloutVariant,
      title: calloutTitle,
      content: calloutBuf.join('\n'),
    });
    inCallout = false;
    calloutTitle = undefined;
    calloutBuf = [];
  };

  for (const line of lines) {
    const trimmed = line.trim();

    // A callout runs until the first line that isn't a `>` quote line.
    if (inCallout) {
      if (trimmed.startsWith('>')) {
        // Strip the leading `>` and one optional space.
        calloutBuf.push(line.replace(/^\s*>\s?/, ''));
        continue;
      }
      flushCallout();
      // Fall through so this same line is reconsidered as normal content.
    }

    if (!inTabs) {
      const calloutMatch = trimmed.match(CALLOUT_RE);
      if (calloutMatch) {
        flushMarkdown();
        inCallout = true;
        calloutVariant = calloutMatch[1].toLowerCase() as CalloutVariant;
        calloutTitle = calloutMatch[2].trim() || undefined;
        calloutBuf = [];
      } else if (trimmed === TABS_OPEN) {
        flushMarkdown();
        inTabs = true;
        tabs = [];
        currentTab = null;
      } else {
        mdBuf.push(line);
      }
      continue;
    }

    // Inside a tabs block.
    if (trimmed.startsWith(TAB_OPEN_PREFIX)) {
      if (currentTab) tabs.push(currentTab);
      const label = trimmed.slice(TAB_OPEN_PREFIX.length).trim();
      currentTab = { label, content: '' };
    } else if (trimmed === TABS_CLOSE) {
      if (currentTab) tabs.push(currentTab);
      if (tabs.length > 0) {
        segments.push({ kind: 'tabs', tabs });
      }
      inTabs = false;
      currentTab = null;
      tabs = [];
    } else if (currentTab) {
      currentTab.content += (currentTab.content ? '\n' : '') + line;
    }
    // Lines inside `::: tabs` but before the first `::: tab` are dropped
    // by design — the author can put a paragraph before the tabs block
    // instead.
  }

  // Unterminated tabs block: render whatever we have so the page still
  // shows up rather than swallowing the rest of the doc.
  if (inTabs) {
    if (currentTab) tabs.push(currentTab);
    if (tabs.length > 0) {
      segments.push({ kind: 'tabs', tabs });
    }
  }
  // A callout that runs to the end of the file (no trailing plain line).
  if (inCallout) {
    flushCallout();
  }
  flushMarkdown();
  return segments;
}

export function DocViewer({ slug }: { slug: string }) {

  const { data, isLoading, error } = useQuery({
    queryKey: ['user-guide-doc', slug],
    queryFn: () => api.help.readUserGuideDoc(slug),
    staleTime: Infinity,
    enabled: isTauri(),
  });

  if (!isTauri()) {
    return (
      <div className="p-6">
        <Card>
          <CardHeader>
            <CardTitle>Docs</CardTitle>
          </CardHeader>
          <CardContent>
            The user guide is only available in the Maestro desktop app.
          </CardContent>
        </Card>
      </div>
    );
  }

  const segments = data ? parseDocSegments(data) : [];
  const mdComponents = makeMarkdownComponents(slug);
  // For a nested doc (`cloud-accounts/aws`), show the section name as a
  // breadcrumb so the reader knows where they are. Top-level docs skip it.
  const parentSegments = slug.split('/').slice(0, -1);

  return (
    <div className="p-6 max-w-4xl space-y-4">
      <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
        <Link href="/docs">
          <Button variant="ghost" size="sm" className="gap-1.5 -ml-2">
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to docs
          </Button>
        </Link>
        {parentSegments.map((seg) => (
          <span key={seg} className="flex items-center gap-1.5">
            <span className="text-muted-foreground/50">/</span>
            <span>{humanizeSegment(seg)}</span>
          </span>
        ))}
      </div>

      {isLoading && (
        <div className="space-y-3">
          <Skeleton className="h-8 w-2/3" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
        </div>
      )}

      {error && (
        <Card>
          <CardContent className="pt-6 text-destructive text-sm">
            Failed to load doc: {String((error as Error).message ?? error)}
          </CardContent>
        </Card>
      )}

      {data && (
        <div className="rounded-xl bg-white px-7 py-6 shadow-sm ring-1 ring-zinc-200/70">
        <article className="doc-prose max-w-none">
          {segments.map((seg, i) => {
            if (seg.kind === 'markdown') {
              return (
                <ReactMarkdown key={i} remarkPlugins={[remarkGfm]} components={mdComponents}>
                  {seg.content}
                </ReactMarkdown>
              );
            }
            if (seg.kind === 'callout') {
              return (
                <Callout
                  key={i}
                  variant={seg.variant}
                  title={seg.title}
                  content={seg.content}
                  components={mdComponents}
                />
              );
            }
            return (
              <Tabs
                key={i}
                defaultValue={seg.tabs[0]?.label}
                // not-prose lets shadcn's Tabs styling take over inside
                // the surrounding `prose` scope — without it, prose's
                // typography classes bleed into the trigger/content.
                className="not-prose my-4"
              >
                <TabsList className="bg-zinc-100">
                  {seg.tabs.map((t) => (
                    <TabsTrigger
                      key={t.label}
                      value={t.label}
                      className="text-zinc-500 data-[state=active]:bg-white data-[state=active]:text-zinc-900 data-[state=active]:shadow-sm"
                    >
                      {t.label}
                    </TabsTrigger>
                  ))}
                </TabsList>
                {seg.tabs.map((t) => (
                  <TabsContent
                    key={t.label}
                    value={t.label}
                    // Re-apply the prose styles inside the tab body so
                    // the markdown content keeps the same look as the
                    // surrounding article.
                    className="doc-prose max-w-none mt-3"
                  >
                    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                      {t.content}
                    </ReactMarkdown>
                  </TabsContent>
                ))}
              </Tabs>
            );
          })}
        </article>
        </div>
      )}
    </div>
  );
}

/**
 * Renders a `> [!TYPE]` callout as a bordered, tinted box with an icon and
 * an optional title. Body content is markdown, so lists/code/links work.
 */
function Callout({
  variant,
  title,
  content,
  components,
}: {
  variant: CalloutVariant;
  title?: string;
  content: string;
  components?: Components;
}) {
  const style = CALLOUT_STYLES[variant];
  const Icon = style.icon;
  return (
    <div className={`not-prose my-4 rounded-lg border-l-2 border ${style.box} px-4 py-3`}>
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 shrink-0 ${style.iconColor}`} />
        <span className={`text-xs font-semibold uppercase tracking-wide ${style.titleColor}`}>
          {title ?? style.label}
        </span>
      </div>
      {content.trim().length > 0 && (
        <div className="doc-prose doc-prose-tight max-w-none mt-2">
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
            {content}
          </ReactMarkdown>
        </div>
      )}
    </div>
  );
}
