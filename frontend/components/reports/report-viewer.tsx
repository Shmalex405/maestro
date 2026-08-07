'use client';

import React, { useMemo } from 'react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '@/lib/utils';
import {
  CisCoverageCard,
  parseCisCoverageFromMarkdown,
} from './cis-coverage-card';

interface ReportViewerProps {
  content: string;
  className?: string;
  maxHeight?: string;
}

export function ReportViewer({ content, className, maxHeight = '70vh' }: ReportViewerProps) {
  // Sniff CIS coverage from the markdown body so we can render a structured
  // card above the content. Returns null when the report has no CIS section
  // (most non-cloud assessments) — caller renders unchanged in that case.
  // Memoised because the parser walks the full content with regex.
  const cisCoverage = useMemo(() => parseCisCoverageFromMarkdown(content), [content]);

  return (
    <div
      className={cn('w-full overflow-y-auto', className)}
      style={{ maxHeight }}
    >
      <div className="prose prose-invert max-w-none px-6 py-4">
        {cisCoverage && (
          <div className="not-prose">
            <CisCoverageCard coverage={cisCoverage} />
          </div>
        )}
        <Markdown
          remarkPlugins={[remarkGfm]}
          components={{
            // Headings
            h1: ({ children }) => (
              <h1 className="text-2xl font-bold text-foreground border-b border-border pb-3 mb-4">
                {children}
              </h1>
            ),
            h2: ({ children }) => (
              <h2 className="text-xl font-semibold text-foreground border-b border-border/50 pb-2 mb-3 mt-8">
                {children}
              </h2>
            ),
            h3: ({ children }) => (
              <h3 className="text-lg font-semibold text-foreground mb-2 mt-6">
                {children}
              </h3>
            ),
            h4: ({ children }) => (
              <h4 className="text-base font-semibold text-foreground mb-2 mt-4">
                {children}
              </h4>
            ),

            // Paragraphs
            p: ({ children }) => (
              <p className="text-muted-foreground leading-relaxed mb-3">
                {children}
              </p>
            ),

            // Strong / emphasis
            strong: ({ children }) => (
              <strong className="text-foreground font-semibold">{children}</strong>
            ),
            em: ({ children }) => (
              <em className="text-muted-foreground italic">{children}</em>
            ),

            // Links
            a: ({ href, children }) => (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300 underline underline-offset-2"
              >
                {children}
              </a>
            ),

            // Lists
            ul: ({ children }) => (
              <ul className="list-disc list-inside space-y-1 mb-3 text-muted-foreground">
                {children}
              </ul>
            ),
            ol: ({ children }) => (
              <ol className="list-decimal list-inside space-y-1 mb-3 text-muted-foreground">
                {children}
              </ol>
            ),
            li: ({ children }) => (
              <li className="text-muted-foreground leading-relaxed">{children}</li>
            ),

            // Tables
            table: ({ children }) => (
              <div className="overflow-x-auto mb-4 rounded-md border border-border">
                <table className="w-full text-sm">
                  {children}
                </table>
              </div>
            ),
            thead: ({ children }) => (
              <thead className="bg-muted/50 border-b border-border">
                {children}
              </thead>
            ),
            tbody: ({ children }) => (
              <tbody className="divide-y divide-border">{children}</tbody>
            ),
            tr: ({ children }) => (
              <tr className="hover:bg-muted/30 transition-colors">{children}</tr>
            ),
            th: ({ children }) => (
              <th className="px-3 py-2 text-left font-semibold text-foreground text-xs uppercase tracking-wider">
                {children}
              </th>
            ),
            td: ({ children }) => (
              <td className="px-3 py-2 text-muted-foreground">{children}</td>
            ),

            // Code blocks
            pre: ({ children }) => (
              <pre className="bg-zinc-900 border border-border rounded-md p-4 overflow-x-auto mb-4 text-sm">
                {children}
              </pre>
            ),
            code: ({ className, children, ...props }) => {
              const isInline = !className;
              if (isInline) {
                return (
                  <code
                    className="bg-muted px-1.5 py-0.5 rounded text-sm font-mono text-orange-300"
                    {...props}
                  >
                    {children}
                  </code>
                );
              }
              return (
                <code className={cn('font-mono text-green-300', className)} {...props}>
                  {children}
                </code>
              );
            },

            // Blockquotes
            blockquote: ({ children }) => (
              <blockquote className="border-l-4 border-primary/50 pl-4 py-1 mb-3 bg-primary/5 rounded-r">
                {children}
              </blockquote>
            ),

            // Horizontal rules
            hr: () => <hr className="border-border my-6" />,

            // Images
            img: ({ src, alt }) => (
              <img
                src={src}
                alt={alt || ''}
                className="max-w-full rounded-md border border-border my-4"
              />
            ),
          }}
        >
          {content}
        </Markdown>
      </div>
    </div>
  );
}
