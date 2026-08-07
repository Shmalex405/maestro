'use client';

// The live narration ticker: a reverse-chronological stream of plain-English
// lines, newest on top, animating in. Each line is one tool dispatch projected
// by the server's templated narrator (no LLM).

import { useEffect, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { CheckCircle2, XCircle, Loader2 } from 'lucide-react';
import type { TickerLine } from '@/lib/assessment-progress/types';

function StatusIcon({ status }: { status: TickerLine['status'] }) {
  if (status === 'ok')
    return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0" />;
  if (status === 'error')
    return <XCircle className="h-3.5 w-3.5 text-amber-500 shrink-0" />;
  return <Loader2 className="h-3.5 w-3.5 text-cyan-400 shrink-0 animate-spin" />;
}

function timeOf(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function ActivityTicker({
  lines,
  className,
}: {
  lines: TickerLine[];
  className?: string;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  // Newest first.
  const ordered = [...lines].reverse();

  // Keep the newest line in view (it's at the top, so scroll to top).
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
  }, [lines.length]);

  return (
    <div className={cn('flex flex-col h-full', className)}>
      <div className="px-3 py-2 border-b flex items-center justify-between">
        <span className="text-xs font-semibold text-foreground">Live activity</span>
        <span className="text-[10px] text-muted-foreground tabular-nums">
          {lines.length} events
        </span>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-2 py-1.5">
        {ordered.length === 0 ? (
          <div className="text-[11px] text-muted-foreground px-2 py-4">
            Waiting for the assessment to start…
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {ordered.map((line) => (
              <motion.div
                key={line.id}
                layout
                initial={{ opacity: 0, y: -6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="flex items-start gap-2 px-2 py-1 rounded-md hover:bg-muted/40"
              >
                <StatusIcon status={line.status} />
                <div className="min-w-0 flex-1">
                  <div className="text-[11px] text-foreground leading-snug">
                    {line.narration}
                  </div>
                  <div className="text-[10px] text-muted-foreground flex items-center gap-1.5">
                    {line.agent && <span className="truncate">{line.agent}</span>}
                    {line.agent && <span>·</span>}
                    <span className="tabular-nums">{timeOf(line.ts)}</span>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
