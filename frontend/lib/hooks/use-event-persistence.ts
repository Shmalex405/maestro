'use client';

import { useEffect, useRef } from 'react';
import { useParsedOutputStore } from '@/lib/stores/parsed-output-store';
import { api } from '@/lib/tauri-api';
import type { ParsedBlock } from '@/lib/terminal-parser';

const PERSIST_TYPES = new Set<ParsedBlock['type']>([
  'tool_call',
  'tool_result',
  'finding_detected',
]);

const EVENT_TYPE_FOR_BLOCK: Record<string, 'tool_call' | 'tool_result' | 'finding_detected'> = {
  tool_call: 'tool_call',
  tool_result: 'tool_result',
  finding_detected: 'finding_detected',
};

/**
 * Persists notable parsed blocks (tool calls, tool results, findings) to the
 * cloud assessment_events table so the activity feed survives across machines
 * and reloads. No-ops when there's no assessmentId yet.
 *
 * createEvent is `cloudRequestOrDefault` so a missing backend endpoint or 404
 * silently returns null — local terminal rendering is unaffected.
 */
export function useEventPersistence(
  assessmentId: string | null,
  sessionKey: string,
) {
  const blocks = useParsedOutputStore((s) => s.sessions.get(sessionKey));
  const persistedIds = useRef<Set<string>>(new Set());

  // Reset the dedupe set when the assessment context changes
  useEffect(() => {
    persistedIds.current = new Set();
  }, [assessmentId, sessionKey]);

  useEffect(() => {
    if (!assessmentId || !blocks) return;

    const fresh = blocks.filter(
      (b) => PERSIST_TYPES.has(b.type) && !persistedIds.current.has(b.id),
    );
    if (fresh.length === 0) return;

    for (const b of fresh) {
      persistedIds.current.add(b.id);

      const meta = (b.metadata ?? {}) as Record<string, unknown>;
      const tool =
        typeof meta.toolName === 'string'
          ? (meta.toolName as string)
          : typeof meta.tool === 'string'
            ? (meta.tool as string)
            : undefined;
      const target =
        typeof meta.target === 'string' ? (meta.target as string) : undefined;
      const refFindingId =
        b.type === 'finding_detected' && typeof meta.findingId === 'string'
          ? (meta.findingId as string)
          : undefined;

      const event = {
        event_type: EVENT_TYPE_FOR_BLOCK[b.type],
        tool,
        target,
        details: {
          blockId: b.id,
          content: b.content?.slice(0, 4000),
          metadata: meta,
          timestamp: b.timestamp,
        },
        ref_finding_id: refFindingId,
      };

      api.assessments.createEvent(assessmentId, event).catch(() => {
        // graceful — already 404-tolerant, but swallow any unexpected throw
      });
    }
  }, [blocks, assessmentId]);
}
