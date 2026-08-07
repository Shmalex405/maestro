// A ProgressFeed is anything that pushes ProgressEvents at a subscriber. Two
// implementations: createLiveFeed (the real SSE stream off the MCP server) and
// createMockFeed (a scripted run for UI development — see ./mock-feed). The
// Assessment View consumes a feed without knowing which it is, so the same
// components validate against mock data and then light up live unchanged.

import type { ProgressEvent } from './types';

export interface ProgressFeed {
  /** Returns an unsubscribe fn. */
  subscribe(cb: (e: ProgressEvent) => void): () => void;
}

const MCP_BASE =
  process.env.NEXT_PUBLIC_DEPLOY_MODE === 'web'
    ? ''
    : process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

/**
 * Live feed: the MCP server's existing SSE endpoint
 * `GET /api/assessments/:id/events`, filtered to `progress_event`s emitted by
 * the tool-dispatch chokepoint. Auto-reconnects (EventSource does this for us);
 * malformed frames are skipped.
 */
export function createLiveFeed(assessmentId: string): ProgressFeed {
  return {
    subscribe(cb) {
      const url = `${MCP_BASE}/api/assessments/${encodeURIComponent(
        assessmentId
      )}/events`;
      const es = new EventSource(url);
      const onProgress = (ev: MessageEvent) => {
        try {
          cb(JSON.parse(ev.data) as ProgressEvent);
        } catch {
          /* skip malformed frame */
        }
      };
      // The route names each event by type; we only want progress_event.
      es.addEventListener('progress_event', onProgress as EventListener);
      return () => {
        es.removeEventListener('progress_event', onProgress as EventListener);
        es.close();
      };
    },
  };
}
