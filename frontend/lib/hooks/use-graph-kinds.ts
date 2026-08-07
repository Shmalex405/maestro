'use client';

// Loads the attack-graph kind registry (GET /graph/kinds, useQuery-cached) and
// derives the runtime kind→style map the explorer + SVG widget consume. The
// hardcoded SEED_KIND_STYLE in attack-path-graph.tsx is only the offline default;
// this hook lets a custom/new kind render with its registered color, no code
// change.

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { NEUTRAL_KIND_STYLE, type KindStyle } from '@/components/viz/attack-path-graph';
import type { GraphKind } from '@/lib/types';

export function useGraphKinds() {
  const { data: kinds, isLoading } = useQuery({
    queryKey: ['graph-kinds'],
    queryFn: () => api.graph.kinds(),
    staleTime: 5 * 60 * 1000,
  });

  const list: GraphKind[] = useMemo(() => kinds ?? [], [kinds]);

  /** kind → style, built from the registry's `display` blob. */
  const kindStyles = useMemo(() => {
    const map: Record<string, KindStyle> = {};
    for (const k of list) {
      const d = k.display ?? {};
      if (d.fill || d.stroke || d.text) {
        map[k.kind] = {
          fill: d.fill ?? NEUTRAL_KIND_STYLE.fill,
          stroke: d.stroke ?? NEUTRAL_KIND_STYLE.stroke,
          text: d.text ?? NEUTRAL_KIND_STYLE.text,
        };
      }
    }
    return map;
  }, [list]);

  const kindByName = useMemo(
    () => new Map(list.map((k) => [k.kind, k] as const)),
    [list],
  );

  /** Node kinds only (for the kind filter); edge kinds excluded. */
  const nodeKinds = useMemo(() => list.filter((k) => !k.is_edge), [list]);

  return { kinds: list, kindStyles, kindByName, nodeKinds, isLoading };
}
