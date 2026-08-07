'use client';

import { useRef, useCallback, useEffect } from 'react';
import { TerminalParser } from '@/lib/terminal-parser';
import { useParsedOutputStore } from '@/lib/stores/parsed-output-store';

/**
 * Hook that creates a TerminalParser instance and connects it to the
 * parsed-output-store. Returns a `feedData` callback that should be
 * called with raw PTY data (same data that xterm.write receives).
 */
export function useTerminalParser(sessionKey: string) {
  const addBlock = useParsedOutputStore((s) => s.addBlock);
  const updateBlock = useParsedOutputStore((s) => s.updateBlock);
  const clearSession = useParsedOutputStore((s) => s.clearSession);
  const parserRef = useRef<TerminalParser | null>(null);

  // Create parser with callbacks that write to the store
  useEffect(() => {
    const parser = new TerminalParser(
      (block) => addBlock(sessionKey, block),
      (id, content) => updateBlock(sessionKey, id, content)
    );
    parserRef.current = parser;

    return () => {
      parser.reset();
      parserRef.current = null;
    };
  }, [sessionKey, addBlock, updateBlock]);

  /** Feed raw PTY data into the parser */
  const feedData = useCallback((data: string) => {
    parserRef.current?.feed(data);
  }, []);

  /** Reset parser and clear stored blocks */
  const reset = useCallback(() => {
    parserRef.current?.reset();
    clearSession(sessionKey);
  }, [sessionKey, clearSession]);

  return { feedData, reset };
}
