import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/**
 * Maestro-side persisted UI settings. Claude credential mode is NOT
 * stored here — that lives in the Tauri backend's keychain + settings
 * file (see commands/credentials.rs) so it can survive a frontend wipe
 * and so the API key never lands in zustand's localStorage.
 */
interface SettingsStore {
  /** Resolved path to tmux binary (bundled sidecar or system); null = unavailable */
  tmuxPath: string | null;
  setTmuxPath: (path: string | null) => void;
}

export const useSettingsStore = create<SettingsStore>()(
  persist(
    (set) => ({
      tmuxPath: null,
      setTmuxPath: (path) => set({ tmuxPath: path }),
    }),
    {
      name: 'maestro-settings',
      // v1 → v2: drop the legacy `preferredCli` and `maestroCommand` fields
      // left over from the bundled-Maestro-CLI era. Local LLM support was
      // removed in 0.1.20, and along with it the option to pick between
      // "claude" and "maestro" CLIs — Claude Code is the only driver now.
      version: 2,
      migrate: (persisted: unknown) => {
        if (persisted && typeof persisted === 'object') {
          const obj = persisted as Record<string, unknown>;
          return { tmuxPath: typeof obj.tmuxPath === 'string' ? obj.tmuxPath : null };
        }
        return { tmuxPath: null };
      },
    }
  )
);

// Legacy export kept for code that hasn't been migrated yet. The values
// are no longer meaningful — every callsite should be updated to drop
// the CLI picker entirely. See FOLLOWUPS in commands/credentials.rs.
export type CliPreference = 'claude';
