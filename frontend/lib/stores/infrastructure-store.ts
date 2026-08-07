import { create } from 'zustand';

export type InfraStatus =
  | 'unknown'
  | 'running'
  | 'stopped'
  | 'starting'
  | 'stopping'
  | 'pending'
  | 'not_provisioned'
  | 'error';

interface InfraState {
  status: InfraStatus;
  healthy: boolean;
  instanceId: string | null;
  instanceType: string | null;
  error: string | null;
  lastChecked: number | null;

  checkStatus: () => Promise<void>;
  startInstance: () => Promise<boolean>;
  stopInstance: () => Promise<boolean>;
  waitForHealthy: (timeoutMs?: number) => Promise<boolean>;
  checkHealth: () => Promise<boolean>;
  reset: () => void;
}

export const useInfraStore = create<InfraState>((set, get) => ({
  status: 'unknown',
  healthy: false,
  instanceId: null,
  instanceType: null,
  error: null,
  lastChecked: null,

  checkStatus: async () => {
    try {
      const res = await fetch('/api/infrastructure/status');
      const data = await res.json();
      set({
        status: data.state === 'not_provisioned' ? 'not_provisioned' : data.state,
        instanceId: data.instanceId,
        instanceType: data.instanceType || null,
        error: data.error || null,
        lastChecked: Date.now(),
      });
      // If running, also check health
      if (data.state === 'running') {
        get().checkHealth();
      } else {
        set({ healthy: false });
      }
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      set({ status: 'error', error: message, lastChecked: Date.now() });
    }
  },

  startInstance: async () => {
    set({ status: 'starting', error: null });
    try {
      const res = await fetch('/api/infrastructure/start', { method: 'POST' });
      if (!res.ok) {
        const data = await res.json();
        set({ status: 'error', error: data.error || 'Failed to start instance' });
        return false;
      }
      // Poll until running
      return new Promise<boolean>((resolve) => {
        const poll = setInterval(async () => {
          await get().checkStatus();
          const { status } = get();
          if (status === 'running') {
            clearInterval(poll);
            resolve(true);
          } else if (status === 'error') {
            clearInterval(poll);
            resolve(false);
          }
        }, 5000);
        // Timeout after 2 minutes
        setTimeout(() => {
          clearInterval(poll);
          if (get().status !== 'running') {
            set({ status: 'error', error: 'Instance start timed out' });
            resolve(false);
          }
        }, 120000);
      });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      set({ status: 'error', error: message });
      return false;
    }
  },

  stopInstance: async () => {
    set({ status: 'stopping', error: null });
    try {
      await fetch('/api/infrastructure/stop', { method: 'POST' });
      set({ status: 'stopped', healthy: false });
      return true;
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      set({ status: 'error', error: message });
      return false;
    }
  },

  waitForHealthy: async (timeoutMs = 180000) => {
    const start = Date.now();
    return new Promise<boolean>((resolve) => {
      const poll = setInterval(async () => {
        const isHealthy = await get().checkHealth();
        if (isHealthy) {
          clearInterval(poll);
          resolve(true);
        } else if (Date.now() - start > timeoutMs) {
          clearInterval(poll);
          resolve(false);
        }
      }, 3000);
    });
  },

  checkHealth: async () => {
    try {
      const res = await fetch('/api/infrastructure/health');
      const data = await res.json();
      set({ healthy: data.healthy });
      return data.healthy;
    } catch {
      set({ healthy: false });
      return false;
    }
  },

  reset: () =>
    set({
      status: 'unknown',
      healthy: false,
      instanceId: null,
      instanceType: null,
      error: null,
      lastChecked: null,
    }),
}));
