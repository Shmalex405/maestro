/**
 * Read-only fast-path in the startup gate.
 *
 * A read-only user can only VIEW cloud data — they can't run assessments, so
 * they have no use for the Kali container/MCP server, and the image-pull path
 * calls a blocked write command (set_toolkit_credentials) that makes the build
 * impossible for them. The gate must short-circuit the whole
 * Docker/image/container pipeline for read-only users and render the app
 * directly. These tests pin that behavior so it can't silently regress.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

vi.mock('@/lib/cognito-auth', () => ({
  isCognitoConfigured: () => true,
  refreshSession: vi.fn(),
  getUserFromToken: vi.fn(),
}));

vi.mock('@/lib/desktop-bootstrap', () => ({
  isBootstrapped: () => true,
  bootstrapNeedsRefresh: () => false,
  getBootstrap: () => null,
  saveBootstrap: vi.fn(),
  discover: vi.fn(),
}));

vi.mock('@/lib/tauri-api', () => ({
  isTauri: () => true,
  api: {
    system: {
      // If the fast-path works, NONE of these run for a read-only user.
      diagnoseDocker: vi.fn(() => Promise.resolve({ state: 'healthy' })),
      checkKaliImageExists: vi.fn(() => Promise.resolve(true)),
      pullKaliImage: vi.fn(),
      pullKaliImageWithAuth: vi.fn(),
      setToolkitCredentials: vi.fn(),
      onBuildProgress: vi.fn(() => () => {}),
      onPullProgress: vi.fn(() => () => {}),
      startKali: vi.fn(),
      ensureMcpServer: vi.fn(),
      getStatus: vi.fn(() => Promise.resolve({ mcp_server_connected: true })),
    },
    terminal: {
      checkAvailableClis: vi.fn(() => Promise.resolve({ claude: true })),
      getTmuxPath: vi.fn(() => Promise.resolve(null)),
    },
  },
}));

// Mutable so each test can pick the signed-in user's groups.
const authState: { groups: string[] } = { groups: [] };
vi.mock('@/lib/stores/auth-store', () => ({
  useAuthStore: Object.assign(
    () => ({ isAuthenticated: true, user: { email: 't@t', groups: authState.groups } }),
    {
      getState: () => ({
        isAuthenticated: true,
        user: { email: 't@t', groups: authState.groups },
        isTokenExpired: () => false,
      }),
    },
  ),
}));

vi.mock('@/lib/stores/settings-store', () => ({
  useSettingsStore: Object.assign(
    () => ({}),
    { getState: () => ({ setTmuxPath: vi.fn() }) },
  ),
}));

import { StartupGate } from '@/components/layout/startup-gate';
import { api } from '@/lib/tauri-api';

const mockApi = api as unknown as {
  system: { diagnoseDocker: ReturnType<typeof vi.fn> };
};

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  authState.groups = [];
});

// NOTE on ordering: the read-only fast-path calls markCompleted(), which flips
// a sticky module-level flag in startup-gate.tsx that beforeEach cannot reset
// (it's module-private and only re-reads sessionStorage while still false). So
// the tests that expect the Docker pipeline to RUN must come before the one
// that skips it (which completes the gate). The existing startup-gate.test.tsx
// relies on the same property — none of its cases reach markCompleted().
describe('StartupGate read-only fast-path', () => {
  it('still runs the Docker pipeline for a non-read-only user', async () => {
    authState.groups = ['org:groovy'];
    // Stop the pipeline early so it never reaches markCompleted() — that would
    // flip the sticky module flag and short-circuit the later test.
    mockApi.system.diagnoseDocker.mockResolvedValueOnce({ state: 'not_installed' });
    render(<StartupGate>app-content</StartupGate>);

    await waitFor(() => {
      expect(mockApi.system.diagnoseDocker).toHaveBeenCalled();
    });
  });

  it('admin overrides read-only — pipeline runs even if both groups present', async () => {
    authState.groups = ['admin', 'read_only'];
    mockApi.system.diagnoseDocker.mockResolvedValueOnce({ state: 'not_installed' });
    render(<StartupGate>app-content</StartupGate>);

    await waitFor(() => {
      expect(mockApi.system.diagnoseDocker).toHaveBeenCalled();
    });
  });

  it('renders the app and skips the Docker pipeline for a read_only user', async () => {
    authState.groups = ['org:groovy', 'read_only'];
    render(<StartupGate>app-content</StartupGate>);

    // App content renders straight away (state === 'skipped').
    expect(await screen.findByText('app-content')).toBeInTheDocument();
    // The Kali/Docker pipeline never ran.
    expect(mockApi.system.diagnoseDocker).not.toHaveBeenCalled();
  });
});
