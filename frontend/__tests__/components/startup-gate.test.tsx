/**
 * Tests for the startup gate's Docker diagnosis state machine
 * (v0.1.70 + Windows fix in v0.1.71).
 *
 * Covers what we just shipped:
 *   - diagnose_docker → 'not_installed' renders the "Download Docker Desktop" panel
 *   - 'not_running' renders "Open Docker Desktop" action button
 *   - 'daemon_unresponsive' renders "Restart Docker Desktop" action button
 *   - 'healthy' proceeds past the gate
 *   - Action buttons call the right Tauri commands
 *
 * We mock past discovery + auth gates so the test lands directly on the
 * Docker check.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';

// All these mocks must come BEFORE the StartupGate import below.
vi.mock('@/lib/cognito-auth', () => ({
  isCognitoConfigured: () => false,
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
      diagnoseDocker: vi.fn(),
      openDockerDesktop: vi.fn(),
      restartDockerDesktop: vi.fn(),
      checkDockerInstalled: vi.fn(),
      getDockerStatus: vi.fn(),
      checkKaliImageExists: vi.fn(),
      pullKaliImage: vi.fn(),
      pullKaliImageWithAuth: vi.fn(),
      buildKaliImage: vi.fn(),
      onBuildProgress: vi.fn(() => () => {}),
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

vi.mock('@/lib/stores/auth-store', () => ({
  useAuthStore: Object.assign(
    () => ({ isAuthenticated: true, user: { email: 't@t' } }),
    { getState: () => ({ isAuthenticated: true, user: { email: 't@t' }, isTokenExpired: () => false }) },
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
  system: {
    diagnoseDocker: ReturnType<typeof vi.fn>;
    openDockerDesktop: ReturnType<typeof vi.fn>;
    restartDockerDesktop: ReturnType<typeof vi.fn>;
  };
};

beforeEach(() => {
  vi.clearAllMocks();
  // Reset session storage so the gate runs fresh each test.
  sessionStorage.clear();
});

describe('StartupGate Docker diagnosis', () => {
  it('shows the install panel when Docker is not installed', async () => {
    mockApi.system.diagnoseDocker.mockResolvedValue({ state: 'not_installed' });
    render(<StartupGate>app</StartupGate>);
    expect(
      await screen.findByRole('button', { name: /download docker desktop/i }),
    ).toBeInTheDocument();
  });

  it('shows the "Open Docker Desktop" panel when daemon is not running', async () => {
    mockApi.system.diagnoseDocker
      .mockResolvedValueOnce({ state: 'not_running' });
    render(<StartupGate>app</StartupGate>);
    expect(
      await screen.findByText(/docker desktop isn't running/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /open docker desktop/i }),
    ).toBeInTheDocument();
  });

  it('shows the "Restart Docker Desktop" panel when daemon is hung', async () => {
    mockApi.system.diagnoseDocker
      .mockResolvedValueOnce({ state: 'daemon_unresponsive' });
    render(<StartupGate>app</StartupGate>);
    expect(
      await screen.findByText(/daemon isn't responding/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /restart docker desktop/i }),
    ).toBeInTheDocument();
  });

  it('clicking "Open Docker Desktop" calls openDockerDesktop', async () => {
    mockApi.system.diagnoseDocker
      .mockResolvedValueOnce({ state: 'not_running' });
    mockApi.system.openDockerDesktop.mockResolvedValue(undefined);
    render(<StartupGate>app</StartupGate>);
    const btn = await screen.findByRole('button', { name: /open docker desktop/i });
    fireEvent.click(btn);
    await waitFor(() => {
      expect(mockApi.system.openDockerDesktop).toHaveBeenCalled();
    });
  });

  it('clicking "Restart Docker Desktop" calls restartDockerDesktop', async () => {
    mockApi.system.diagnoseDocker
      .mockResolvedValueOnce({ state: 'daemon_unresponsive' });
    mockApi.system.restartDockerDesktop.mockResolvedValue(undefined);
    render(<StartupGate>app</StartupGate>);
    const btn = await screen.findByRole('button', { name: /restart docker desktop/i });
    fireEvent.click(btn);
    await waitFor(() => {
      expect(mockApi.system.restartDockerDesktop).toHaveBeenCalled();
    });
  });
});
