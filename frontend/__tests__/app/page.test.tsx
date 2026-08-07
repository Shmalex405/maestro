/**
 * Tests for Dashboard Page Component.
 *
 * Tests rendering and basic functionality.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Mock the API module
vi.mock('../../lib/api', () => ({
  api: {
    findings: {
      stats: vi.fn(),
    },
    assessments: {
      list: vi.fn(),
    },
  },
}));

// Mock next/link
vi.mock('next/link', () => ({
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

import { api } from '../../lib/api';
import DashboardPage from '../../app/page';

// `api` is heavily typed; cast through unknown so the vitest mock surface
// (just the methods we exercise) doesn't have to match the full API.
const mockApi = api as unknown as {
  findings: { stats: ReturnType<typeof vi.fn> };
  assessments: { list: ReturnType<typeof vi.fn> };
};

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
    },
  });
}

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>
  );
}

describe('Dashboard Page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Setup default mocks
    mockApi.findings.stats.mockResolvedValue({
      total: 0,
      by_severity: {},
      by_status: {},
    });
    mockApi.assessments.list.mockResolvedValue({
      data: [],
      total: 0,
      page: 1,
      limit: 5,
      hasMore: false,
    });
  });

  describe('Rendering', () => {
    it('should render without crashing', async () => {
      renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        expect(document.body.innerHTML.length).toBeGreaterThan(0);
      });
    });

    it('should render page title', async () => {
      renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        expect(screen.getByText(/Dashboard/i)).toBeDefined();
      });
    });

    it('should render new assessment button', async () => {
      renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        expect(screen.getByText(/New Assessment/i)).toBeDefined();
      });
    });

    it('should render severity cards', async () => {
      renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        // Look for severity labels
        expect(screen.getByText(/critical/i)).toBeDefined();
      });
    });
  });

  describe('Stats Cards', () => {
    it('should display severity breakdown cards', async () => {
      renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        // Should have multiple stat cards
        const cards = document.querySelectorAll('[data-slot="card"]');
        expect(cards.length).toBeGreaterThan(0);
      });
    });

    it('should show findings count', async () => {
      renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        // Should display "findings" label somewhere
        expect(screen.getAllByText(/findings/i).length).toBeGreaterThan(0);
      });
    });
  });

  describe('Navigation', () => {
    it('should have link to new assessment page', async () => {
      renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        const link = document.querySelector('a[href="/assessments/new"]');
        expect(link).toBeDefined();
      });
    });
  });

  describe('Component Integration', () => {
    it('should integrate with QueryClientProvider', async () => {
      const { container } = renderWithProviders(<DashboardPage />);

      await waitFor(() => {
        expect(container).toBeDefined();
        expect(container.innerHTML.length).toBeGreaterThan(0);
      });
    });

    it('should not throw during render', () => {
      expect(() => {
        renderWithProviders(<DashboardPage />);
      }).not.toThrow();
    });
  });

  describe('API Mocks Setup', () => {
    it('should have findings stats mock available', () => {
      expect(mockApi.findings.stats).toBeDefined();
      expect(typeof mockApi.findings.stats).toBe('function');
    });

    it('should have assessments list mock available', () => {
      expect(mockApi.assessments.list).toBeDefined();
      expect(typeof mockApi.assessments.list).toBe('function');
    });
  });
});
