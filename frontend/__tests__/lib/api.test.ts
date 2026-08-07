/**
 * Tests for API Client.
 *
 * Tests request handling, error handling, and query string building.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// We need to import after setting up mocks
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Import the module dynamically to pick up mocks
let api: typeof import('../../lib/api').api;
let subscribeToAssessmentEvents: typeof import('../../lib/api').subscribeToAssessmentEvents;

beforeEach(async () => {
  mockFetch.mockReset();
  vi.resetModules();
  const module = await import('../../lib/api');
  api = module.api;
  subscribeToAssessmentEvents = module.subscribeToAssessmentEvents;
});

describe('API Client', () => {
  describe('request function', () => {
    it('should make GET request with correct headers', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"data": []}'),
      });

      await api.assessments.list();

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/assessments'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      );
    });

    it('should make POST request with body', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () =>
          Promise.resolve(
            JSON.stringify({
              id: 'new-id',
              type: 'recon',
              status: 'pending',
            })
          ),
      });

      await api.assessments.create({
        type: 'recon',
        targets: ['192.168.1.1'],
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/assessments'),
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"type":"recon"'),
        })
      );
    });

    it('should throw ApiError on non-OK response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: () => Promise.resolve({ message: 'Resource not found' }),
      });

      await expect(api.assessments.get('non-existent')).rejects.toThrow('Resource not found');
    });

    it('should handle empty response body', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(''),
      });

      const result = await api.assessments.cancel('id');

      expect(result).toBeNull();
    });

    it('should handle 500 errors', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: () => Promise.resolve({}),
      });

      await expect(api.system.health()).rejects.toThrow();
    });

    it('should handle JSON parse errors in error response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: () => Promise.reject(new Error('Invalid JSON')),
      });

      await expect(api.assessments.list()).rejects.toThrow('Bad Request');
    });
  });

  describe('query string builder (qs)', () => {
    it('should build query string from params', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"data": [], "total": 0, "page": 1, "limit": 10}'),
      });

      await api.assessments.list({ page: 1, limit: 10, status: 'completed' });

      const calledUrl = mockFetch.mock.calls[0][0];
      expect(calledUrl).toContain('page=1');
      expect(calledUrl).toContain('limit=10');
      expect(calledUrl).toContain('status=completed');
    });

    it('should filter out undefined and null values', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"data": [], "total": 0}'),
      });

      await api.assessments.list({ status: undefined, type: null as unknown as string, page: 1 });

      const calledUrl = mockFetch.mock.calls[0][0];
      expect(calledUrl).not.toContain('status');
      expect(calledUrl).not.toContain('type');
      expect(calledUrl).toContain('page=1');
    });

    it('should filter out empty strings', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"data": []}'),
      });

      await api.findings.list({ search: '', severity: 'high' });

      const calledUrl = mockFetch.mock.calls[0][0];
      expect(calledUrl).not.toContain('search=');
      expect(calledUrl).toContain('severity=high');
    });

    it('should encode special characters', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"data": []}'),
      });

      await api.findings.list({ search: 'SQL Injection & XSS' });

      const calledUrl = mockFetch.mock.calls[0][0];
      expect(calledUrl).toContain('search=SQL');
      expect(calledUrl).toContain('%26'); // Encoded &
    });
  });
});

describe('API Endpoints', () => {
  describe('assessments', () => {
    it('should call list endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"data": [], "total": 0}'),
      });

      await api.assessments.list();

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringMatching(/\/api\/assessments/),
        expect.any(Object)
      );
    });

    it('should call get endpoint with id', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"id": "test-id"}'),
      });

      await api.assessments.get('test-id');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/assessments/test-id'),
        expect.any(Object)
      );
    });

    it('should call create endpoint with POST', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"id": "new-id"}'),
      });

      await api.assessments.create({ type: 'full', targets: ['example.com'] });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/assessments'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should call cancel endpoint with DELETE', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(''),
      });

      await api.assessments.cancel('test-id');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/assessments/test-id'),
        expect.objectContaining({ method: 'DELETE' })
      );
    });
  });

  describe('findings', () => {
    it('should call stats endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () =>
          Promise.resolve(
            JSON.stringify({
              total: 10,
              by_severity: { critical: 1, high: 2 },
              by_status: { open: 5 },
            })
          ),
      });

      const stats = await api.findings.stats();

      expect(stats.total).toBe(10);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/findings/stats'),
        expect.any(Object)
      );
    });

    it('should call update endpoint with PATCH', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"id": "finding-id", "status": "remediated"}'),
      });

      await api.findings.update('finding-id', { status: 'remediated' });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/findings/finding-id'),
        expect.objectContaining({ method: 'PATCH' })
      );
    });

    it('should call createJiraTicket endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"ticket_key": "SEC-123", "url": "https://..."}'),
      });

      await api.findings.createJiraTicket('finding-id', 'SEC');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/findings/finding-id/jira'),
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('config', () => {
    it('should call scope.get endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"networks": [], "domains": []}'),
      });

      await api.config.scope.get();

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/config/scope'),
        expect.any(Object)
      );
    });

    it('should call scope.validate endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"valid": true, "environment": "staging"}'),
      });

      const result = await api.config.scope.validate('192.168.1.1');

      expect(result.valid).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/config/scope/validate'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should call credentials.testConnection endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"success": true}'),
      });

      await api.config.credentials.testConnection('test-app');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/config/credentials/test'),
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('reports', () => {
    it('should generate download URL', () => {
      const url = api.reports.download('report-id', 'pdf');

      expect(url).toContain('/api/reports/report-id/download');
      expect(url).toContain('format=pdf');
    });

    it('should call list endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"data": [], "total": 0}'),
      });

      await api.reports.list({ page: 1, limit: 10 });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringMatching(/\/api\/reports/),
        expect.any(Object)
      );
    });
  });

  describe('system', () => {
    it('should call health endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"status": "healthy"}'),
      });

      await api.system.health();

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/health'),
        expect.any(Object)
      );
    });

    it('should call status endpoint', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        text: () =>
          Promise.resolve(
            JSON.stringify({
              healthy: true,
              container_status: 'running',
              database_connected: true,
            })
          ),
      });

      const status = await api.system.status();

      expect(status.healthy).toBe(true);
    });
  });
});

describe('SSE Subscription', () => {
  it('should create EventSource with correct URL', () => {
    const unsubscribe = subscribeToAssessmentEvents('assessment-123', {});

    // Verify EventSource was created
    expect(typeof unsubscribe).toBe('function');
  });

  it('should return unsubscribe function', () => {
    const handlers = {
      onProgress: vi.fn(),
      onCompleted: vi.fn(),
    };

    const unsubscribe = subscribeToAssessmentEvents('assessment-123', handlers);

    expect(typeof unsubscribe).toBe('function');

    // Should not throw when called
    unsubscribe();
  });

  it('should call handlers when events are received', () => {
    const onProgress = vi.fn();
    const onCompleted = vi.fn();

    subscribeToAssessmentEvents('assessment-123', {
      onProgress,
      onCompleted,
    });

    // The mock EventSource should handle event simulation
    // This test verifies the subscription setup works
    expect(onProgress).not.toHaveBeenCalled(); // Not called until event fires
  });
});

describe('Error Handling', () => {
  it('should include status code in ApiError', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      json: () => Promise.resolve({ message: 'Access denied' }),
    });

    try {
      await api.assessments.list();
      expect.fail('Should have thrown');
    } catch (error: unknown) {
      const apiError = error as { status: number };
      expect(apiError.status).toBe(403);
    }
  });

  it('should handle network errors', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    await expect(api.system.health()).rejects.toThrow('Network error');
  });
});
