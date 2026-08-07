/**
 * Tests for Docker Execution Utilities.
 *
 * Tests command execution in Kali container.
 * Note: These tests mock dockerode at the module level.
 */

// Create mock container before jest.mock
const mockExec = jest.fn();
const mockInspect = jest.fn();
const mockGetContainer = jest.fn(() => ({
  exec: mockExec,
  inspect: mockInspect,
}));

// Mock dockerode - must be before imports. `modem.demuxStream` forwards the raw
// stream's data to the stdout PassThrough, mirroring dockerode's real behavior so
// executeViaDocker can accumulate output under test.
jest.mock('dockerode', () => {
  return jest.fn().mockImplementation(() => ({
    getContainer: mockGetContainer,
    modem: {
      demuxStream: (stream: { on: (e: string, cb: (c?: Buffer) => void) => void }, stdout: NodeJS.WritableStream) => {
        stream.on('data', (chunk?: Buffer) => {
          if (chunk) stdout.write(chunk);
        });
      },
    },
  }));
});

import { executeInKali, executeInKaliDetailed, isKaliRunning } from '../../src/utils/docker-exec';

// Helper to create mock stream
interface MockStream {
  on: jest.Mock;
}

function createMockStream(handlers: {
  data?: Buffer[];
  error?: Error;
  end?: boolean;
}): MockStream {
  const stream: MockStream = {
    on: jest.fn((event: string, callback: (arg?: unknown) => void) => {
      if (event === 'data' && handlers.data) {
        handlers.data.forEach((chunk) => callback(chunk));
      }
      if (event === 'error' && handlers.error) {
        setTimeout(() => callback(handlers.error), 0);
      }
      if (event === 'end' && handlers.end !== false) {
        setTimeout(() => callback(), 0);
      }
      return stream;
    }),
  };
  return stream;
}

describe('Docker Execution', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset mock implementations
    mockGetContainer.mockReturnValue({
      exec: mockExec,
      inspect: mockInspect,
    });
  });

  describe('executeInKali', () => {
    it('should execute command and return output', async () => {
      const mockStream = createMockStream({
        data: [Buffer.from('command output')],
        end: true,
      });

      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
      });

      const result = await executeInKali('echo "hello"');

      expect(result).toBe('command output');
      expect(mockGetContainer).toHaveBeenCalledWith('kali-pentest');
    });

    it('should pass command to bash', async () => {
      const mockStream = createMockStream({ end: true });

      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
      });

      await executeInKali('nmap -sV 192.168.1.1');

      expect(mockExec).toHaveBeenCalledWith({
        Cmd: ['bash', '-c', 'nmap -sV 192.168.1.1'],
        AttachStdout: true,
        AttachStderr: true,
      });
    });

    it('should handle execution errors', async () => {
      mockExec.mockRejectedValue(new Error('Container not running'));

      await expect(executeInKali('echo test')).rejects.toThrow('Container not running');
    });

    it('should handle stream errors', async () => {
      const mockStream = createMockStream({
        error: new Error('Stream error'),
        end: false,
      });

      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
      });

      await expect(executeInKali('test')).rejects.toThrow('Stream error');
    });

    it('should handle no stream returned', async () => {
      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: undefined) => void) => {
          callback(null, undefined);
        },
      });

      await expect(executeInKali('test')).rejects.toThrow('No stream returned');
    });

    it('should handle exec start error', async () => {
      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: null) => void) => {
          callback(new Error('Exec start failed'), null);
        },
      });

      await expect(executeInKali('test')).rejects.toThrow('Exec start failed');
    });

    it('should accumulate multiple data chunks', async () => {
      const mockStream = createMockStream({
        data: [Buffer.from('chunk1'), Buffer.from('chunk2'), Buffer.from('chunk3')],
        end: true,
      });

      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
      });

      const result = await executeInKali('cat largefile');

      expect(result).toBe('chunk1chunk2chunk3');
    });
  });

  describe('executeInKaliDetailed (provenance: exit codes)', () => {
    it('captures the real exit code from exec.inspect()', async () => {
      const mockStream = createMockStream({ data: [Buffer.from('boom')], end: true });
      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
        inspect: jest.fn().mockResolvedValue({ ExitCode: 7 }),
      });

      const result = await executeInKaliDetailed('exit 7');

      expect(result.exitCode).toBe(7);
      expect(result.stdout).toBe('boom');
    });

    it('reports exit code 0 for a clean run', async () => {
      const mockStream = createMockStream({ data: [Buffer.from('ok')], end: true });
      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
        inspect: jest.fn().mockResolvedValue({ ExitCode: 0 }),
      });

      const result = await executeInKaliDetailed('true');

      expect(result.exitCode).toBe(0);
    });

    it('falls back to null exit code when inspect is unavailable', async () => {
      const mockStream = createMockStream({ data: [Buffer.from('x')], end: true });
      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
        // no inspect method — must not throw, just yields null
      });

      const result = await executeInKaliDetailed('echo x');

      expect(result.exitCode).toBeNull();
      expect(result.stdout).toBe('x');
    });
  });

  describe('executeInKaliDetailed (non-destructive backstop)', () => {
    it('refuses a catastrophic command without ever executing it', async () => {
      const result = await executeInKaliDetailed('rm -rf /');

      expect(result.exitCode).toBe(126);
      expect(result.stderr).toContain('DESTRUCTIVE_BLOCKED');
      expect(mockExec).not.toHaveBeenCalled();
    });

    it('lets a normal scan command through to exec', async () => {
      const mockStream = createMockStream({ data: [Buffer.from('ok')], end: true });
      mockExec.mockResolvedValue({
        start: (_opts: unknown, callback: (err: Error | null, stream: MockStream) => void) => {
          callback(null, mockStream);
        },
        inspect: jest.fn().mockResolvedValue({ ExitCode: 0 }),
      });

      const result = await executeInKaliDetailed('nmap -sV 10.0.0.1');

      expect(mockExec).toHaveBeenCalled();
      expect(result.exitCode).toBe(0);
    });
  });

  describe('isKaliRunning', () => {
    it('should return true when container is running', async () => {
      mockInspect.mockResolvedValue({
        State: {
          Running: true,
        },
      });

      const running = await isKaliRunning();

      expect(running).toBe(true);
      expect(mockGetContainer).toHaveBeenCalledWith('kali-pentest');
    });

    it('should return false when container is stopped', async () => {
      mockInspect.mockResolvedValue({
        State: {
          Running: false,
        },
      });

      const running = await isKaliRunning();

      expect(running).toBe(false);
    });

    it('should return false when container does not exist', async () => {
      mockInspect.mockRejectedValue(new Error('No such container'));

      const running = await isKaliRunning();

      expect(running).toBe(false);
    });

    it('should return false on any error', async () => {
      mockInspect.mockRejectedValue(new Error('Docker daemon not running'));

      const running = await isKaliRunning();

      expect(running).toBe(false);
    });
  });
});

describe('Container Name', () => {
  it('should use correct container name', async () => {
    mockInspect.mockResolvedValue({ State: { Running: true } });

    await isKaliRunning();

    // Verify the container name is 'kali-pentest'
    expect(mockGetContainer).toHaveBeenCalledWith('kali-pentest');
  });
});
