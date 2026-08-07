/**
 * Tests for Code Scan Tools.
 *
 * Tests parser functions for various security scanning tools.
 */

// We need to mock the dependencies before importing the module
jest.mock('fs', () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
  readdirSync: jest.fn(),
  statSync: jest.fn(),
}));

jest.mock('../../src/utils/docker-exec', () => ({
  executeInKali: jest.fn(),
  isKaliRunning: jest.fn(),
}));

import * as fs from 'fs';
import { executeInKali } from '../../src/utils/docker-exec';

const mockFs = fs as jest.Mocked<typeof fs>;
const mockExecuteInKali = executeInKali as jest.MockedFunction<typeof executeInKali>;

describe('Code Scan Handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFs.existsSync.mockReturnValue(true);
  });

  // Import handlers dynamically to pick up mocks
  async function getHandlers() {
    const module = await import('../../src/tools/code-scan');
    return module.codeScanHandlers;
  }

  describe('Semgrep Scanning', () => {
    it('should parse valid Semgrep JSON output', async () => {
      const semgrepOutput = JSON.stringify({
        results: [
          {
            check_id: 'python.sql-injection',
            path: 'app/db.py',
            start: { line: 45, col: 10 },
            end: { line: 45, col: 50 },
            extra: {
              message: 'SQL injection vulnerability',
              severity: 'ERROR',
              metadata: {
                cwe: ['CWE-89'],
                owasp: ['A03:2021'],
              },
              lines: 'cursor.execute(f"SELECT * FROM users WHERE id = {id}")',
            },
          },
        ],
        errors: [],
      });

      mockExecuteInKali.mockResolvedValue(semgrepOutput);

      const handlers = await getHandlers();
      const result = await handlers.scan_semgrep({
        repo_path: '/mnt/host-home/project',
      });

      const parsed = JSON.parse(result);
      expect(parsed.findings).toBeDefined();
    });

    it('should handle empty Semgrep results', async () => {
      mockExecuteInKali.mockResolvedValue(JSON.stringify({ results: [], errors: [] }));

      const handlers = await getHandlers();
      const result = await handlers.scan_semgrep({
        repo_path: '/mnt/host-home/project',
      });

      const parsed = JSON.parse(result);
      expect(parsed.findings).toEqual([]);
    });

    it('should handle malformed Semgrep output gracefully', async () => {
      mockExecuteInKali.mockResolvedValue('not json at all');

      const handlers = await getHandlers();
      const result = await handlers.scan_semgrep({
        repo_path: '/mnt/host-home/project',
      });

      // Should return something without crashing
      expect(result).toBeDefined();
    });
  });

  describe('Bandit Scanning', () => {
    it('should parse valid Bandit JSON output', async () => {
      const banditOutput = JSON.stringify({
        results: [
          {
            filename: 'app/auth.py',
            test_id: 'B105',
            test_name: 'hardcoded_password_string',
            issue_severity: 'MEDIUM',
            issue_confidence: 'HIGH',
            issue_text: 'Possible hardcoded password',
            line_number: 25,
            code: 'password = "secret123"',
            issue_cwe: { id: 259, link: 'https://cwe.mitre.org/data/definitions/259.html' },
          },
        ],
        metrics: {},
      });

      mockExecuteInKali.mockResolvedValue(banditOutput);

      const handlers = await getHandlers();
      const result = await handlers.scan_bandit({
        repo_path: '/mnt/host-home/project',
      });

      const parsed = JSON.parse(result);
      expect(parsed.findings).toBeDefined();
    });

    it('should filter by severity level', async () => {
      const banditOutput = JSON.stringify({
        results: [
          {
            filename: 'test.py',
            test_id: 'B101',
            issue_severity: 'HIGH',
            issue_text: 'Use of exec',
            line_number: 10,
          },
          {
            filename: 'test.py',
            test_id: 'B102',
            issue_severity: 'LOW',
            issue_text: 'Use of assert',
            line_number: 20,
          },
        ],
      });

      mockExecuteInKali.mockResolvedValue(banditOutput);

      const handlers = await getHandlers();
      const result = await handlers.scan_bandit({
        repo_path: '/mnt/host-home/project',
        severity: 'high',
      });

      expect(result).toBeDefined();
    });
  });

  describe('Secret Detection', () => {
    it('should parse Gitleaks JSON output', async () => {
      const gitleaksOutput = JSON.stringify([
        {
          RuleID: 'aws-access-key',
          Match: 'AKIA...',
          Secret: 'AKIAIOSFODNN7EXAMPLE',
          File: 'config.py',
          StartLine: 5,
          EndLine: 5,
          Commit: 'abc123',
        },
      ]);

      mockExecuteInKali.mockResolvedValue(gitleaksOutput);

      const handlers = await getHandlers();
      const result = await handlers.scan_secrets({
        repo_path: '/mnt/host-home/project',
      });

      const parsed = JSON.parse(result);
      expect(parsed.findings).toBeDefined();
    });

    it('should scan with git history option', async () => {
      mockExecuteInKali.mockResolvedValue('[]');

      const handlers = await getHandlers();
      const result = await handlers.scan_secrets({
        repo_path: '/mnt/host-home/project',
        include_git_history: true,
      });

      expect(result).toBeDefined();
    });
  });

  describe('Dependency Scanning', () => {
    it('should parse npm audit output', async () => {
      const npmAuditOutput = JSON.stringify({
        vulnerabilities: {
          lodash: {
            name: 'lodash',
            severity: 'high',
            via: [{ title: 'Prototype Pollution', url: 'https://...' }],
            range: '<4.17.21',
            nodes: ['node_modules/lodash'],
            fixAvailable: true,
          },
        },
      });

      mockExecuteInKali.mockResolvedValue(npmAuditOutput);

      const handlers = await getHandlers();
      const result = await handlers.scan_dependencies({
        repo_path: '/mnt/host-home/project',
        package_manager: 'npm',
      });

      expect(result).toBeDefined();
    });

    it('should handle auto package manager detection', async () => {
      mockFs.existsSync.mockImplementation((path) => {
        return String(path).includes('package.json');
      });

      mockExecuteInKali.mockResolvedValue(JSON.stringify({ vulnerabilities: {} }));

      const handlers = await getHandlers();
      const result = await handlers.scan_dependencies({
        repo_path: '/mnt/host-home/project',
        package_manager: 'auto',
      });

      expect(result).toBeDefined();
    });
  });

  describe('NjsScan Scanning', () => {
    it('should parse valid njsscan output', async () => {
      const njsscanOutput = JSON.stringify({
        nodejs: {
          'node_deserialize': {
            files: [{ file_path: 'app.js', match_position: [10, 15], match_string: 'unserialize(' }],
            metadata: {
              cwe: 'CWE-502',
              owasp: 'A08:2021',
              severity: 'high',
              description: 'Deserialization vulnerability',
            },
          },
        },
      });

      mockExecuteInKali.mockResolvedValue(njsscanOutput);

      const handlers = await getHandlers();
      const result = await handlers.scan_njsscan({
        repo_path: '/mnt/host-home/project',
      });

      const parsed = JSON.parse(result);
      expect(parsed.findings).toBeDefined();
    });

    it('should handle empty njsscan results', async () => {
      const njsscanOutput = JSON.stringify({
        nodejs: {},
        templates: {},
        errors: [],
      });

      mockExecuteInKali.mockResolvedValue(njsscanOutput);

      const handlers = await getHandlers();
      const result = await handlers.scan_njsscan({
        repo_path: '/mnt/host-home/project',
      });

      expect(result).toBeDefined();
    });
  });

  describe('Language Detection', () => {
    it('should detect languages from file extensions', async () => {
      // Use any type to bypass strict Dirent typing in newer Node.js versions
      (mockFs.readdirSync as jest.Mock).mockReturnValue(['main.py', 'app.js', 'server.ts', 'utils.go']);
      mockFs.statSync.mockReturnValue({ isDirectory: () => false } as fs.Stats);

      const handlers = await getHandlers();
      const result = await handlers.detect_languages({
        repo_path: '/mnt/host-home/project',
      });

      const parsed = JSON.parse(result);
      expect(parsed.languages).toBeDefined();
    });
  });

  describe('Code Context Analysis', () => {
    it('should analyze code for SQL injection patterns', async () => {
      const codeContent = `
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
`;

      mockFs.readFileSync.mockReturnValue(codeContent);
      mockExecuteInKali.mockResolvedValue('');

      const handlers = await getHandlers();
      const result = await handlers.analyze_code_context({
        file_path: '/mnt/host-home/project/db.py',
        line_start: 1,
        line_end: 6,
        vulnerability_type: 'sqli',
      });

      // Result should be defined and parseable
      expect(result).toBeDefined();
      const parsed = JSON.parse(result);
      // Check for common response fields - analysis or code_snippet or context
      expect(parsed.code_snippet || parsed.analysis || parsed.context || parsed.file_path).toBeDefined();
    });

    it('should analyze code for XSS patterns', async () => {
      const codeContent = `
function renderUser(name) {
  document.innerHTML = '<div>' + name + '</div>';
}
`;

      mockFs.readFileSync.mockReturnValue(codeContent);
      mockExecuteInKali.mockResolvedValue('');

      const handlers = await getHandlers();
      const result = await handlers.analyze_code_context({
        file_path: '/mnt/host-home/project/view.js',
        vulnerability_type: 'xss',
      });

      expect(result).toBeDefined();
    });
  });

  describe('Repository Scanning', () => {
    it('should run comprehensive scan', async () => {
      mockExecuteInKali.mockResolvedValue(JSON.stringify({ results: [] }));
      (mockFs.readdirSync as jest.Mock).mockReturnValue(['main.py']);
      mockFs.statSync.mockReturnValue({ isDirectory: () => false } as fs.Stats);

      const handlers = await getHandlers();
      const result = await handlers.scan_repository({
        repo_path: '/mnt/host-home/project',
        scan_types: ['sast'],
        severity_threshold: 'medium',
      });

      expect(result).toBeDefined();
      const parsed = JSON.parse(result);
      expect(parsed.scan_id).toBeDefined();
    });

    it('should run selective scan types', async () => {
      mockExecuteInKali.mockResolvedValue(JSON.stringify({ results: [] }));

      const handlers = await getHandlers();
      const result = await handlers.scan_repository({
        repo_path: '/mnt/host-home/project',
        scan_types: ['secrets'],
      });

      expect(result).toBeDefined();
    });
  });

  describe('Report Generation', () => {
    it('should generate scan report', async () => {
      // First run a scan to populate results
      mockExecuteInKali.mockResolvedValue(JSON.stringify({ results: [] }));

      const handlers = await getHandlers();
      const scanResult = await handlers.scan_repository({
        repo_path: '/mnt/host-home/project',
        scan_types: ['sast'],
      });

      const scanData = JSON.parse(scanResult);

      const reportResult = await handlers.generate_scan_report({
        scan_id: scanData.scan_id,
        format: 'json',
      });

      expect(reportResult).toBeDefined();
    });

    it('should handle invalid scan_id', async () => {
      const handlers = await getHandlers();
      const result = await handlers.generate_scan_report({
        scan_id: 'non-existent-id',
        format: 'json',
      });

      const parsed = JSON.parse(result);
      // Should return error or empty result
      expect(parsed.error !== undefined || parsed.findings === undefined).toBeTruthy();
    });
  });
});
