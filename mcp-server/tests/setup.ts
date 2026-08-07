/**
 * Jest global test setup.
 *
 * Configures mocks and global test utilities.
 */

// Increase timeout for async operations
jest.setTimeout(10000);

// Mock console.log/warn in tests to reduce noise
const originalConsole = { ...console };

beforeAll(() => {
  // Suppress console output during tests unless DEBUG is set
  if (!process.env.DEBUG) {
    console.log = jest.fn();
    console.warn = jest.fn();
  }
});

afterAll(() => {
  // Restore console
  console.log = originalConsole.log;
  console.warn = originalConsole.warn;
});

// Clean up mocks after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Export helper for creating mock functions
export function createMockFn<T extends (...args: unknown[]) => unknown>(): jest.MockedFunction<T> {
  return jest.fn() as unknown as jest.MockedFunction<T>;
}
