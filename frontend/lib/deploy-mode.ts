export type DeployMode = 'tauri' | 'web';

export function getDeployMode(): DeployMode {
  if (typeof window === 'undefined') {
    // Server-side: check env var
    return process.env.NEXT_PUBLIC_DEPLOY_MODE === 'web' ? 'web' : 'tauri';
  }
  // Client-side: check env var first, then runtime detection
  if (process.env.NEXT_PUBLIC_DEPLOY_MODE === 'web') return 'web';
  return (window as any).__TAURI_INTERNALS__ ? 'tauri' : 'web';
}

export function isWebMode(): boolean {
  return getDeployMode() === 'web';
}

export function isTauriMode(): boolean {
  return getDeployMode() === 'tauri';
}
