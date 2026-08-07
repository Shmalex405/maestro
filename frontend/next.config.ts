import type { NextConfig } from "next";
import { readFileSync } from 'fs';
import { join } from 'path';

const isWebBuild = process.env.NEXT_OUTPUT_MODE === 'standalone';

// Pull the desktop app version from tauri.conf.json so version-check.ts has
// the real bundled version. Falls back gracefully if the file is unreadable.
function readTauriVersion(): string {
  try {
    const raw = readFileSync(join(__dirname, 'src-tauri/tauri.conf.json'), 'utf-8');
    return JSON.parse(raw).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const nextConfig: NextConfig = {
  output: isWebBuild ? 'standalone' : 'export',
  images: {
    unoptimized: !isWebBuild,
  },
  trailingSlash: !isWebBuild,
  // In desktop (static export) mode, only compile standard .ts/.tsx files.
  // In web (standalone) mode, also compile .web.ts/.web.tsx files which contain API routes.
  pageExtensions: isWebBuild
    ? ['tsx', 'ts', 'jsx', 'js', 'web.tsx', 'web.ts']
    : ['tsx', 'ts', 'jsx', 'js'],
  env: {
    NEXT_PUBLIC_APP_VERSION: process.env.NEXT_PUBLIC_APP_VERSION ?? readTauriVersion(),
  },
};

export default nextConfig;
