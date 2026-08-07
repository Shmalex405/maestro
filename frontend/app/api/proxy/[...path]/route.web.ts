import { requireLicense } from '@/lib/license-guard';
import { NextRequest } from 'next/server';

// This route file uses the .web.ts extension so it is only included in
// standalone (web) builds and excluded from static export (desktop) builds.

async function proxyRequest(req: NextRequest, params: { path: string[] }) {
  const guard = await requireLicense();
  if (!guard.ok) return guard.response;

  const { config } = guard;
  const path = params.path.join('/');

  // Reconstruct the target URL
  const url = new URL(req.url);
  const targetUrl = `${config.backendUrl}/api/${path}${url.search}`;

  // Forward the request
  const headers: Record<string, string> = {
    'Content-Type': req.headers.get('content-type') || 'application/json',
  };

  const fetchOptions: RequestInit = {
    method: req.method,
    headers,
  };

  // Include body for non-GET requests
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    fetchOptions.body = await req.text();
  }

  try {
    const response = await fetch(targetUrl, fetchOptions);

    // Handle SSE streaming
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('text/event-stream')) {
      return new Response(response.body, {
        status: response.status,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });
    }

    // Regular response
    const body = await response.text();
    return new Response(body, {
      status: response.status,
      headers: { 'Content-Type': contentType || 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Backend unreachable' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export async function GET(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await context.params);
}
export async function POST(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await context.params);
}
export async function PUT(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await context.params);
}
export async function PATCH(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await context.params);
}
export async function DELETE(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, await context.params);
}
