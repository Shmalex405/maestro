import { requireLicense } from '@/lib/license-guard';

// This route file uses the .web.ts extension so it is only included in
// standalone (web) builds and excluded from static export (desktop) builds.

export async function GET() {
  const guard = await requireLicense();
  if (!guard.ok) return guard.response;

  const { config } = guard;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${config.backendUrl}/health`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (response.ok) {
      const data = await response.json();
      return Response.json({ healthy: true, ...data });
    }
    return Response.json({ healthy: false });
  } catch {
    return Response.json({ healthy: false });
  }
}
