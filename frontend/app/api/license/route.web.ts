import { auth } from '@/lib/auth';
import { checkLicense } from '@/lib/customer-registry';

// Returns the current user's license status for frontend display.

export async function GET() {
  const session = await auth();
  if (!session?.user?.email) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const result = await checkLicense(session.user.email);

  if (!result.valid) {
    return Response.json({
      valid: false,
      reason: result.reason,
      customerName: null,
      tier: null,
      expiresAt: null,
    });
  }

  const { config } = result;
  return Response.json({
    valid: true,
    reason: null,
    customerName: config!.customerName,
    orgId: config!.orgId,
    tier: config!.license.tier,
    status: config!.license.status,
    expiresAt: config!.license.expiresAt,
    seats: config!.license.seats,
  });
}
