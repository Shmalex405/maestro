import { auth } from '@/lib/auth';
import { checkLicense, type CustomerConfig } from '@/lib/customer-registry';

/**
 * Checks auth + license in one call. Returns the customer config if valid,
 * or a Response to return early if not.
 */
export async function requireLicense(): Promise<
  { ok: true; email: string; config: CustomerConfig } | { ok: false; response: Response }
> {
  const session = await auth();
  if (!session?.user?.email) {
    return {
      ok: false,
      response: Response.json({ error: 'Unauthorized' }, { status: 401 }),
    };
  }

  const result = await checkLicense(session.user.email);

  if (!result.valid) {
    const messages: Record<string, string> = {
      expired: 'Your license has expired. Please contact sales to renew.',
      suspended: 'Your account has been suspended. Please contact support.',
      no_license: 'No active license found for your organization.',
      not_found: 'Your organization was not found. Please contact support.',
    };
    return {
      ok: false,
      response: Response.json(
        { error: 'LICENSE_INVALID', reason: result.reason, message: messages[result.reason!] },
        { status: 403 }
      ),
    };
  }

  return { ok: true, email: session.user.email, config: result.config! };
}
