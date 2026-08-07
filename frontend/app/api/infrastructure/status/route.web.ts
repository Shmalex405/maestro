import { requireLicense } from '@/lib/license-guard';
import { getInstanceState } from '@/lib/aws-infra';

// This route file uses the .web.ts extension so it is only included in
// standalone (web) builds and excluded from static export (desktop) builds.

export async function GET() {
  const guard = await requireLicense();
  if (!guard.ok) return guard.response;

  const { config } = guard;
  if (!config.aws) {
    return Response.json({ state: 'not_provisioned', instanceId: null });
  }

  try {
    const state = await getInstanceState(config.aws.roleArn, config.aws.region, config.aws.instanceId);
    return Response.json(state);
  } catch (error: any) {
    return Response.json(
      { state: 'error', error: error.message, instanceId: config.aws.instanceId },
      { status: 500 }
    );
  }
}
