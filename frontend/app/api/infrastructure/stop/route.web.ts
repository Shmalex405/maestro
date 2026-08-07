import { requireLicense } from '@/lib/license-guard';
import { stopInstance } from '@/lib/aws-infra';

// This route file uses the .web.ts extension so it is only included in
// standalone (web) builds and excluded from static export (desktop) builds.

export async function POST() {
  const guard = await requireLicense();
  if (!guard.ok) return guard.response;

  const { config } = guard;
  if (!config.aws) {
    return Response.json({ error: 'Infrastructure not provisioned' }, { status: 404 });
  }

  try {
    await stopInstance(config.aws.roleArn, config.aws.region, config.aws.instanceId);
    return Response.json({ success: true, message: 'Instance stopping' });
  } catch (error: any) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
