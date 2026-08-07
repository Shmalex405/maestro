import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import {
  EC2Client,
  DescribeInstancesCommand,
  StartInstancesCommand,
  StopInstancesCommand,
} from '@aws-sdk/client-ec2';

// Simple credential cache (10-min TTL)
const credentialCache = new Map<
  string,
  { credentials: { accessKeyId: string; secretAccessKey: string; sessionToken: string }; expiry: number }
>();

export async function getEC2Client(roleArn: string, region: string): Promise<EC2Client> {
  const cacheKey = `${roleArn}:${region}`;
  const cached = credentialCache.get(cacheKey);
  if (cached && cached.expiry > Date.now()) {
    return new EC2Client({ region, credentials: cached.credentials });
  }

  const sts = new STSClient({ region });
  const assumed = await sts.send(
    new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: `maestro-platform-${Date.now()}`,
      DurationSeconds: 900,
      ExternalId: 'maestro-prod', // Must match customer's trust policy
    })
  );

  const credentials = {
    accessKeyId: assumed.Credentials!.AccessKeyId!,
    secretAccessKey: assumed.Credentials!.SecretAccessKey!,
    sessionToken: assumed.Credentials!.SessionToken!,
  };

  credentialCache.set(cacheKey, { credentials, expiry: Date.now() + 10 * 60 * 1000 });
  return new EC2Client({ region, credentials });
}

export interface InstanceState {
  state: 'running' | 'stopped' | 'pending' | 'stopping' | 'terminated' | 'shutting-down' | 'not_found';
  instanceId: string;
  instanceType?: string;
  publicIp?: string;
}

export async function getInstanceState(
  roleArn: string,
  region: string,
  instanceId: string
): Promise<InstanceState> {
  const ec2 = await getEC2Client(roleArn, region);
  const result = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
  const instance = result.Reservations?.[0]?.Instances?.[0];
  if (!instance) return { state: 'not_found', instanceId };
  return {
    state: (instance.State?.Name as InstanceState['state']) || 'not_found',
    instanceId,
    instanceType: instance.InstanceType,
    publicIp: instance.PublicIpAddress,
  };
}

export async function startInstance(roleArn: string, region: string, instanceId: string): Promise<void> {
  const ec2 = await getEC2Client(roleArn, region);
  await ec2.send(new StartInstancesCommand({ InstanceIds: [instanceId] }));
}

export async function stopInstance(roleArn: string, region: string, instanceId: string): Promise<void> {
  const ec2 = await getEC2Client(roleArn, region);
  await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] }));
}
