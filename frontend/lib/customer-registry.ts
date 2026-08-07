import {
  SecretsManagerClient,
  ListSecretsCommand,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';

export interface LicenseInfo {
  status: 'active' | 'trial' | 'suspended' | 'expired';
  tier: 'starter' | 'professional' | 'enterprise';
  expiresAt: string; // ISO 8601 date
  seats: number;     // max users for this org
}

export interface CustomerConfig {
  backendUrl: string;
  customerName: string;
  orgId: string;
  license: LicenseInfo;
  aws?: {
    region: string;
    instanceId: string;
    roleArn: string;
  };
  /** OAST listener for the `oast` verification oracle. Written by the
   *  onboarding terraform into the org's registry secret. Absent when the org
   *  has no listener — the oracle then reports `oast_unavailable` and blind
   *  findings stay honest unverified candidates.
   *
   *  HOSTNAME ONLY, deliberately. The polling token is NOT stored here: this
   *  secret is read to answer the unauthenticated /api/discover, and a token
   *  that gates access to interaction data must not be reachable that way. */
  oast?: { server: string };
}

export interface LicenseCheckResult {
  valid: boolean;
  reason?: 'expired' | 'suspended' | 'no_license' | 'not_found';
  config?: CustomerConfig;
}

const DEFAULT_BACKEND = process.env.DEFAULT_BACKEND_URL || 'http://localhost:3001';

const DEFAULT_LICENSE: LicenseInfo = {
  status: 'active',
  tier: 'starter',
  expiresAt: '2099-12-31T23:59:59Z',
  seats: 999,
};

interface RegistryEntry {
  email: string;
  backendUrl: string;
  customerName: string;
  orgId?: string;
  license?: Partial<LicenseInfo>;
  aws?: CustomerConfig['aws'];
  oast?: CustomerConfig['oast'];
}

// Shape of one per-customer secret in Secrets Manager when running in
// multi-secret mode. The onboarding terraform module produces this shape.
interface CustomerSecret {
  orgId: string;
  customerName: string;
  backendUrl: string;
  emails: string[]; // exact emails or "*@domain" wildcards
  license?: Partial<LicenseInfo>;
  aws?: CustomerConfig['aws'];
  oast?: CustomerConfig['oast'];
}

function matchEntry(entries: RegistryEntry[], email: string): RegistryEntry | undefined {
  const exact = entries.find(e => e.email === email);
  if (exact) return exact;

  const domain = email.split('@')[1];
  return entries.find(e => e.email === `*@${domain}`);
}

function toCustomerConfig(entry: RegistryEntry): CustomerConfig {
  return {
    backendUrl: entry.backendUrl,
    customerName: entry.customerName,
    orgId: entry.orgId || entry.customerName.toLowerCase().replace(/\s+/g, '-'),
    license: { ...DEFAULT_LICENSE, ...entry.license },
    aws: entry.aws,
    oast: entry.oast,
  };
}

// ─── Multi-secret loader ─────────────────────────────────────────────────────
// In production (platform deployed on ECS) we fan out one secret per customer
// and discover them via the tag filter `maestro:customer=true`. This keeps
// onboarding/offboarding clean (one terraform workspace per customer —
// destroy removes the secret cleanly) and avoids race conditions from
// multiple onboardings editing a single JSON blob concurrently.

const REGISTRY_CACHE_TTL_MS = 60_000;
let registryCache: { entries: RegistryEntry[]; fetchedAt: number } | null = null;

async function fetchMultiSecretRegistry(): Promise<RegistryEntry[]> {
  if (registryCache && Date.now() - registryCache.fetchedAt < REGISTRY_CACHE_TTL_MS) {
    return registryCache.entries;
  }

  const region = process.env.AWS_REGION || 'us-west-2';
  const tagKey = process.env.CUSTOMER_REGISTRY_TAG_KEY || 'maestro:customer';
  const client = new SecretsManagerClient({ region });

  const entries: RegistryEntry[] = [];
  let nextToken: string | undefined;

  do {
    const list = await client.send(
      new ListSecretsCommand({
        Filters: [{ Key: 'tag-key', Values: [tagKey] }],
        NextToken: nextToken,
      })
    );

    for (const secret of list.SecretList ?? []) {
      if (!secret.ARN) continue;
      try {
        const value = await client.send(new GetSecretValueCommand({ SecretId: secret.ARN }));
        if (!value.SecretString) continue;
        const parsed: CustomerSecret = JSON.parse(value.SecretString);
        for (const email of parsed.emails ?? []) {
          entries.push({
            email,
            backendUrl: parsed.backendUrl,
            customerName: parsed.customerName,
            orgId: parsed.orgId,
            license: parsed.license,
            aws: parsed.aws,
            oast: parsed.oast,
          });
        }
      } catch (err) {
        console.error(`[customer-registry] failed to load ${secret.Name}:`, err);
      }
    }

    nextToken = list.NextToken;
  } while (nextToken);

  registryCache = { entries, fetchedAt: Date.now() };
  return entries;
}

function fetchEnvRegistry(): RegistryEntry[] {
  const registry = process.env.CUSTOMER_REGISTRY;
  if (!registry) return [];
  try {
    return JSON.parse(registry) as RegistryEntry[];
  } catch (e) {
    console.error('[customer-registry] Failed to parse CUSTOMER_REGISTRY env var:', e);
    return [];
  }
}

async function loadRegistry(): Promise<RegistryEntry[]> {
  if (process.env.CUSTOMER_REGISTRY_MODE === 'multi-secret') {
    try {
      return await fetchMultiSecretRegistry();
    } catch (err) {
      console.error('[customer-registry] multi-secret fetch failed, falling back to env var:', err);
      return fetchEnvRegistry();
    }
  }
  return fetchEnvRegistry();
}

export async function getCustomerConfig(email: string): Promise<CustomerConfig> {
  const entries = await loadRegistry();
  const entry = matchEntry(entries, email);
  if (entry) return toCustomerConfig(entry);

  return {
    backendUrl: DEFAULT_BACKEND,
    customerName: 'Local',
    orgId: 'local',
    license: DEFAULT_LICENSE,
  };
}

/**
 * Check if a user's license is valid. Returns the config if valid,
 * or a reason code if not.
 */
export async function checkLicense(email: string): Promise<LicenseCheckResult> {
  const config = await getCustomerConfig(email);

  if (config.orgId === 'local') {
    return { valid: true, config };
  }

  const { license } = config;

  if (license.status === 'suspended') {
    return { valid: false, reason: 'suspended' };
  }

  if (license.status === 'expired' || new Date(license.expiresAt) < new Date()) {
    return { valid: false, reason: 'expired' };
  }

  if (license.status === 'active' || license.status === 'trial') {
    return { valid: true, config };
  }

  return { valid: false, reason: 'no_license' };
}
