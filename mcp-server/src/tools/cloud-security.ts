import { executeInKali } from "../utils/docker-exec";

export const cloudSecurityTools = [
  {
    name: "test_cloud_metadata",
    description: "Test for cloud metadata service exposure via SSRF or direct access. Probes AWS IMDS (v1 and v2), Azure Instance Metadata Service, and GCP metadata endpoints.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL to test SSRF through (e.g., 'https://app.com/proxy?url=FUZZ'). If not provided, tests direct metadata endpoint access.",
        },
        parameter: { type: "string", description: "URL parameter to inject metadata URLs into" },
        providers: {
          type: "array",
          items: { type: "string" },
          description: "Cloud providers to test: 'aws', 'azure', 'gcp'. Defaults to all.",
        },
        headers: { type: "object", description: "Custom request headers (e.g., authentication)" },
      },
      required: [],
    },
  },
  {
    name: "check_s3_bucket",
    description: "Test S3 bucket permissions and misconfigurations. Read-only by default (public listing, read access, ACL disclosure, bucket policy exposure). The active write test (a PUT of a temp object, self-deleted) only runs when attempt_write is explicitly set to true.",
    inputSchema: {
      type: "object",
      properties: {
        bucket_name: { type: "string", description: "S3 bucket name to test (e.g., 'company-assets')" },
        region: { type: "string", description: "AWS region (e.g., 'us-east-1')", default: "us-east-1" },
        attempt_write: {
          type: "boolean",
          description:
            "Opt-in: actively test public write by PUTting a temp object (.pentest-write-check-deleteme) and deleting it. Defaults to false so the tool is fully read-only; when false the write posture is reported as 'NOT TESTED (read-only mode)'.",
          default: false,
        },
      },
      required: ["bucket_name"],
    },
  },
];

export const cloudSecurityHandlers: Record<string, Function> = {
  test_cloud_metadata: async (args: {
    target?: string;
    parameter?: string;
    providers?: string[];
    headers?: Record<string, string>;
  }) => {
    const { target, parameter, providers = ["aws", "azure", "gcp"], headers = {} } = args;

    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H "${k}: ${v}"`)
      .join(" ");

    const commands: string[] = [`echo "=== Cloud Metadata Service Exposure Test ==="`];

    const metadataEndpoints: Record<string, { url: string; headers: string; description: string }[]> = {
      aws: [
        { url: "http://169.254.169.254/latest/meta-data/", headers: "", description: "AWS IMDSv1 - Instance metadata root" },
        { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", headers: "", description: "AWS IMDSv1 - IAM credentials listing" },
        { url: "http://169.254.169.254/latest/user-data", headers: "", description: "AWS IMDSv1 - User data (may contain secrets)" },
        { url: "http://169.254.169.254/latest/api/token", headers: '-H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT', description: "AWS IMDSv2 - Token request" },
      ],
      azure: [
        { url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers: '-H "Metadata: true"', description: "Azure IMDS - Instance metadata" },
        { url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", headers: '-H "Metadata: true"', description: "Azure IMDS - Managed identity token" },
      ],
      gcp: [
        { url: "http://metadata.google.internal/computeMetadata/v1/", headers: '-H "Metadata-Flavor: Google"', description: "GCP - Metadata root" },
        { url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", headers: '-H "Metadata-Flavor: Google"', description: "GCP - Service account token" },
        { url: "http://metadata.google.internal/computeMetadata/v1/project/attributes/", headers: '-H "Metadata-Flavor: Google"', description: "GCP - Project attributes" },
      ],
    };

    for (const provider of providers) {
      const endpoints = metadataEndpoints[provider];
      if (!endpoints) continue;

      commands.push(`echo ""`);
      commands.push(`echo "--- ${provider.toUpperCase()} Metadata Endpoints ---"`);

      for (const ep of endpoints) {
        let testUrl: string;
        if (target && parameter) {
          testUrl = target.replace("FUZZ", encodeURIComponent(ep.url));
        } else if (target) {
          testUrl = target.replace("FUZZ", encodeURIComponent(ep.url));
        } else {
          testUrl = ep.url;
        }

        commands.push(`echo "Testing: ${ep.description}"`);
        commands.push(
          `RESP=$(curl -s -o /tmp/meta-resp.txt -w "%{http_code}" --max-time 5 ${ep.headers} ${headerFlags} "${testUrl}" 2>/dev/null) && echo "  Status: $RESP" && if [ "$RESP" = "200" ]; then echo "  EXPOSED - Response:"; head -c 1000 /tmp/meta-resp.txt; echo ""; else echo "  Not accessible"; fi`
        );
      }
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  check_s3_bucket: async (args: { bucket_name: string; region?: string; attempt_write?: boolean }) => {
    const { bucket_name, region = "us-east-1", attempt_write = false } = args;
    const bucketUrl = `https://${bucket_name}.s3.${region}.amazonaws.com`;

    const command = [
      `echo "=== S3 Bucket Security Check ==="`,
      `echo "Bucket: ${bucket_name}"`,
      `echo "Region: ${region}"`,
      `echo "URL: ${bucketUrl}"`,
      `echo ""`,

      `echo "--- 1. Bucket Existence ---"`,
      `EXIST_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${bucketUrl}")`,
      `echo "Status: $EXIST_STATUS"`,
      `if [ "$EXIST_STATUS" = "404" ]; then echo "Bucket does not exist."; elif [ "$EXIST_STATUS" = "403" ]; then echo "Bucket exists but access denied (expected)."; elif [ "$EXIST_STATUS" = "200" ]; then echo "WARNING: Bucket is publicly accessible!"; fi`,
      `echo ""`,

      `echo "--- 2. Public Listing (GET /) ---"`,
      `LIST_STATUS=$(curl -s -o /tmp/s3-list.txt -w "%{http_code}" --max-time 10 "${bucketUrl}/")`,
      `echo "Status: $LIST_STATUS"`,
      `if [ "$LIST_STATUS" = "200" ]; then echo "WARNING: Public listing enabled!"; head -c 2000 /tmp/s3-list.txt; echo ""; else echo "OK: Listing not publicly accessible."; fi`,
      `echo ""`,

      `echo "--- 3. ACL Check ---"`,
      `ACL_STATUS=$(curl -s -o /tmp/s3-acl.txt -w "%{http_code}" --max-time 10 "${bucketUrl}/?acl")`,
      `echo "Status: $ACL_STATUS"`,
      `if [ "$ACL_STATUS" = "200" ]; then echo "WARNING: ACL is publicly readable!"; cat /tmp/s3-acl.txt; echo ""; else echo "OK: ACL not publicly accessible."; fi`,
      `echo ""`,

      `echo "--- 4. Bucket Policy ---"`,
      `POLICY_STATUS=$(curl -s -o /tmp/s3-policy.txt -w "%{http_code}" --max-time 10 "${bucketUrl}/?policy")`,
      `echo "Status: $POLICY_STATUS"`,
      `if [ "$POLICY_STATUS" = "200" ]; then echo "WARNING: Bucket policy is publicly readable!"; cat /tmp/s3-policy.txt; echo ""; else echo "OK: Policy not publicly accessible."; fi`,
      `echo ""`,

      ...(attempt_write
        ? [
            `echo "--- 5. Write Test (opt-in: PUT temp object, self-delete) ---"`,
            `WRITE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X PUT -d "pentest-write-check" "${bucketUrl}/.pentest-write-check-deleteme")`,
            `echo "Status: $WRITE_STATUS"`,
            `if [ "$WRITE_STATUS" = "200" ]; then echo "CRITICAL: Public write access enabled! Uploaded test file .pentest-write-check-deleteme"; curl -s -X DELETE "${bucketUrl}/.pentest-write-check-deleteme" 2>/dev/null; echo "Cleanup: Attempted to delete test file."; else echo "OK: Write access not publicly available."; fi`,
            `echo ""`,
          ]
        : [
            `echo "--- 5. Write Test ---"`,
            `echo "NOT TESTED (read-only mode). Re-run with attempt_write=true to actively test public write access."`,
            `echo ""`,
          ]),

      `echo "=== S3 Bucket Check Complete ==="`,
    ].join("\n");

    return await executeInKali(command);
  },
};
