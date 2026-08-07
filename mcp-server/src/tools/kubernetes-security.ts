import { executeInKali } from "../utils/docker-exec";

export const kubernetesSecurityTools = [
  {
    name: "enum_k8s_cluster",
    description:
      "Enumerate Kubernetes cluster: namespaces, pods, services, deployments, configmaps, service accounts, RBAC roles, ingresses, network policies.",
    inputSchema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Kubernetes cluster identifier or context name" },
        namespace: {
          type: "string",
          description: "Specific namespace to enumerate. If not provided, enumerates all namespaces.",
        },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_rbac",
    description:
      "Analyze Kubernetes RBAC for overprivileged service accounts, cluster-admin bindings, wildcard permissions, and privesc paths.",
    inputSchema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Kubernetes cluster identifier or context name" },
        service_account: {
          type: "string",
          description: "Specific service account to audit (format: namespace:name). If not provided, audits all.",
        },
        attempt_escalation: {
          type: "boolean",
          description: "Attempt privilege escalation checks (e.g., can-i create pods, get secrets)",
          default: true,
        },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_secrets",
    description:
      "Attempt to extract secrets from Kubernetes: Secret resources, mounted volumes, environment variables in pods.",
    inputSchema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Kubernetes cluster identifier or context name" },
        namespace: {
          type: "string",
          description: "Specific namespace to extract secrets from. If not provided, checks all namespaces.",
        },
        attempt_etcd: {
          type: "boolean",
          description: "Attempt direct etcd access to dump secrets (likely to fail without etcd creds)",
          default: false,
        },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_escape",
    description:
      "Test for container escape vectors: privileged pods, hostPID/hostNetwork, Docker socket mounts, writable hostPath, SYS_ADMIN/SYS_PTRACE capabilities.",
    inputSchema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Kubernetes cluster identifier or context name" },
        namespace: {
          type: "string",
          description: "Specific namespace to check. If not provided, checks all namespaces.",
        },
        pod_name: {
          type: "string",
          description: "Specific pod name to inspect for escape vectors.",
        },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_network_policy",
    description:
      "Verify Kubernetes network segmentation: cross-namespace connectivity, missing network policies, service mesh bypass.",
    inputSchema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Kubernetes cluster identifier or context name" },
        source_namespace: {
          type: "string",
          description: "Source namespace for cross-namespace connectivity test",
        },
        target_namespace: {
          type: "string",
          description: "Target namespace for cross-namespace connectivity test",
        },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_api_server",
    description:
      "Test Kubernetes API server security: anonymous auth, exposed dashboard, metrics endpoints, health check info disclosure.",
    inputSchema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Kubernetes cluster identifier or context name" },
        api_server_url: {
          type: "string",
          description: "API server URL (e.g., 'https://k8s-api.example.com:6443'). Auto-detected if not provided.",
        },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_admission",
    description:
      "Test admission controller enforcement: attempt to deploy pods violating security policies. Non-destructive: uses --dry-run=server so nothing is actually created.",
    inputSchema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Kubernetes cluster identifier or context name" },
        namespace: { type: "string", description: "Namespace to test admission policies in" },
        test_policies: {
          type: "array",
          items: { type: "string" },
          description:
            "Policies to test: 'privileged', 'host_network', 'host_pid', 'root_user', 'capabilities'. Defaults to all.",
          default: ["privileged", "host_network", "host_pid", "root_user", "capabilities"],
        },
      },
      required: ["cluster_id", "namespace"],
    },
  },
];

export const kubernetesSecurityHandlers: Record<string, Function> = {
  enum_k8s_cluster: async (args: { cluster_id: string; namespace?: string }) => {
    const { cluster_id, namespace } = args;
    const nsFlag = namespace ? `-n ${namespace}` : "--all-namespaces";
    const nsLabel = namespace || "all";

    const commands: string[] = [
      `echo "=== Kubernetes Cluster Enumeration ==="`,
      `echo "Cluster: ${cluster_id}"`,
      `echo "Namespace: ${nsLabel}"`,
      `echo ""`,

      // Namespaces
      `echo "--- Namespaces ---"`,
      `kubectl get namespaces -o json 2>&1`,
      `echo ""`,

      // Pods
      `echo "--- Pods (${nsLabel}) ---"`,
      `kubectl get pods ${nsFlag} -o json 2>&1`,
      `echo ""`,

      // Services
      `echo "--- Services (${nsLabel}) ---"`,
      `kubectl get services ${nsFlag} -o json 2>&1`,
      `echo ""`,

      // Deployments
      `echo "--- Deployments (${nsLabel}) ---"`,
      `kubectl get deployments ${nsFlag} -o json 2>&1`,
      `echo ""`,

      // ConfigMaps
      `echo "--- ConfigMaps (${nsLabel}) ---"`,
      `kubectl get configmaps ${nsFlag} -o json 2>&1`,
      `echo ""`,

      // Service Accounts
      `echo "--- Service Accounts (${nsLabel}) ---"`,
      `kubectl get serviceaccounts ${nsFlag} -o json 2>&1`,
      `echo ""`,

      // Ingresses
      `echo "--- Ingresses (${nsLabel}) ---"`,
      `kubectl get ingresses ${nsFlag} -o json 2>&1`,
      `echo ""`,

      // Network Policies
      `echo "--- Network Policies (${nsLabel}) ---"`,
      `kubectl get networkpolicies ${nsFlag} -o json 2>&1`,
      `echo ""`,

      // Cluster-wide RBAC
      `echo "--- Cluster Roles ---"`,
      `kubectl get clusterroles -o json 2>&1`,
      `echo ""`,

      `echo "--- Cluster Role Bindings ---"`,
      `kubectl get clusterrolebindings -o json 2>&1`,
      `echo ""`,

      `echo "=== Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  test_k8s_rbac: async (args: {
    cluster_id: string;
    service_account?: string;
    attempt_escalation?: boolean;
  }) => {
    const { cluster_id, service_account, attempt_escalation = true } = args;

    const commands: string[] = [
      `echo "=== Kubernetes RBAC Analysis ==="`,
      `echo "Cluster: ${cluster_id}"`,
      `echo ""`,

      // Find cluster-admin bindings
      `echo "--- Cluster-Admin Bindings ---"`,
      `kubectl get clusterrolebindings -o json 2>&1 | jq '[.items[] | select(.roleRef.name=="cluster-admin") | {name: .metadata.name, subjects: .subjects}]' 2>/dev/null || echo "Failed to query cluster role bindings"`,
      `echo ""`,

      // Overprivileged role bindings
      `echo "--- All Role Bindings (all namespaces) ---"`,
      `kubectl get rolebindings --all-namespaces -o json 2>&1 | jq '[.items[] | {namespace: .metadata.namespace, name: .metadata.name, role: .roleRef.name, subjects: .subjects}]' 2>/dev/null || echo "Failed to query role bindings"`,
      `echo ""`,

      // Wildcard permissions in cluster roles
      `echo "--- Cluster Roles with Wildcard Permissions ---"`,
      `kubectl get clusterroles -o json 2>&1 | jq '[.items[] | select(.rules[]?.verbs[]? == "*") | {name: .metadata.name, rules: .rules}]' 2>/dev/null || echo "Failed to check wildcard permissions"`,
      `echo ""`,
    ];

    if (service_account) {
      // Audit specific service account
      const parts = service_account.split(":");
      const saNs = parts[0] || "default";
      const saName = parts[1] || parts[0];

      commands.push(`echo "--- Permissions for ${saNs}:${saName} ---"`);
      commands.push(
        `kubectl auth can-i --list --as=system:serviceaccount:${saNs}:${saName} 2>&1`
      );
      commands.push(`echo ""`);

      if (attempt_escalation) {
        commands.push(`echo "--- Privilege Escalation Checks for ${saNs}:${saName} ---"`);
        commands.push(
          `echo "Can create pods: $(kubectl auth can-i create pods --as=system:serviceaccount:${saNs}:${saName} 2>&1)"`
        );
        commands.push(
          `echo "Can get secrets: $(kubectl auth can-i get secrets --as=system:serviceaccount:${saNs}:${saName} 2>&1)"`
        );
        commands.push(
          `echo "Can create clusterrolebindings: $(kubectl auth can-i create clusterrolebindings --as=system:serviceaccount:${saNs}:${saName} 2>&1)"`
        );
        commands.push(
          `echo "Can exec into pods: $(kubectl auth can-i create pods/exec --as=system:serviceaccount:${saNs}:${saName} 2>&1)"`
        );
        commands.push(
          `echo "Can create serviceaccounts: $(kubectl auth can-i create serviceaccounts --as=system:serviceaccount:${saNs}:${saName} 2>&1)"`
        );
        commands.push(`echo ""`);
      }
    } else {
      // Enumerate all service accounts and check permissions
      commands.push(`echo "--- Service Account Permission Audit ---"`);
      commands.push(
        `SA_LIST=$(kubectl get serviceaccounts --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}:{.metadata.name}{"\\n"}{end}' 2>/dev/null) && for sa in $SA_LIST; do NS=$(echo $sa | cut -d: -f1); NAME=$(echo $sa | cut -d: -f2); echo "== $NS:$NAME =="; kubectl auth can-i --list --as=system:serviceaccount:$NS:$NAME 2>&1 | head -20; echo ""; done`
      );
      commands.push(`echo ""`);
    }

    // Run kube-hunter if available
    commands.push(`echo "--- Kube-Hunter Active Scan ---"`);
    commands.push(`kube-hunter --active --report json 2>/dev/null || echo "kube-hunter not available"`);
    commands.push(`echo ""`);

    commands.push(`echo "=== RBAC Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_k8s_secrets: async (args: {
    cluster_id: string;
    namespace?: string;
    attempt_etcd?: boolean;
  }) => {
    const { cluster_id, namespace, attempt_etcd = false } = args;
    const nsFlag = namespace ? `-n ${namespace}` : "--all-namespaces";
    const nsLabel = namespace || "all";

    const commands: string[] = [
      `echo "=== Kubernetes Secrets Extraction ==="`,
      `echo "Cluster: ${cluster_id}"`,
      `echo "Namespace: ${nsLabel}"`,
      `echo ""`,

      // Get all secrets and decode base64 values
      `echo "--- Secret Resources ---"`,
      `kubectl get secrets ${nsFlag} -o json 2>&1 | jq '[.items[] | {namespace: .metadata.namespace, name: .metadata.name, type: .type, keys: (.data // {} | keys)}]' 2>/dev/null || echo "Failed to list secrets"`,
      `echo ""`,

      // Decode secret values
      `echo "--- Decoded Secret Values ---"`,
      `kubectl get secrets ${nsFlag} -o json 2>&1 | jq -r '.items[] | select(.type != "kubernetes.io/service-account-token") | "\\nSecret: \\(.metadata.namespace)/\\(.metadata.name) (\\(.type))", (.data // {} | to_entries[] | "  \\(.key): \\(.value | @base64d)")' 2>/dev/null || echo "Failed to decode secrets"`,
      `echo ""`,

      // Extract env vars referencing secrets from pods
      `echo "--- Pod Environment Variables Referencing Secrets ---"`,
      `kubectl get pods ${nsFlag} -o json 2>&1 | jq '[.items[] | {pod: .metadata.name, namespace: .metadata.namespace, secret_env_refs: [.spec.containers[].env[]? | select(.valueFrom.secretKeyRef != null) | {var: .name, secret: .valueFrom.secretKeyRef.name, key: .valueFrom.secretKeyRef.key}], secret_volume_mounts: [.spec.volumes[]? | select(.secret != null) | {volume: .name, secret: .secret.secretName}]} | select(.secret_env_refs | length > 0 or .secret_volume_mounts | length > 0)]' 2>/dev/null || echo "Failed to extract secret references"`,
      `echo ""`,

      // Attempt to read mounted service account tokens
      `echo "--- Mounted Service Account Tokens ---"`,
      `PODS=$(kubectl get pods ${nsFlag} -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\\n"}{end}' 2>/dev/null) && for pod in $PODS; do NS=$(echo $pod | cut -d/ -f1); NAME=$(echo $pod | cut -d/ -f2); TOKEN=$(kubectl exec -n $NS $NAME -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); if [ -n "$TOKEN" ]; then echo "Pod $NS/$NAME token: $(echo $TOKEN | head -c 80)..."; fi; done`,
      `echo ""`,

      // Search ConfigMaps for sensitive patterns
      `echo "--- Sensitive Patterns in ConfigMaps ---"`,
      `kubectl get configmaps ${nsFlag} -o json 2>&1 | grep -iE '(password|secret|token|key|credential|api_key|apikey|db_pass|database_url|connection_string)' 2>/dev/null || echo "No sensitive patterns found in ConfigMaps"`,
      `echo ""`,
    ];

    if (attempt_etcd) {
      commands.push(`echo "--- Direct etcd Access Attempt ---"`);
      commands.push(
        `ETCD_POD=$(kubectl get pods -n kube-system -l component=etcd -o jsonpath='{.items[0].metadata.name}' 2>/dev/null) && if [ -n "$ETCD_POD" ]; then echo "Found etcd pod: $ETCD_POD"; kubectl exec -n kube-system $ETCD_POD -- etcdctl get / --prefix --keys-only --limit=50 2>&1 | head -50; else echo "No etcd pod found or not accessible"; fi`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== Secrets Extraction Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_k8s_escape: async (args: {
    cluster_id: string;
    namespace?: string;
    pod_name?: string;
  }) => {
    const { cluster_id, namespace, pod_name } = args;
    const nsFlag = namespace ? `-n ${namespace}` : "--all-namespaces";
    const nsLabel = namespace || "all";

    const commands: string[] = [
      `echo "=== Container Escape Vector Analysis ==="`,
      `echo "Cluster: ${cluster_id}"`,
      `echo "Namespace: ${nsLabel}"`,
      pod_name ? `echo "Pod: ${pod_name}"` : `echo "Pod: all"`,
      `echo ""`,
    ];

    const podSelector = pod_name
      ? `[.items[] | select(.metadata.name=="${pod_name}")]`
      : ".items[]";
    const podJsonBase = pod_name
      ? `kubectl get pods ${nsFlag} -o json 2>&1 | jq '[.items[] | select(.metadata.name=="${pod_name}")]'`
      : `kubectl get pods ${nsFlag} -o json 2>&1`;

    // Privileged pods
    commands.push(`echo "--- 1. Privileged Pods ---"`);
    commands.push(
      `kubectl get pods ${nsFlag} -o json 2>&1 | jq '[.items[] | select(.spec.containers[].securityContext.privileged==true) | {name: .metadata.name, namespace: .metadata.namespace, containers: [.spec.containers[] | select(.securityContext.privileged==true) | .name]}]' 2>/dev/null || echo "Failed to check privileged pods"`
    );
    commands.push(`echo ""`);

    // hostPID / hostNetwork
    commands.push(`echo "--- 2. hostPID / hostNetwork Pods ---"`);
    commands.push(
      `kubectl get pods ${nsFlag} -o json 2>&1 | jq '[.items[] | select(.spec.hostPID==true or .spec.hostNetwork==true) | {name: .metadata.name, namespace: .metadata.namespace, hostPID: .spec.hostPID, hostNetwork: .spec.hostNetwork}]' 2>/dev/null || echo "Failed to check hostPID/hostNetwork"`
    );
    commands.push(`echo ""`);

    // Docker socket mounts
    commands.push(`echo "--- 3. Docker Socket Mounts ---"`);
    commands.push(
      `kubectl get pods ${nsFlag} -o json 2>&1 | jq '[.items[] | select(.spec.volumes[]?.hostPath.path=="/var/run/docker.sock") | {name: .metadata.name, namespace: .metadata.namespace}]' 2>/dev/null || echo "Failed to check Docker socket mounts"`
    );
    commands.push(`echo ""`);

    // Writable hostPath volumes
    commands.push(`echo "--- 4. hostPath Volume Mounts ---"`);
    commands.push(
      `kubectl get pods ${nsFlag} -o json 2>&1 | jq '[.items[] | select(.spec.volumes[]?.hostPath != null) | {name: .metadata.name, namespace: .metadata.namespace, hostPaths: [.spec.volumes[] | select(.hostPath != null) | {name: .name, path: .hostPath.path, type: .hostPath.type}]}]' 2>/dev/null || echo "Failed to check hostPath volumes"`
    );
    commands.push(`echo ""`);

    // Dangerous capabilities
    commands.push(`echo "--- 5. Dangerous Capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN) ---"`);
    commands.push(
      `kubectl get pods ${nsFlag} -o json 2>&1 | jq '[.items[] | select(.spec.containers[].securityContext.capabilities.add[]? | test("SYS_ADMIN|SYS_PTRACE|NET_ADMIN")) | {name: .metadata.name, namespace: .metadata.namespace, containers: [.spec.containers[] | select(.securityContext.capabilities.add != null) | {name: .name, capabilities: .securityContext.capabilities.add}]}]' 2>/dev/null || echo "Failed to check capabilities"`
    );
    commands.push(`echo ""`);

    // CDK evaluate
    commands.push(`echo "--- 6. CDK Container Escape Evaluation ---"`);
    commands.push(`cdk evaluate 2>/dev/null || echo "CDK not available"`);
    commands.push(`echo ""`);

    // kubeaudit
    commands.push(`echo "--- 7. Kubeaudit Scan ---"`);
    if (namespace) {
      commands.push(`kubeaudit all -n ${namespace} --format json 2>/dev/null || echo "kubeaudit not available"`);
    } else {
      commands.push(`kubeaudit all --format json 2>/dev/null || echo "kubeaudit not available"`);
    }
    commands.push(`echo ""`);

    commands.push(`echo "=== Escape Vector Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_k8s_network_policy: async (args: {
    cluster_id: string;
    source_namespace?: string;
    target_namespace?: string;
  }) => {
    const { cluster_id, source_namespace, target_namespace } = args;

    const commands: string[] = [
      `echo "=== Kubernetes Network Policy Analysis ==="`,
      `echo "Cluster: ${cluster_id}"`,
      `echo ""`,

      // Get all network policies
      `echo "--- Network Policies (all namespaces) ---"`,
      `kubectl get networkpolicies --all-namespaces -o json 2>&1 | jq '[.items[] | {namespace: .metadata.namespace, name: .metadata.name, podSelector: .spec.podSelector, policyTypes: .spec.policyTypes, ingress: .spec.ingress, egress: .spec.egress}]' 2>/dev/null || echo "Failed to list network policies"`,
      `echo ""`,

      // Find namespaces WITHOUT network policies
      `echo "--- Namespaces WITHOUT Network Policies ---"`,
      `POLICY_NS=$(kubectl get networkpolicies --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\\n"}{end}' 2>/dev/null | sort -u) && ALL_NS=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null | sort -u) && echo "Namespaces with policies: $POLICY_NS" && echo "All namespaces: $ALL_NS" && echo "Missing policies:" && comm -23 <(echo "$ALL_NS") <(echo "$POLICY_NS")`,
      `echo ""`,

      // Check for default deny policies
      `echo "--- Default Deny Policies ---"`,
      `kubectl get networkpolicies --all-namespaces -o json 2>&1 | jq '[.items[] | select(.spec.podSelector == {} and (.spec.policyTypes[]? | test("Ingress|Egress"))) | {namespace: .metadata.namespace, name: .metadata.name, policyTypes: .spec.policyTypes}]' 2>/dev/null || echo "Failed to check default deny"`,
      `echo ""`,
    ];

    // Cross-namespace connectivity test
    if (source_namespace && target_namespace) {
      commands.push(`echo "--- Cross-Namespace Connectivity Test ---"`);
      commands.push(`echo "Source: ${source_namespace} -> Target: ${target_namespace}"`);

      // Get services in target namespace
      commands.push(
        `TARGET_SVCS=$(kubectl get services -n ${target_namespace} -o jsonpath='{range .items[*]}{.metadata.name}{"\\n"}{end}' 2>/dev/null)`
      );

      // Create test pod, run connectivity tests, clean up
      commands.push(
        `echo "Creating test pod in ${source_namespace}..." && kubectl run maestro-net-test --image=busybox --restart=Never -n ${source_namespace} --command -- sleep 30 2>&1 && sleep 3`
      );
      commands.push(
        `for svc in $TARGET_SVCS; do echo "Testing connectivity to $svc.${target_namespace}.svc.cluster.local..."; kubectl exec maestro-net-test -n ${source_namespace} -- wget -qO- --timeout=5 http://$svc.${target_namespace}.svc.cluster.local 2>&1 | head -c 200; echo ""; done`
      );
      commands.push(
        `echo "Cleaning up test pod..." && kubectl delete pod maestro-net-test -n ${source_namespace} --grace-period=0 --force 2>&1`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== Network Policy Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_k8s_api_server: async (args: { cluster_id: string; api_server_url?: string }) => {
    const { cluster_id, api_server_url } = args;

    const commands: string[] = [
      `echo "=== Kubernetes API Server Security Test ==="`,
      `echo "Cluster: ${cluster_id}"`,
      `echo ""`,

      // Get API server URL
      `echo "--- API Server Info ---"`,
      `kubectl cluster-info 2>&1`,
      `echo ""`,
    ];

    // Determine API server URL
    if (api_server_url) {
      commands.push(`API_SERVER="${api_server_url}"`);
    } else {
      commands.push(
        `API_SERVER=$(kubectl cluster-info 2>/dev/null | grep -oP 'https://[^\\s]+' | head -1)`
      );
    }

    // Anonymous auth check
    commands.push(`echo "--- Anonymous Authentication ---"`);
    commands.push(`kubectl auth can-i --list --as=system:anonymous 2>&1`);
    commands.push(`echo ""`);

    // Anonymous API access
    commands.push(`echo "--- Anonymous API Access ---"`);
    commands.push(
      `echo "Namespaces:" && curl -sk $API_SERVER/api/v1/namespaces --max-time 5 2>/dev/null | head -c 500`
    );
    commands.push(`echo ""`);

    // Exposed endpoints
    commands.push(`echo "--- Exposed Endpoints ---"`);
    const endpoints = ["/metrics", "/healthz", "/version", "/openapi/v2", "/apis"];
    for (const ep of endpoints) {
      commands.push(
        `echo "  ${ep}:" && RESP=$(curl -sk -o /tmp/k8s-ep-resp.txt -w "%{http_code}" --max-time 5 $API_SERVER${ep} 2>/dev/null) && echo "    Status: $RESP" && if [ "$RESP" = "200" ]; then echo "    EXPOSED - Response preview:"; head -c 300 /tmp/k8s-ep-resp.txt; echo ""; fi`
      );
    }
    commands.push(`echo ""`);

    // Dashboard check
    commands.push(`echo "--- Kubernetes Dashboard ---"`);
    commands.push(
      `kubectl get pods --all-namespaces 2>/dev/null | grep dashboard || echo "No dashboard pods found"`
    );
    commands.push(
      `kubectl get svc --all-namespaces 2>/dev/null | grep dashboard || echo "No dashboard services found"`
    );
    commands.push(`echo ""`);

    // Exposed kubelet
    commands.push(`echo "--- Kubelet Exposure Check ---"`);
    commands.push(
      `NODES=$(kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\\n"}{end}' 2>/dev/null) && for node in $NODES; do echo "Node $node:10250:"; curl -sk https://$node:10250/pods --max-time 5 2>/dev/null | head -c 500; echo ""; done || echo "Could not enumerate node IPs"`
    );
    commands.push(`echo ""`);

    commands.push(`echo "=== API Server Security Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_k8s_admission: async (args: {
    cluster_id: string;
    namespace: string;
    test_policies?: string[];
  }) => {
    const {
      cluster_id,
      namespace,
      test_policies = ["privileged", "host_network", "host_pid", "root_user", "capabilities"],
    } = args;

    const commands: string[] = [
      `echo "=== Kubernetes Admission Controller Test ==="`,
      `echo "Cluster: ${cluster_id}"`,
      `echo "Namespace: ${namespace}"`,
      `echo "Tests: ${test_policies.join(", ")}"`,
      `echo ""`,
      `echo "All tests use --dry-run=server (nothing is actually created)"`,
      `echo ""`,
    ];

    const policyOverrides: Record<string, { description: string; overrides: string }> = {
      privileged: {
        description: "Privileged container",
        overrides: JSON.stringify({
          spec: {
            containers: [
              {
                name: "maestro-priv-test",
                image: "busybox",
                command: ["sleep", "1"],
                securityContext: { privileged: true },
              },
            ],
          },
        }),
      },
      host_network: {
        description: "Host network access",
        overrides: JSON.stringify({
          spec: {
            hostNetwork: true,
            containers: [
              {
                name: "maestro-hostnet-test",
                image: "busybox",
                command: ["sleep", "1"],
              },
            ],
          },
        }),
      },
      host_pid: {
        description: "Host PID namespace",
        overrides: JSON.stringify({
          spec: {
            hostPID: true,
            containers: [
              {
                name: "maestro-hostpid-test",
                image: "busybox",
                command: ["sleep", "1"],
              },
            ],
          },
        }),
      },
      root_user: {
        description: "Run as root (UID 0)",
        overrides: JSON.stringify({
          spec: {
            containers: [
              {
                name: "maestro-root-test",
                image: "busybox",
                command: ["sleep", "1"],
                securityContext: { runAsUser: 0 },
              },
            ],
          },
        }),
      },
      capabilities: {
        description: "SYS_ADMIN capability",
        overrides: JSON.stringify({
          spec: {
            containers: [
              {
                name: "maestro-caps-test",
                image: "busybox",
                command: ["sleep", "1"],
                securityContext: {
                  capabilities: { add: ["SYS_ADMIN"] },
                },
              },
            ],
          },
        }),
      },
    };

    for (const policy of test_policies) {
      const config = policyOverrides[policy];
      if (!config) {
        commands.push(`echo "--- Unknown policy: ${policy} (skipped) ---"`);
        commands.push(`echo ""`);
        continue;
      }

      const podName = `maestro-${policy.replace(/_/g, "-")}-test`;
      // Escape single quotes in the JSON for shell safety
      const escapedOverrides = config.overrides.replace(/'/g, "'\\''");

      commands.push(`echo "--- Test: ${config.description} ---"`);
      commands.push(
        `kubectl run ${podName} --image=busybox --restart=Never -n ${namespace} --overrides='${escapedOverrides}' --dry-run=server -o json 2>&1 && echo "RESULT: ALLOWED (admission controller did NOT block this)" || echo "RESULT: DENIED (admission controller blocked this)"`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== Admission Controller Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
