# Kubernetes

Recipes for connecting a Kubernetes cluster — via a kubeconfig file or in-cluster service account.

> [!NOTE] At a glance
> - **Two methods:** Kubeconfig *(standard)* and In-cluster *(Maestro runs as a pod)*.
> - **Shared RBAC:** both bind a read-only `ClusterRole` (`get`, `list`, `watch`) to a `maestro-audit` service account.
> - **In-cluster can't be probed from the desktop** — it validates at assessment runtime.

> [!TIP] New here?
> Start with the [Cloud Accounts overview](./overview.md) for the managed-vs-self-managed decision and the method matrix.

### Kubernetes — Kubeconfig

Standard case: a kubeconfig file points Maestro at the cluster's API server, authenticating as a service account that has read-only RBAC.

::: tabs
::: tab Terraform
```hcl
resource "kubernetes_service_account" "maestro" {
  metadata {
    name      = "maestro-audit"
    namespace = "kube-system"
  }
}

resource "kubernetes_cluster_role" "maestro" {
  metadata { name = "maestro-audit" }
  rule {
    api_groups = ["", "apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io", "policy"]
    resources  = ["*"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding" "maestro" {
  metadata { name = "maestro-audit" }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.maestro.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.maestro.metadata[0].name
    namespace = kubernetes_service_account.maestro.metadata[0].namespace
  }
}

# Token Secret for the SA (K8s 1.24+ requires explicit Secret creation
# for SA tokens that don't auto-rotate).
resource "kubernetes_secret" "maestro_token" {
  metadata {
    name      = "maestro-audit-token"
    namespace = "kube-system"
    annotations = {
      "kubernetes.io/service-account.name" = kubernetes_service_account.maestro.metadata[0].name
    }
  }
  type = "kubernetes.io/service-account-token"
  wait_for_service_account_token = true
}
```

Then build a kubeconfig pointing at the cluster, using the token from `kubernetes_secret.maestro_token.data["token"]` for credentials. Save it somewhere on your host and paste the path into the form.
::: tab Manual
1. Save this to `maestro-rbac.yaml`:
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: maestro-audit
     namespace: kube-system
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRole
   metadata:
     name: maestro-audit
   rules:
     - apiGroups: ["", "apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io", "policy"]
       resources: ["*"]
       verbs: ["get", "list", "watch"]
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata:
     name: maestro-audit
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: ClusterRole
     name: maestro-audit
   subjects:
     - kind: ServiceAccount
       name: maestro-audit
       namespace: kube-system
   ---
   apiVersion: v1
   kind: Secret
   metadata:
     name: maestro-audit-token
     namespace: kube-system
     annotations:
       kubernetes.io/service-account.name: maestro-audit
   type: kubernetes.io/service-account-token
   ```
2. Apply:
   ```bash
   kubectl apply -f maestro-rbac.yaml
   ```
3. Extract the token + cluster cert and build a kubeconfig for Maestro:
   ```bash
   TOKEN=$(kubectl -n kube-system get secret maestro-audit-token -o jsonpath='{.data.token}' | base64 -d)
   CA=$(kubectl -n kube-system get secret maestro-audit-token -o jsonpath='{.data.ca\.crt}')
   SERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')

   cat > ~/.kube/maestro.config <<EOF
   apiVersion: v1
   kind: Config
   clusters:
   - cluster:
       server: ${SERVER}
       certificate-authority-data: ${CA}
     name: maestro-target
   contexts:
   - context:
       cluster: maestro-target
       user: maestro-audit
     name: maestro
   current-context: maestro
   users:
   - name: maestro-audit
     user:
       token: ${TOKEN}
   EOF
   ```
4. Paste `~/.kube/maestro.config` into the form's **Kubeconfig Path**.
:::

---

### Kubernetes — In-cluster

Use when Maestro itself runs as a pod in the cluster. The pod's mounted service account becomes the credential.

::: tabs
::: tab Terraform
Same `kubernetes_service_account` + `kubernetes_cluster_role` + `kubernetes_cluster_role_binding` as the Kubeconfig recipe — but you skip generating a kubeconfig file. Instead, assign the service account to Maestro's deployment:

```hcl
resource "kubernetes_deployment" "maestro" {
  # ... existing config ...
  spec {
    template {
      spec {
        service_account_name = kubernetes_service_account.maestro.metadata[0].name
        # Maestro picks up /var/run/secrets/kubernetes.io/serviceaccount/token automatically.
        container {
          name  = "maestro"
          image = "..."
        }
      }
    }
  }
}
```
::: tab Manual
1. Apply the same `maestro-rbac.yaml` from the Kubeconfig recipe (the ServiceAccount + ClusterRole + ClusterRoleBinding parts).
2. In Maestro's pod spec, set:
   ```yaml
   spec:
     serviceAccountName: maestro-audit
   ```
3. The pod mounts `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}` automatically. No kubeconfig path to set; pick **In-cluster** in the form and leave the path blank.
:::

## Troubleshooting

> [!WARNING] Kubeconfig path resolves to nothing inside the container
> Maestro mounts `~/.kube/` from your host into the Kali container by default. If you put the kubeconfig somewhere else, give the **host** path; Maestro translates host paths to in-container paths automatically.
