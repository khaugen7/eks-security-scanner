# Scan Types

`eks-security-scanner` supports multiple scan types to detect risky configurations and access paths in Kubernetes and EKS clusters. This document explains each scan type and what it looks for.

---

## Threat Graph

### Purpose
Visualize internal access paths and identity usage to support threat modeling and lateral movement analysis.

### Command

`eks-scanner graph -c <cluster>`

### Output
- ASCII or DOT format
- Maps:
  - Pods → Services → Endpoints (network path)
  - Pods → ServiceAccounts → IAM roles (identity path)

### What It Detects
- Reused or overly privileged service accounts
- Services that expose sensitive workloads
- Pods that can reach many endpoints across namespaces
- Potential privilege escalation paths

---

## Audit Scan

### Purpose
Review Kubernetes RBAC and AWS IAM integration for common misconfigurations and high-risk roles.

### Command

`eks-scanner audit -c <cluster>`

### Checks Performed
- Wildcard verbs or resources in `Role` or `ClusterRole`
- `cluster-admin` bindings
- Roles granting access to secrets, persistent volumes, or pods
- `eks.amazonaws.com/role-arn` mappings to IAM roles with broad privileges

### Why It Matters
Over-permissive roles and bindings increase the attack surface and often violate the principle of least privilege.

---

## Privilege Scan

### Purpose
Identify pods with dangerous runtime configurations that can allow container breakout or host access.

### Command

`eks-scanner privilege -c <cluster>`

### Checks Performed
- `securityContext.privileged: true`
- `allowPrivilegeEscalation: true`
- `runAsUser: 0` (root)
- `hostPID`, `hostIPC`, or `hostNetwork: true`
- `hostPath` volumes

### Why It Matters
These settings are frequently used in container escape attacks, privilege escalation, and host compromise scenarios.

---

## Namespace Scan

### Purpose
Detect missing or unsafe policies at the namespace level that impact workload isolation, stability, and resource usage.

### Command

`eks-scanner namespace -c <cluster> -n <namespace>`

### Checks Performed
- Presence of `LimitRange` objects
- Presence of `ResourceQuota` objects
- Absence of both may indicate risk of:
  - Resource exhaustion
  - No memory/CPU enforcement
  - Namespace abuse

### Why It Matters
Limit ranges and quotas help ensure fairness and stability in multi-tenant clusters. Their absence allows workloads to consume unbounded resources.

---

## Interpreting Results

Each scan provides brief summaries of findings. For a detailed guide on interpreting and remediating each result, see [interpreting-results.md](interpreting-results.md).

---

## Roadmap

Planned future scan types may include:
- Network policy gaps
- PodSecurityPolicy / PodSecurity admission checks
- Image vulnerability integration

Contributions are welcome!
