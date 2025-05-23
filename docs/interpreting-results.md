# Interpreting Scan Results

This guide helps you understand and act on the output from `eks-security-scanner`. Each scan type produces results that highlight potentially risky configurations or over-permissive access within your Kubernetes or EKS environment.

---

## Severity Indicators

Findings from scans should be triaged based on:

- **Scope of impact** (namespace-only vs. cluster-wide)
- **Sensitivity of resources involved** (secrets, host access)
- **Ease of exploitation** (misconfigured pod vs IAM admin role)

Use the following rough severity levels:

| Severity   | Description |
|------------|-------------|
| Critical   | Allows cluster compromise or host access |
| High       | Enables lateral movement or privilege escalation |
| Medium     | Increases blast radius but needs additional conditions |
| Low        | Unlikely to be exploited or mitigated by other controls |

---

## Threat Graph

### What It Shows
- Directed relationships between pods, services, endpoints, service accounts, and IAM roles
- Combines **network exposure paths** and **identity privilege paths**

### Relationships Tracked
- **Pods → Services → Endpoints** (network path)
- **Pods → ServiceAccounts → IAM Roles** (identity path)

### How to Interpret
- Look for **pods exposed via services** that lead to sensitive endpoints
- Identify **service accounts reused** across multiple pods
- Trace pods that connect to **endpoints in other namespaces**
- Highlight **IAM roles mapped to high-privilege service accounts**

### Recommended Actions
- Reduce service exposure to only necessary consumers
- Create unique SAs per workload and restrict IAM permissions
- Segment workloads using namespaces, network policies, or service mesh
- Review fan-in/out patterns to identify lateral movement risks

---

## Audit Scan

### What It Shows
- RBAC roles and bindings with risky configurations
- IAM roles mapped via `eks.amazonaws.com/role-arn`

### Common Findings

| Finding | Explanation | Severity |
|--------|-------------|----------|
| Wildcard verb or resource | Grants too much access | High |
| cluster-admin role | Full cluster control | Critical |
| IAM admin policies | Cross-service impact | Critical |

### Recommended Actions
- Replace wildcards with explicit resource+verb pairs
- Use least privilege principles in IAM and RBAC
- Review all `eks.amazonaws.com/role-arn` policies regularly

---

## Privilege Scan

### What It Shows
- Pod-level `securityContext` settings that bypass container isolation

### Common Findings

| Setting | Description | Severity |
|---------|-------------|----------|
| `privileged: true` | Full access to host kernel | Critical |
| `runAsUser: 0` | Running as root | High |
| `allowPrivilegeEscalation: true` | Allows `sudo` or container breakout | High |
| `hostPath` volumes | Can read/write to host filesystem | High |
| `hostNetwork` / `hostPID` | Shares namespace with host | Medium |

### Recommended Actions
- Enforce restrictive pod security policies or PodSecurity admission
- Avoid running containers as root
- Disable privilege escalation
- Use volumes like `emptyDir` or `configMap` over `hostPath`

---

## Namespace Scan

### What It Shows
- Whether namespaces have enforced policies for resource management

### Common Findings

| Finding | Explanation | Severity |
|---------|-------------|----------|
| No `LimitRange` | No upper or default CPU/memory constraints | Medium |
| No `ResourceQuota` | No guardrails for total namespace resource usage | Medium |
| Both missing | Namespace can be abused by unbounded workloads | High (in shared clusters) |
| Uses Default Service Account | Pods inherit the default service account, which may have risky or shared access permissions | High

### Recommended Actions
- Define default `LimitRange` objects to enforce CPU/memory per pod
- Apply `ResourceQuota` to cap total resources in the namespace
- Regularly audit policy presence in critical namespaces

---

## Summary

Use scan output to:
- Prioritize remediation based on severity and context
- Understand potential attack paths within your cluster
- Enforce security best practices at the pod, namespace, and cluster levels
- Assign dedicated service accounts to pods

For a full understanding of how issues are discovered, see [scan-types.md](scan-types.md) and [threat-modeling.md](threat-modeling.md).
