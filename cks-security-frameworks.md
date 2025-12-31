# Security Frameworks for CKS

## MITRE ATT&CK Framework (Containers Matrix)

### Overview

A knowledge base of adversary tactics and techniques used to attack container and Kubernetes environments. Helps defenders understand how attacks happen and what controls to implement.

### Attack Lifecycle (Tactics)

| # | Tactic | Description | K8s Example |
|---|--------|-------------|-------------|
| 1 | **Initial Access** | Gaining first access to the cluster | Exposed dashboard, compromised image, stolen kubeconfig |
| 2 | **Execution** | Running malicious code | `kubectl exec`, deploying rogue containers |
| 3 | **Persistence** | Maintaining access | Backdoor containers, modified configs |
| 4 | **Privilege Escalation** | Gaining higher privileges | Exploiting privileged containers, hostPID |
| 5 | **Defense Evasion** | Avoiding detection | Clearing logs, disabling monitoring |
| 6 | **Credential Access** | Stealing credentials | Accessing Secrets, service account tokens |
| 7 | **Discovery** | Reconnaissance | Scanning kubelet, API server enumeration |
| 8 | **Lateral Movement** | Moving between resources | Pod-to-pod attacks, node compromise |
| 9 | **Collection** | Gathering data | Exfiltrating secrets, config data |
| 10 | **Impact** | Causing damage | Cryptomining, DoS, data destruction |

### Key Kubernetes Attack Techniques

| Technique | How It Works | CKS Mitigation |
|-----------|--------------|----------------|
| **Exposed Dashboard** | Unauthenticated access to K8s dashboard | Disable or require auth, use NetworkPolicy |
| **Compromised Images** | Malicious images pushed to registry | Image scanning (Trivy), allowlist registries |
| **Kubeconfig Theft** | Stealing cluster credentials | Protect kubeconfig, use short-lived tokens |
| **Default Service Account** | Abuse of auto-mounted SA tokens | `automountServiceAccountToken: false` |
| **Privileged Containers** | Container with host-level access | Pod Security Standards, drop capabilities |
| **Vulnerable Application** | RCE via app vulnerability | Network Policies, minimal images, scanning |
| **Cloud Metadata API** | Access to 169.254.169.254 | NetworkPolicy blocking metadata endpoint |
| **etcd Access** | Direct access to cluster datastore | mTLS for etcd, restrict network access |

---

## STRIDE Framework (Threat Modeling)

### Overview

Microsoft-developed mnemonic for categorizing security threats. Useful for understanding *why* security controls exist.

### The Six Threat Categories

| Letter | Threat | Definition | Violated Property |
|--------|--------|------------|-------------------|
| **S** | Spoofing | Pretending to be someone/something else | Authentication |
| **T** | Tampering | Unauthorized modification of data | Integrity |
| **R** | Repudiation | Denying an action occurred | Non-repudiation |
| **I** | Information Disclosure | Exposing data to unauthorized parties | Confidentiality |
| **D** | Denial of Service | Making a system unavailable | Availability |
| **E** | Elevation of Privilege | Gaining unauthorized capabilities | Authorization |

### STRIDE → Kubernetes Controls Mapping

| Threat | K8s Security Controls |
|--------|----------------------|
| **Spoofing** | RBAC, X.509 certificates, ServiceAccount tokens, OIDC |
| **Tampering** | `readOnlyRootFilesystem`, immutable containers, ValidatingAdmissionWebhook |
| **Repudiation** | Audit logging, audit policies |
| **Info Disclosure** | Secrets encryption at rest, NetworkPolicies, mTLS |
| **DoS** | ResourceQuotas, LimitRanges, NetworkPolicies |
| **Elevation of Privilege** | Pod Security Standards, `allowPrivilegeEscalation: false`, drop ALL capabilities |

---

## Quick Reference: Threat → Control → Exam Task

| Scenario | Framework Mapping | CKS Control |
|----------|-------------------|-------------|
| Pod accessing other pods | MITRE: Lateral Movement / STRIDE: I | NetworkPolicy (ingress/egress) |
| Container running as root | MITRE: Priv Escalation / STRIDE: E | `runAsNonRoot: true`, `runAsUser: 1000` |
| No audit trail | MITRE: Defense Evasion / STRIDE: R | Audit Policy in kube-apiserver |
| Secrets in plaintext | MITRE: Credential Access / STRIDE: I | EncryptionConfiguration for etcd |
| Privileged container | MITRE: Priv Escalation / STRIDE: E | Pod Security Admission (restricted) |
| Service account auto-mount | MITRE: Credential Access / STRIDE: S | `automountServiceAccountToken: false` |
| Unrestricted image sources | MITRE: Initial Access / STRIDE: T | ImagePolicyWebhook, OPA Gatekeeper |
| Container can write to fs | MITRE: Persistence / STRIDE: T | `readOnlyRootFilesystem: true` |

---

## CKS Exam Application

When analyzing a security scenario:

```
1. What attack technique/tactic is this? (MITRE ATT&CK)
2. What security property is violated? (STRIDE)
3. What Kubernetes control mitigates it? (Your answer)
```

### Example Walkthrough

**Scenario:** "Prevent pods in namespace `prod` from accessing the cloud metadata service"

1. **MITRE:** Initial Access → Instance Metadata API
2. **STRIDE:** Information Disclosure (leaking cloud credentials)
3. **Control:** NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
```

---

## Tools That Map to These Frameworks

| Tool | Purpose | MITRE/STRIDE Coverage |
|------|---------|----------------------|
| **Falco** | Runtime threat detection | Execution, Persistence, Priv Escalation |
| **Trivy** | Image vulnerability scanning | Initial Access (compromised images) |
| **kube-bench** | CIS benchmark compliance | All categories (hardening) |
| **OPA/Gatekeeper** | Policy enforcement | Tampering, Elevation of Privilege |
| **Audit Logging** | Activity tracking | Repudiation, all detection |
| **NetworkPolicies** | Network segmentation | Lateral Movement, Info Disclosure |
