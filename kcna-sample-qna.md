# CKS Study Guide - Kubernetes Security Concepts

## Auditing and Logging

### Viewing Audit Logs
Kubernetes audit logs are **not** exposed as a kubectl resource. They're written directly to files on the control plane node.

**Access method:** SSH into the control plane node and read the file directly.
```bash
cat /var/log/audit.log
# or
tail -f /var/log/kubernetes/audit/audit.log
```

**Key API server flags:**
- `--audit-log-path` – Where logs are written
- `--audit-policy-file` – Defines what events get logged

**Audit policy levels:** `None`, `Metadata`, `Request`, `RequestResponse`

---

## Security Context Enforcement

### Responsible Component: Kubelet

The **kubelet** enforces security contexts at runtime by translating pod spec settings into instructions for the container runtime.

**Settings enforced:**
- `runAsUser` / `runAsGroup`
- `fsGroup`
- `readOnlyRootFilesystem`
- `allowPrivilegeEscalation`
- `capabilities`
- SELinux / AppArmor / seccomp profiles

**Component responsibilities:**
| Component | Role |
|-----------|------|
| API Server | Validates and admits pods (policy enforcement) |
| Controller Manager | Reconciles desired vs actual state |
| Scheduler | Decides node placement |
| Kubelet | **Enforces** security contexts at runtime |

---

## Authentication Methods

### Valid Kubernetes Authentication Methods

| Method | Description |
|--------|-------------|
| **X.509 Client Certificates** | CN = username, O = groups. Configured via `--client-ca-file` |
| **Bearer Tokens** | Static tokens, bootstrap tokens, service account JWTs |
| **OpenID Connect** | Integration with IdPs (Okta, Azure AD, Keycloak) |

**NOT valid:** SSH keys (used for node access, not API authentication)

**Other valid methods:**
- Authenticating proxy (`--requestheader-client-ca-file`)
- Webhook token authentication (`--authentication-token-webhook-config-file`)

---

## Compliance Frameworks

### Key Pillars
1. **Policies** – High-level statements defining organizational intent
2. **Procedures** – Step-by-step implementation instructions
3. **Controls** – Technical/administrative safeguards that enforce policies
4. **Audits** – Periodic verification of compliance

**Kubernetes mapping:**
- Policies → Pod Security Standards
- Procedures → Runbooks for patching, incident response
- Controls → NetworkPolicies, RBAC, admission controllers
- Audits → Audit logging, compliance scans

---

## Threat Modeling

### Framework Goals
1. **Identify threats** – Map attack vectors and adversaries
2. **Prioritize risks** – Assess likelihood and impact
3. **Define mitigations** – Determine countermeasures
4. **Validate security controls** – Verify effectiveness

### STRIDE vs MITRE ATT&CK

| Aspect | STRIDE | MITRE ATT&CK |
|--------|--------|--------------|
| Purpose | Threat modeling (design-time) | Adversary behavior knowledge base |
| Focus | What threats could exist | How attacks actually happen |
| Approach | Theoretical categorization | Empirical observation |
| When used | Design phase | Detection / operations |

**STRIDE categories:**
- **S**poofing (identity)
- **T**ampering (data integrity)
- **R**epudiation (deniability)
- **I**nformation Disclosure (confidentiality)
- **D**enial of Service (availability)
- **E**levation of Privilege (authorization)

---

## Supply Chain Security

### Software Bill of Materials (SBOM)
An inventory of all components, libraries, and dependencies in software.

**Purpose:**
- Dependency tracking (direct and transitive)
- Vulnerability identification (cross-reference with CVE databases)
- Rapid incident response (e.g., Log4Shell)
- Compliance requirements

**Common formats:** SPDX, CycloneDX, SWID tags

**Tools:** Syft, Grype, Trivy, Anchore

---

## Admission Controllers

### Security-Focused Admission Controllers

| Controller | Purpose |
|------------|---------|
| **PodSecurityPolicy** | Restricted pod creation based on security fields (deprecated 1.21, removed 1.25) |
| **DenyEscalatingExec** | Denies exec/attach to privileged containers (deprecated) |
| **Pod Security Admission** | Replacement for PSP (current) |
| **NodeRestriction** | Limits kubelet API access |
| **ImagePolicyWebhook** | External image validation |

**NOT security-enhancing:**
- `AlwaysAdmit` – Admits everything (no security benefit)
- `EventRateLimit` – Rate limiting, not pod security

**External solutions:** OPA/Gatekeeper, Kyverno

---

## Denial of Service Prevention

### Valid DoS Prevention Strategies

| Strategy | How it helps |
|----------|--------------|
| **Limit API server requests** | Protects control plane (`--max-requests-inflight`, API Priority and Fairness) |
| **Horizontal Pod Autoscaling** | Absorbs traffic spikes automatically |
| **LimitRange / ResourceQuota** | Prevents resource exhaustion per namespace |
| **PodDisruptionBudgets** | Maintains availability during disruptions |

**Increases DoS risk (avoid):**
- Disabling network policies
- Unbounded resource limits

---

## Network Security

### Man-in-the-Middle Mitigation
**Solution: TLS encryption for communications**

TLS provides:
- **Encryption** – Traffic unreadable to interceptors
- **Authentication** – Certificates verify identity
- **Integrity** – Tampering detected cryptographically

**Where to implement TLS in Kubernetes:**
- API server ↔ etcd
- API server ↔ kubelet
- Pod ↔ Pod (service mesh or application-level)
- Ingress ↔ backend services
- Client ↔ API server

**Best practice:** mTLS (mutual TLS) via service mesh (Istio, Linkerd, Cilium)

### "Attacker on the Network" Threat Model
**Primary target:** Network traffic between services and pods

**Attack capabilities:**
- Eavesdropping on unencrypted traffic
- MITM attacks
- Traffic injection
- Service impersonation

**Mitigations:**
- mTLS via service mesh
- NetworkPolicies
- Encrypted CNI (WireGuard in Cilium, Calico encryption)

---

## Trust Boundaries

### Key Kubernetes Trust Boundaries

| Boundary | Description | Controls |
|----------|-------------|----------|
| **Cluster** | External vs internal traffic | Ingress, firewalls, API authn |
| **Node** | Per-node isolation | NodeRestriction, minimal node access |
| **Namespace** | Logical multi-tenant separation (soft boundary) | RBAC, NetworkPolicies, ResourceQuotas, PSA |
| **Pod** | Pod-to-pod isolation | NetworkPolicies, service mesh, mTLS |
| **Container** | Weakest isolation (shared kernel) | Seccomp, AppArmor/SELinux, capabilities |
| **Control plane / Data plane** | API server, etcd vs kubelets, workloads | TLS, RBAC, etcd encryption |
| **User / Service account** | Different identity trust levels | RBAC, separate SAs, disable token automount |

**Defense in depth:** Don't rely on a single boundary for security.

---

## Privilege Escalation

### Common Kubernetes Privilege Escalation Techniques

| Technique | Description |
|-----------|-------------|
| **etcd access** | Read secrets, extract service account tokens |
| **Overly permissive RBAC** | `pods/exec`, `secrets/get`, `*` verbs |
| **Container escape** | Privileged containers, hostPID/hostNetwork |
| **hostPath mounts** | Access node filesystem, kubelet credentials |
| **Writable SA token mounts** | Token theft |
| **Node compromise** | Kubelet credentials → API access |
| **Create pods permission** | Spawn privileged pod → escape to node |

**Defenses:**
- Principle of least privilege
- Encrypt etcd at rest
- Restrict etcd network access
- Regular RBAC audits
- Disable service account token automounting

---

## Quick Reference

### Key Ports
| Component | Port |
|-----------|------|
| API Server | 6443 |
| etcd | 2379-2380 |
| Kubelet | 10250 |
| Scheduler | 10259 |
| Controller Manager | 10257 |

### Important API Server Flags
```
--audit-log-path
--audit-policy-file
--client-ca-file
--encryption-provider-config
--enable-admission-plugins
--oidc-issuer-url
--max-requests-inflight
```

### Pod Security Standards (PSA)
| Level | Description |
|-------|-------------|
| **Privileged** | Unrestricted (no restrictions) |
| **Baseline** | Minimally restrictive, prevents known privilege escalations |
| **Restricted** | Heavily restricted, hardening best practices |

### Modes
- `enforce` – Reject violations
- `audit` – Log violations
- `warn` – Warn on violations
