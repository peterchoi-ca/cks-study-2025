# CKS Study Notes: Complete Security Guide

## Table of Contents
1. [Security Frameworks](#security-frameworks)
   - [MITRE ATT&CK (Containers)](#mitre-attck)
   - [STRIDE Threat Modeling](#stride)
2. [Compliance Frameworks](#compliance-frameworks)
   - [CIS Benchmarks & kube-bench](#cis-benchmarks)
   - [HIPAA / PCI DSS / GDPR](#other-compliance)
3. [Control Plane Hardening](#control-plane-hardening)
4. [Audit Logging](#audit-logging)
5. [Linux Security Primitives](#linux-security)
   - [DAC (UID/GID)](#dac)
   - [SELinux](#selinux)
   - [Privileged vs Unprivileged](#privileged)
   - [Linux Capabilities](#capabilities)
   - [AppArmor](#apparmor)
   - [Seccomp](#seccomp)
6. [Quick Reference Tables](#quick-reference)

---

# 1. Security Frameworks {#security-frameworks}

## MITRE ATT&CK Framework (Containers Matrix) {#mitre-attck}

### Overview
A knowledge base of adversary tactics and techniques used to attack container and Kubernetes environments. Helps defenders understand how attacks happen and what controls to implement.

### Attack Lifecycle (Tactics) — Containers Matrix

The Containers Matrix has **9 tactics** (not the full 14 from Enterprise):

| # | Tactic | Description | K8s Example |
|---|--------|-------------|-------------|
| 1 | **Initial Access** | Gaining first access to cluster | Exposed dashboard, compromised image, stolen kubeconfig |
| 2 | **Execution** | Running malicious code | `kubectl exec`, deploying rogue containers |
| 3 | **Persistence** | Maintaining access | Backdoor containers, CronJobs, modified configs |
| 4 | **Privilege Escalation** | Gaining higher privileges | Escape to host, privileged containers, hostPID |
| 5 | **Defense Evasion** | Avoiding detection | Clearing logs, disabling tools, masquerading |
| 6 | **Credential Access** | Stealing credentials | Brute force, unsecured credentials, stealing tokens |
| 7 | **Discovery** | Reconnaissance | Container/resource discovery, network scanning |
| 8 | **Lateral Movement** | Moving between resources | Application access tokens |
| 9 | **Impact** | Causing damage | Cryptomining, DoS, data destruction |

**Note:** "Collection", "Reconnaissance", "Resource Development", "Command and Control", and "Exfiltration" are NOT in the Containers matrix.

### Key Kubernetes Attack Techniques

| Technique | How It Works | CKS Mitigation |
|-----------|--------------|----------------|
| **Exposed Dashboard** | Unauthenticated access to K8s dashboard | Disable or require auth, NetworkPolicy |
| **Compromised Images** | Malicious images pushed to registry | Image scanning (Trivy), allowlist registries |
| **Kubeconfig Theft** | Stealing cluster credentials | Protect kubeconfig, short-lived tokens |
| **Default Service Account** | Abuse of auto-mounted SA tokens | `automountServiceAccountToken: false` |
| **Privileged Containers** | Container with host-level access | Pod Security Standards, drop capabilities |
| **Vulnerable Application** | RCE via app vulnerability | NetworkPolicies, minimal images, scanning |
| **Cloud Metadata API** | Access to 169.254.169.254 | NetworkPolicy blocking metadata endpoint |
| **etcd Access** | Direct access to cluster datastore | mTLS for etcd, restrict network access |

### MITRE Tactic → CKS Topic Mapping

| MITRE Tactic | CKS Topic |
|--------------|-----------|
| Initial Access | Secure ingress, NetworkPolicies, disable anonymous auth |
| Execution | Pod Security Standards, securityContext, Admission Controllers |
| Persistence | Audit logging, immutable containers, RBAC |
| Privilege Escalation | Limit capabilities, non-root, no privileged pods |
| Credential Access | Secrets management, disable SA automounting |
| Lateral Movement | NetworkPolicies, service mesh, mTLS |

---

## STRIDE Framework (Threat Modeling) {#stride}

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

### Practical Application

When analyzing a security scenario:
```
1. What attack technique/tactic is this? (MITRE ATT&CK)
2. What security property is violated? (STRIDE)
3. What Kubernetes control mitigates it? (Your answer)
```

**Example:** "Prevent pods from accessing the node's metadata service"
- MITRE: Initial Access → Instance Metadata API
- STRIDE: Information Disclosure
- Control: NetworkPolicy blocking 169.254.169.254

---

# 2. Compliance Frameworks {#compliance-frameworks}

## CKS Exam Relevance

| Framework | Directly Tested? | CKS Relevance |
|-----------|------------------|---------------|
| **CIS Benchmarks** | ✅ YES | Run kube-bench, remediate findings |
| HIPAA | ❌ No | Context only (healthcare) |
| PCI DSS | ❌ No | Context only (payment cards) |
| GDPR | ❌ No | Context only (EU data privacy) |

---

## CIS Benchmarks & kube-bench {#cis-benchmarks}

### What CIS Kubernetes Benchmark Covers

| Section | Components |
|---------|------------|
| 1.x | Control Plane (kube-apiserver, controller-manager, scheduler) |
| 2.x | etcd |
| 3.x | Control Plane Configuration (auth, logging) |
| 4.x | Worker Nodes (kubelet, kube-proxy) |
| 5.x | Policies (RBAC, Pod Security, NetworkPolicies, Secrets) |

### kube-bench Commands

```bash
# Run full CIS benchmark
kube-bench

# Run against specific target
kube-bench run --targets=master
kube-bench run --targets=node
kube-bench run --targets=etcd

# Check specific benchmark item
kube-bench run --check=1.2.1

# Run as container
docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro \
  aquasec/kube-bench:latest

# Run as Kubernetes job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench
```

### Reading kube-bench Output

```
[INFO] 1 Control Plane Security Configuration
[PASS] 1.1.1 Ensure API server pod spec file permissions are 644
[FAIL] 1.1.2 Ensure API server pod spec file ownership is root:root
[WARN] 1.1.3 Ensure controller manager pod spec permissions are 644

== Remediations master ==
1.1.2 Run: chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml

== Summary master ==
42 checks PASS | 3 checks FAIL | 11 checks WARN
```

### Config File Locations

| Component | Config Location |
|-----------|-----------------|
| kube-apiserver | `/etc/kubernetes/manifests/kube-apiserver.yaml` |
| kube-controller-manager | `/etc/kubernetes/manifests/kube-controller-manager.yaml` |
| kube-scheduler | `/etc/kubernetes/manifests/kube-scheduler.yaml` |
| etcd | `/etc/kubernetes/manifests/etcd.yaml` |
| kubelet | `/var/lib/kubelet/config.yaml` |

---

## Other Compliance Frameworks {#other-compliance}

### HIPAA (Healthcare)

| HIPAA Requirement | K8s Implementation |
|-------------------|-------------------|
| Access controls | RBAC, ServiceAccount restrictions |
| Audit controls | Audit logging on API server |
| Transmission security | mTLS, TLS for all endpoints |
| Encryption | Secrets encryption at rest |

### PCI DSS (Payment Cards)

| PCI DSS Requirement | K8s Implementation |
|--------------------|-------------------|
| Network segmentation | NetworkPolicies |
| No vendor defaults | Disable default SA tokens |
| Protect stored data | Secrets encryption at rest |
| Encrypt transmission | mTLS, TLS ingress |
| Restrict access | RBAC with least privilege |
| Track and monitor | Audit logging, Falco |

### GDPR (EU Data Privacy)

| GDPR Principle | K8s Implementation |
|----------------|-------------------|
| Data minimization | Minimal container images |
| Integrity & confidentiality | Encryption, NetworkPolicies, RBAC |
| Accountability | Audit logging |

---

# 3. Control Plane Hardening {#control-plane-hardening}

## Flags to Set to `false` (Minimize Attack Surface)

| Component | Flag | Value | CIS ID | Rationale |
|-----------|------|-------|--------|-----------|
| kube-scheduler | `--profiling` | `false` | 1.4.1 | Profiling exposes system details |
| kube-controller-manager | `--profiling` | `false` | 1.3.2 | Profiling exposes system details |
| kube-apiserver | `--profiling` | `false` | 1.2.21 | Profiling exposes system details |
| kube-apiserver | `--anonymous-auth` | `false` | 1.2.1 | Prevent unauthenticated access |

## Additional Hardening Flags

| Component | Flag | Recommended Value |
|-----------|------|-------------------|
| kube-scheduler | `--bind-address` | `127.0.0.1` |
| kube-controller-manager | `--bind-address` | `127.0.0.1` |
| kube-apiserver | `--kubelet-certificate-authority` | Path to CA |
| kube-apiserver | `--tls-min-version` | `VersionTLS12` |
| kubelet | `--anonymous-auth` | `false` |
| kubelet | `--protect-kernel-defaults` | `true` |

## Example: Hardened kube-scheduler

Edit `/etc/kubernetes/manifests/kube-scheduler.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-scheduler
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-scheduler
    - --authentication-kubeconfig=/etc/kubernetes/scheduler.conf
    - --authorization-kubeconfig=/etc/kubernetes/scheduler.conf
    - --bind-address=127.0.0.1
    - --kubeconfig=/etc/kubernetes/scheduler.conf
    - --profiling=false
```

## Verify Hardening

```bash
# Check scheduler profiling
ps -ef | grep kube-scheduler | grep profiling

# Check with kube-bench
kube-bench run --targets=master | grep -A5 "1.4"

# Check API server anonymous auth
ps -ef | grep kube-apiserver | grep anonymous-auth
```

---

# 4. Audit Logging {#audit-logging}

## Required API Server Flags

| Flag | Purpose |
|------|---------|
| `--audit-policy-file` | Path to audit policy YAML (required) |
| `--audit-log-path` | Where to write audit logs |
| `--audit-log-maxage` | Max days to retain logs |
| `--audit-log-maxbackup` | Max number of log files to keep |
| `--audit-log-maxsize` | Max size in MB before rotation |

## Audit Levels

| Level | What's Logged |
|-------|---------------|
| `None` | Nothing |
| `Metadata` | User, timestamp, resource, verb — no body |
| `Request` | Metadata + request body |
| `RequestResponse` | Metadata + request body + response body |

## Basic Audit Policy

Create `/etc/kubernetes/audit/audit-policy.yaml`:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
```

## Advanced Audit Policy Examples

**Log secrets at RequestResponse, configmaps at Metadata:**
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["configmaps"]
  - level: None
    users: ["system:kube-scheduler"]
```

**Log specific namespace:**
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    namespaces: ["production"]
  - level: Metadata
```

**Log everything except reads:**
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: None
    verbs: ["get", "list", "watch"]
  - level: RequestResponse
```

## API Server Configuration

Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    # ... existing flags ...
    - --audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
    - --audit-log-path=/var/log/kubernetes/audit/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
    volumeMounts:
    - name: audit-policy
      mountPath: /etc/kubernetes/audit
      readOnly: true
    - name: audit-log
      mountPath: /var/log/kubernetes/audit
  volumes:
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit
      type: DirectoryOrCreate
  - name: audit-log
    hostPath:
      path: /var/log/kubernetes/audit
      type: DirectoryOrCreate
```

## CKS Exam Workflow for Audit Logging

```bash
# 1. Create directories
mkdir -p /etc/kubernetes/audit
mkdir -p /var/log/kubernetes/audit

# 2. Create audit policy
cat <<EOF > /etc/kubernetes/audit/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
EOF

# 3. Edit API server manifest (add flags + volumes)
vim /etc/kubernetes/manifests/kube-apiserver.yaml

# 4. Wait for API server to restart
watch crictl ps | grep kube-apiserver

# 5. Verify logs are being written
tail -f /var/log/kubernetes/audit/audit.log
```

## Audit Logging Checklist

- [ ] Audit policy file exists and is valid YAML
- [ ] `--audit-policy-file` points to correct path
- [ ] `--audit-log-path` points to writable location
- [ ] Volume mount for policy file (read-only)
- [ ] Volume mount for log directory (read-write)
- [ ] hostPath volumes defined for both
- [ ] API server restarted successfully

---

# 5. Linux Security Primitives {#linux-security}

All of these are configured via **securityContext** in Pod/Container specs or through runtime security profiles.

## Overview

| Primitive | What It Does | CKS Relevance |
|-----------|--------------|---------------|
| DAC (UID/GID) | File/process permissions based on user/group | ✅ `runAsUser`, `runAsGroup`, `fsGroup` |
| SELinux | Mandatory access control via labels | ✅ `seLinuxOptions` |
| Privileged Mode | Full host access (dangerous) | ✅ Must restrict with Pod Security |
| Linux Capabilities | Granular root privileges | ✅ `capabilities.drop`, `capabilities.add` |
| AppArmor | Per-program restrictions | ✅ Annotations on pods |
| Seccomp | System call filtering | ✅ `seccompProfile` |

---

## Discretionary Access Control (DAC) — UID/GID

Controls file and process permissions based on user ID and group ID.

### SecurityContext Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000        # Run as non-root user
    runAsGroup: 3000       # Primary group
    fsGroup: 2000          # Volume ownership group
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsNonRoot: true   # Enforce non-root
      allowPrivilegeEscalation: false
```

### Key Fields

| Field | Level | Purpose |
|-------|-------|---------|
| `runAsUser` | Pod/Container | UID to run processes as |
| `runAsGroup` | Pod/Container | Primary GID for processes |
| `fsGroup` | Pod only | GID for volume ownership |
| `runAsNonRoot` | Pod/Container | Fail if image runs as root |
| `supplementalGroups` | Pod only | Additional GIDs |

---

## SELinux (Security Enhanced Linux)

Mandatory Access Control (MAC) using security labels. Objects and processes get labels; policy controls access.

### SecurityContext Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: selinux-demo
spec:
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"   # MCS label
  containers:
  - name: app
    image: nginx
    securityContext:
      seLinuxOptions:
        type: "container_t"    # SELinux type
        level: "s0:c123,c456"
```

### SELinux Label Components

| Component | Example | Purpose |
|-----------|---------|---------|
| `user` | `system_u` | SELinux user |
| `role` | `system_r` | SELinux role |
| `type` | `container_t` | Type enforcement |
| `level` | `s0:c123,c456` | MCS/MLS level |

---

## Privileged vs Unprivileged Containers

### Privileged Mode (DANGEROUS)

```yaml
# DON'T DO THIS unless absolutely necessary
securityContext:
  privileged: true   # Full host access, all capabilities
```

**Privileged containers can:**
- Access all host devices
- Bypass all security modules
- Load kernel modules
- Modify host network/filesystem

### Unprivileged (Default & Recommended)

```yaml
securityContext:
  privileged: false                    # Default
  allowPrivilegeEscalation: false      # Prevent setuid
  readOnlyRootFilesystem: true         # Immutable container
  runAsNonRoot: true
```

---

## Linux Capabilities

Fine-grained privileges instead of all-or-nothing root access.

### Drop All, Add Only What's Needed

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: capabilities-demo
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      capabilities:
        drop:
          - ALL                 # Drop all capabilities first
        add:
          - NET_BIND_SERVICE    # Only add what's needed
```

### Common Capabilities

| Capability | Purpose | Usually Needed? |
|------------|---------|-----------------|
| `NET_BIND_SERVICE` | Bind to ports < 1024 | Sometimes |
| `NET_RAW` | Raw sockets (ping) | Rarely |
| `SYS_ADMIN` | Many admin operations | ❌ Dangerous |
| `SYS_PTRACE` | Debug processes | ❌ Rarely |
| `CHOWN` | Change file ownership | Rarely |
| `DAC_OVERRIDE` | Bypass file permissions | ❌ Dangerous |
| `SETUID/SETGID` | Change UID/GID | ❌ Drop this |

### CKS Best Practice

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]    # Always start here
```

---

## AppArmor

Restricts program capabilities using profiles. Configured via **annotations** (not securityContext).

### Apply AppArmor Profile

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-demo
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/my-profile
spec:
  containers:
  - name: app
    image: nginx
```

### Annotation Format

```
container.apparmor.security.beta.kubernetes.io/<container_name>: <profile>
```

### Profile Types

| Value | Meaning |
|-------|---------|
| `runtime/default` | Container runtime's default profile |
| `localhost/<profile>` | Custom profile loaded on node |
| `unconfined` | No AppArmor restrictions |

### Check Available Profiles on Node

```bash
# List loaded profiles
cat /sys/kernel/security/apparmor/profiles

# Load a profile
apparmor_parser -q /etc/apparmor.d/my-profile
```

### Example AppArmor Profile

```
#include <tunables/global>

profile my-profile flags=(attach_disconnected) {
  #include <abstractions/base>
  
  # Deny write to /etc
  deny /etc/** w,
  
  # Allow read from /var
  /var/** r,
  
  # Allow network
  network inet tcp,
}
```

---

## Seccomp (Secure Computing Mode)

Filters system calls a process can make to the kernel.

### SecurityContext Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-demo
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault    # Use container runtime's default
  containers:
  - name: app
    image: nginx
```

### Profile Types

| Type | Meaning |
|------|---------|
| `Unconfined` | No seccomp filtering (not recommended) |
| `RuntimeDefault` | Container runtime's default profile |
| `Localhost` | Custom profile from node |

### Custom Seccomp Profile

```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/my-seccomp.json
```

Profile location: `/var/lib/kubelet/seccomp/profiles/my-seccomp.json`

### Example Seccomp Profile (JSON)

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "exit", "exit_group", "openat"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### Seccomp Actions

| Action | Effect |
|--------|--------|
| `SCMP_ACT_ALLOW` | Allow the syscall |
| `SCMP_ACT_ERRNO` | Deny and return error |
| `SCMP_ACT_KILL` | Kill the process |
| `SCMP_ACT_LOG` | Allow but log |

---

## Complete Hardened Pod Example

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache/nginx
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

---

## Pod Security Standards Mapping

| PSS Level | Capabilities | Privilege Escalation | Seccomp | SELinux |
|-----------|-------------|---------------------|---------|---------|
| **Privileged** | Any | Any | Any | Any |
| **Baseline** | Drop some dangerous | Allowed | Any | Any |
| **Restricted** | Drop ALL, limited add | `false` | `RuntimeDefault` or stricter | Any |

---

## CKS Exam Commands

```bash
# Check if AppArmor is enabled
aa-status

# Check seccomp support
grep SECCOMP /boot/config-$(uname -r)

# Verify pod security context
kubectl get pod <name> -o jsonpath='{.spec.securityContext}'

# Check container security context
kubectl get pod <name> -o jsonpath='{.spec.containers[0].securityContext}'

# View seccomp profiles on node
ls /var/lib/kubelet/seccomp/

# Trace syscalls (useful for creating seccomp profiles)
strace -c -p <pid>
```

---

# 6. Quick Reference Tables {#quick-reference}

## Threat → Control → Exam Task

| Scenario | Framework Mapping | CKS Control |
|----------|-------------------|-------------|
| Pod accessing other pods | MITRE: Lateral Movement / STRIDE: I | NetworkPolicy |
| Container running as root | MITRE: Priv Escalation / STRIDE: E | `runAsNonRoot: true` |
| No audit trail | MITRE: Defense Evasion / STRIDE: R | Audit Policy |
| Secrets in plaintext | MITRE: Credential Access / STRIDE: I | EncryptionConfiguration |
| Privileged container | MITRE: Priv Escalation / STRIDE: E | Pod Security Admission |
| Service account auto-mount | MITRE: Credential Access / STRIDE: S | `automountServiceAccountToken: false` |
| Unrestricted image sources | MITRE: Initial Access / STRIDE: T | ImagePolicyWebhook, OPA |
| Container can write to fs | MITRE: Persistence / STRIDE: T | `readOnlyRootFilesystem: true` |

## Compliance → CKS Controls Matrix

| Control | CIS | HIPAA | PCI | GDPR |
|---------|-----|-------|-----|------|
| RBAC | ✅ | ✅ | ✅ | ✅ |
| Network Policies | ✅ | ✅ | ✅ | ✅ |
| Audit Logging | ✅ | ✅ | ✅ | ✅ |
| Secrets Encryption | ✅ | ✅ | ✅ | ✅ |
| Pod Security | ✅ | ✅ | ✅ | ✅ |
| Image Scanning | ✅ | ✅ | ✅ | ✅ |
| TLS/mTLS | ✅ | ✅ | ✅ | ✅ |
| Disable Anonymous Auth | ✅ | ✅ | ✅ | - |
| Disable Profiling | ✅ | - | - | - |

## Tools That Map to Frameworks

| Tool | Purpose | Coverage |
|------|---------|----------|
| **kube-bench** | CIS benchmark compliance | All hardening |
| **Falco** | Runtime threat detection | Execution, Persistence, Priv Escalation |
| **Trivy** | Image vulnerability scanning | Initial Access (compromised images) |
| **OPA/Gatekeeper** | Policy enforcement | Tampering, Elevation of Privilege |
| **Audit Logging** | Activity tracking | Repudiation, all detection |
| **NetworkPolicies** | Network segmentation | Lateral Movement, Info Disclosure |

## Linux Security Quick Reference

| Primitive | Config Location | Key Settings |
|-----------|-----------------|--------------|
| **UID/GID** | `securityContext` | `runAsUser`, `runAsGroup`, `fsGroup`, `runAsNonRoot` |
| **SELinux** | `securityContext.seLinuxOptions` | `type`, `level`, `user`, `role` |
| **Privileged** | `securityContext` | `privileged: false` (always) |
| **Capabilities** | `securityContext.capabilities` | `drop: [ALL]`, then add only needed |
| **AppArmor** | Pod annotation | `container.apparmor.security.beta.kubernetes.io/<c>: localhost/<profile>` |
| **Seccomp** | `securityContext.seccompProfile` | `type: RuntimeDefault` or `Localhost` |

## Hardened Container Checklist

- [ ] `runAsNonRoot: true`
- [ ] `runAsUser: <non-zero>`
- [ ] `allowPrivilegeEscalation: false`
- [ ] `readOnlyRootFilesystem: true`
- [ ] `capabilities.drop: [ALL]`
- [ ] `privileged: false` (or omit, it's default)
- [ ] `seccompProfile.type: RuntimeDefault`
- [ ] AppArmor annotation (if available)
