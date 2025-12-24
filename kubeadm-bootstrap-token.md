# Kubeadm bootstrap token

- Docs: `bootstrap token`
- Create bootstrap token using docs
- kubeadm token create -h
    - kubeadm token create --dry-run --ttl 2h --print-join-command

- the dry run will create an example join command,

```
kubeadm join 192.168.121.54:6443 --token ff0ku8.4yu2ygbvntpjoj2k --discovery-token-ca-cert-hash sha256:9bd5fa1155f6f895d2b8564015ee6638d4e80c19c1e9dd65140a2abb295b7b8f
```

- use the join command on the worker node

```
ssh node01

root@node01 ~ ➜  kubeadm join 192.168.121.54:6443 --token 07401b.f395accd246ae52d --discovery-token-ca-cert-hash sha256:9bd5fa1155f6f895d2b8564015ee6638d4e80c19c1e9dd65140a2abb295b7b8f
[preflight] Running pre-flight checks
[preflight] Reading configuration from the "kubeadm-config" ConfigMap in namespace "kube-system"...
[preflight] Use 'kubeadm init phase upload-config kubeadm --config your-config-file' to re-upload it.
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/instance-config.yaml"
[patches] Applied patch of type "application/strategic-merge-patch+json" to target "kubeletconfiguration"
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Starting the kubelet
[kubelet-check] Waiting for a healthy kubelet at http://127.0.0.1:10248/healthz. This can take up to 4m0s
[kubelet-check] The kubelet is healthy after 1.001935553s
[kubelet-start] Waiting for the kubelet to perform the TLS Bootstrap

This node has joined the cluster:
* Certificate signing request was sent to apiserver and a response was received.
* The Kubelet was informed of the new secure connection details.

Run 'kubectl get nodes' on the control-plane to see this node join the cluster.
```
