# General

- https://kubernetes.io/docs/concepts/security/

- the 4 C's of cloud security: cloud, cluster, container, code

# CIS Benchmarks
- .`/script -i -rd /var/www/html -rp index -nts` # run the tool in interactive mode, saved to a directory, with report prefix "index" which is html file.

# Kube Bench (Aqua Sec)
- kube-bench run
- kube-bench --check=1"1.3.1"

```
All these tests are part of the control plane Kubernetes component tests, such as kube-controller-manager, kube-scheduler and etcd. These are grouped under a target test group called master in kube-bench. You can only run the tests for this target group using the command:

kube-bench run --targets="master"

The list of available targets are [master node controlplane etcd policies]. You can select multiple targets from the list to be invoked, comma-separated as below:

kube-bench run --targets="master,etcd"
```