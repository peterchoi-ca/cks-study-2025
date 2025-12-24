# Service Accounts

- Manually created a long lived API token for a SA
- https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/

```
apiVersion: v1
kind: Secret
metadata:
  name: build-robot-secret
  annotations:
    kubernetes.io/service-account.name: build-robot
type: kubernetes.io/service-account-token

apiVersion: v1
kind: ServiceAccount
metadata:
  name: build-robot
  namespace: default
secrets:
  - name: build-robot-secret # usually NOT present for a manually generated token
```

- create a role
    - multiple capabilities should be listed separately
- create a role binding
    - bind to an SA, user, or group

```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  creationTimestamp: "2025-12-24T20:45:26Z"
  name: developer
  namespace: blue
  resourceVersion: "3612"
  uid: dbcfa22f-b31b-42ec-814f-9763a330c33f
rules:
- apiGroups:
  - ""
  resourceNames:
  - dark-blue-app
  resources:
  - pods
  verbs:
  - get
  - watch
  - create
  - delete
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - get
  - watch
  - create
  - delete
  ```
