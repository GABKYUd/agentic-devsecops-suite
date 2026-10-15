# Playbook: Container / Kubernetes Compromise

**Trigger conditions:** anonymous or unauthorized access to the Kubernetes
API server, an unexpected `kubectl exec`/`attach` into a pod, a runtime
security alert consistent with container escape, a resource-usage spike
consistent with cryptomining, or a pod running an image from an untrusted
registry.

**Roles:** Platform/infra team (lead), SOC/IR, the app team owning the
affected workload.

## 1. Detect
- Kubernetes audit-log alerts for anonymous/unauthorized API server access.
- Unusual `exec`/`attach`/`port-forward` activity into pods that don't
  normally receive it.
- Runtime security tooling (behavioral, e.g. Falco-style) alerting on
  container-escape-pattern syscalls (host filesystem access, unexpected
  capability use).
- Unexpected outbound connections from a pod, or a sustained CPU spike
  consistent with cryptomining.

## 2. Analyze
- Identify the entry point: exposed API server, a compromised CI/CD
  credential, a vulnerable base image, or an overpermissioned service
  account token.
- Review which RBAC bindings/roles the compromised identity actually had —
  this defines blast radius.
- Determine whether the compromise stayed inside the container or escaped
  to the host node (host-level compromise is a materially bigger incident).
- Check for lateral movement to other namespaces or pods, and check image
  provenance/registry for anything pulled outside your approved sources.

## 3. Contain
- Apply a deny-all network policy to isolate the affected pod(s).
- Revoke the credential/service account token used for the access.
- If host-level (node) compromise is suspected: cordon and drain the node
  immediately so no new workloads schedule onto it.
- Block the source registry at the cluster level if a malicious image is
  confirmed.

## 4. Eradicate
- Delete the compromised pods/deployments and redeploy from known-good,
  version-controlled manifests and scanned images — don't try to "fix" a
  running compromised pod in place.
- Rotate any secrets mounted into the affected pod or namespace.
- Fix the RBAC overpermissioning that allowed the access in the first
  place.
- Check for persistence: malicious CronJobs, DaemonSets, or admission
  webhooks the attacker may have created.

## 5. Recover
- Redeploy through CI/CD with images that pass your scanning gate
  (Trivy-clean or equivalent).
- If a node was compromised at the host level, replace it entirely rather
  than trusting a cleaned node back into the pool.

## 6. Post-incident
- Enforce the NSA/CISA Kubernetes hardening baseline if gaps are found:
  non-root containers, least-privilege RBAC, no anonymous authentication on
  the API server, network policies by default, encrypted etcd.
- Add or verify an image-scanning gate in CI/CD so vulnerable/untrusted
  images are blocked before deploy, not caught after.
- Confirm audit logging and runtime security tooling are enabled
  cluster-wide, not just on the affected namespace.

## Ties to companion docs
- Offensive tooling: kube-hunter, Trivy — also legitimately used defensively
  (tools reference §9).
- Structural defense: NSA/CISA Kubernetes Hardening Guidance v1.2
  (devsecops-defense-playbooks.md §2).
