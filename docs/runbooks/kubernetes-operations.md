# Kubernetes Operations Runbook

This runbook is for practicing production-style deployment operations after the Docker hands-on is stable.

## Prerequisites

- A Kubernetes cluster with NetworkPolicy support.
- Metrics Server installed for HPA.
- A container image pushed with an immutable Git SHA tag.
- Runtime secrets created outside Git.

## Secret Setup

Create secrets locally or through your platform secret manager. Do not commit secret values.

```bash
kubectl -n secure-learn create secret generic secure-learn-db \
  --from-literal=username="$DB_USER" \
  --from-literal=credential="$DB_PASS" \
  --from-literal=database="$DB_NAME"

kubectl -n secure-learn create secret generic secure-learn-app \
  --from-literal=token-signing-key="$AUTH_TOKEN_SECRET"
```

## Deploy

```bash
kubectl apply -k k8s/base
kubectl -n secure-learn set image deployment/secure-learn-app \
  app=ghcr.io/albert-einshutoin/secure-learn-app:$GIT_SHA
kubectl -n secure-learn rollout status deployment/secure-learn-app
```

## Verify

```bash
kubectl -n secure-learn get pods
kubectl -n secure-learn port-forward service/secure-learn-app 3000:3000
scripts/backend_hands_on_tests.sh
scripts/load_hands_on_tests.sh
```

## Rollback

```bash
kubectl -n secure-learn rollout undo deployment/secure-learn-app
kubectl -n secure-learn rollout status deployment/secure-learn-app
```

## SRE Evidence

- Readiness: `/health/ready`
- Liveness: `/health`
- Rollout status output
- Backend hands-on report
- Load hands-on report
- Postmortem template: `docs/templates/postmortem.md`
