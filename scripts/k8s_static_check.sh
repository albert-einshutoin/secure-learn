#!/bin/bash
# Static checks for Kubernetes manifests without requiring a cluster.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K8S_DIR="$ROOT_DIR/k8s/base"

required_files=(
  kustomization.yaml
  namespace.yaml
  app-deployment.yaml
  app-service.yaml
  postgres-statefulset.yaml
  networkpolicy.yaml
  hpa.yaml
)

for file in "${required_files[@]}"; do
  if [ ! -f "$K8S_DIR/$file" ]; then
    echo "Missing Kubernetes manifest: $file"
    exit 1
  fi
done

if grep -RInE 'image: .*:latest\b' "$K8S_DIR"; then
  echo "Kubernetes manifests must not use latest image tags."
  exit 1
fi

for pattern in 'readinessProbe:' 'livenessProbe:' 'resources:' 'securityContext:' 'NetworkPolicy' 'HorizontalPodAutoscaler'; do
  if ! grep -Rqs "$pattern" "$K8S_DIR"; then
    echo "Kubernetes manifests missing required pattern: $pattern"
    exit 1
  fi
done

if grep -RInE 'value:[[:space:]]*[^{}[:space:]]+' "$K8S_DIR" | grep -Ei 'PASS|TOKEN|SECRET|CREDENTIAL'; then
  echo "Secret-like Kubernetes environment values must use secretKeyRef."
  exit 1
fi

echo "Kubernetes static checks passed."
