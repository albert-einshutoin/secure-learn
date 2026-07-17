#!/bin/bash
# Build release images, reject actionable HIGH/CRITICAL findings, and emit
# machine-readable scan reports plus SPDX SBOMs for the tagged source release.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/release}"
TRIVY_IMAGE='aquasec/trivy:0.72.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f'
SYFT_IMAGE='anchore/syft:v1.48.0@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c'
APP_IMAGE="secure-learn-app:$VERSION"
SURICATA_IMAGE="secure-learn-suricata:$VERSION"
IPS_IMAGE="secure-learn-ips-iptables:$VERSION"

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "VERSION must use semantic x.y.z form: $VERSION" >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"

docker build -t "$APP_IMAGE" "$ROOT_DIR/app"
docker build -t "$SURICATA_IMAGE" "$ROOT_DIR/suricata"
docker build -t "$IPS_IMAGE" "$ROOT_DIR/docker/ips-iptables"
"$ROOT_DIR/scripts/verify_ips_helper.sh" "$IPS_IMAGE"

scan_image() {
  local image="$1"
  local report="$2"

  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v secure-learn-trivy-cache:/root/.cache/trivy \
    "$TRIVY_IMAGE" image \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --exit-code 1 \
    --format json \
    "$image" > "$report"
}

generate_sbom() {
  local image="$1"
  local report="$2"

  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$SYFT_IMAGE" "docker:$image" -o spdx-json > "$report"
}

scan_image "$APP_IMAGE" "$OUTPUT_DIR/secure-learn-app-$VERSION.trivy.json"
scan_image "$SURICATA_IMAGE" "$OUTPUT_DIR/secure-learn-suricata-$VERSION.trivy.json"
scan_image "$IPS_IMAGE" "$OUTPUT_DIR/secure-learn-ips-iptables-$VERSION.trivy.json"
generate_sbom "$APP_IMAGE" "$OUTPUT_DIR/secure-learn-app-$VERSION.spdx.json"
generate_sbom "$SURICATA_IMAGE" "$OUTPUT_DIR/secure-learn-suricata-$VERSION.spdx.json"
generate_sbom "$IPS_IMAGE" "$OUTPUT_DIR/secure-learn-ips-iptables-$VERSION.spdx.json"

(
  cd "$OUTPUT_DIR"
  shasum -a 256 ./*.json > checksums.txt
)

echo "Release security evidence written to $OUTPUT_DIR"
