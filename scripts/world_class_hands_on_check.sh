#!/bin/bash
# Generate a hands-on evidence checklist for advanced Secure Learn topics.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOPIC="${1:-all}"
REPORT_DIR="${REPORT_DIR:-$ROOT_DIR/reports/world_class_hands_on_$(date +%Y%m%d_%H%M%S)}"
REPORT_FILE="$REPORT_DIR/summary.md"

mkdir -p "$REPORT_DIR"

verified_count=0
present_count=0
documented_count=0
warn_count=0

record() {
  local status="$1"
  local topic="$2"
  local detail="$3"

  case "$status" in
    VERIFIED) verified_count=$((verified_count + 1)) ;;
    PRESENT) present_count=$((present_count + 1)) ;;
    DOCUMENTED) documented_count=$((documented_count + 1)) ;;
    WARN) warn_count=$((warn_count + 1)) ;;
  esac

  printf '| %s | %s | %s |\n' "$status" "$topic" "$detail" >> "$REPORT_FILE"
  printf '[%s] %s - %s\n' "$status" "$topic" "$detail"
}

has_file() {
  local file="$1"
  local topic="$2"
  local detail="$3"
  if [[ -f "$ROOT_DIR/$file" ]]; then
    record PRESENT "$topic" "$detail: $file"
  else
    record WARN "$topic" "Missing expected file: $file"
  fi
}

has_text() {
  local pattern="$1"
  local topic="$2"
  local detail="$3"
  # Excluding this checker is essential: its own search patterns are not
  # curriculum evidence. Generated reports and dependency trees are excluded
  # for the same reason.
  if grep -R -E -q \
    --exclude='world_class_hands_on_check.sh' \
    --exclude-dir=.git \
    --exclude-dir=node_modules \
    --exclude-dir=reports \
    "$pattern" "$ROOT_DIR"; then
    record DOCUMENTED "$topic" "$detail"
  else
    record WARN "$topic" "Coverage text not found: $pattern"
  fi
}

section() {
  local topic="$1"
  local abstract="$2"
  local concrete="$3"

  {
    echo
    echo "## $topic"
    echo
    echo "**Abstract:** $abstract"
    echo
    echo "**Concrete hands-on:** $concrete"
    echo
    echo "| Status | Check | Evidence |"
    echo "|--------|-------|----------|"
  } >> "$REPORT_FILE"
}

run_linux() {
  section "linux" "OS資源、隔離、syscall、capabilityを障害調査と防御境界として読む。" "toolboxでss/lsof/straceを使い、composeのcap_drop/no-new-privilegesを確認する。"
  has_text "strace" linux "strace coverage exists"
  has_text "cap_drop" linux "container capability hardening exists"
  has_text "no-new-privileges" linux "runtime no-new-privileges is configured"
}

run_network() {
  section "network" "L3/L4/L7/edgeの観測点を分け、アプリに届く前の障害を説明する。" "edge proxy、DNS、TLS probe、ssを使ってdirect/proxyの違いを確認する。"
  has_file "learning/nginx/edge.conf" network "edge proxy config exists"
  has_text "SYN backlog|TCP retransmission|L4/L7 load balancer" network "advanced network topics are documented"
}

run_edge() {
  section "edge" "BGP/Anycast/CDN/QUICを、実インターネットを操作せず設計と観測で学ぶ。" "edge routing図、必要ログ、vendor escalation templateを作る。"
  has_text "BGP|Anycast|QUIC|HTTP/3|CDN" edge "internet edge topics are documented"
}

run_kubernetes() {
  section "kubernetes" "Kubernetesをpolicy、identity、network、upgradeを持つplatformとして扱う。" "k8s_static_checkを実行し、Admission/RBAC/NetworkPolicy/PodSecurityのreview観点を作る。"
  "$ROOT_DIR/scripts/k8s_static_check.sh" >/dev/null
  record VERIFIED kubernetes "k8s static guardrail check passed"
  has_text "Admission Controller|Helm|Kustomize|Operator|CRD" kubernetes "platform topics are documented"
}

run_cloud() {
  section "cloud" "IAM、KMS、network、audit、org guardrailでcloud変更のblast radiusを下げる。" "sample policy reviewとしてwildcard、public exposure、missing auditを指摘する。"
  has_text "AWS IAM|GCP IAM|Azure IAM|CloudTrail|Org policy|SCP" cloud "cloud security coverage exists"
  has_file "SECURITY.md" cloud "security disclosure entry point exists"
}

run_iac() {
  section "iac" "IaC変更をplan、policy、state、drift、environment separationでreviewする。" "Terraform/OPA/Conftest相当の禁止条件と例外申請を作る。"
  has_text "Terraform|OPA|Conftest|drift detection|state management" iac "IaC policy topics are documented"
}

run_observability() {
  section "observability" "metrics/logs/tracesをSLO判断へ変換し、alert fatigueを減らす。" "Prometheus、Grafana、OpenTelemetry、burn-rate条件を確認する。"
  has_file "learning/prometheus/prometheus.yml" observability "Prometheus config exists"
  has_file "learning/otel/otel-collector.yml" observability "OpenTelemetry collector config exists"
  has_text "burn-rate|high cardinality|RED metrics|USE metrics" observability "advanced observability coverage exists"
}

run_distributed() {
  section "distributed" "重複、遅延、順序入れ替わり、部分失敗を前提にbackend契約を作る。" "Redisをqueue代替にし、idempotency、backpressure、retry/backoffを設計する。"
  has_text "learning-redis" distributed "Redis learning service exists"
  has_text "Kafka|PubSub|Temporal|idempotency|backpressure" distributed "distributed systems topics are documented"
}

run_backend() {
  section "backend" "schema変更、同時実行、pagination、API互換性をproduction contractとして守る。" "unit/integration/OpenAPI/loadの結果をmigration/rollback設計へ接続する。"
  has_file "docs/api/openapi.yaml" backend "OpenAPI contract exists"
  has_file "app/test/openapi.contract.test.js" backend "OpenAPI contract test exists"
  has_text "schema migration|race condition|pagination|API versioning" backend "backend production topics are documented"
}

run_api_security() {
  section "api-security" "BOLA/SSRF/upload/RCEをpayloadではなく認可、egress、file、sandbox境界として扱う。" "安全なred test、control、detection、CWE/CVSSを作る。"
  has_text "SSRF|IDOR|BOLA|unsafe upload|RCE" api-security "advanced API security topics are documented"
  has_file "docs/curriculum/owasp-api-security-track.md" api-security "OWASP API track exists"
}

run_supply_chain() {
  section "supply-chain" "依存、CI、artifact、署名、配布、開示までを攻撃面として扱う。" "npm audit、SBOM/SAST/DAST/SCA coverage、artifact signing、advisoryを確認する。"
  (cd "$ROOT_DIR/app" && npm audit --omit=dev --audit-level=high >/dev/null)
  record VERIFIED supply-chain "npm production dependency audit passed"
  has_text "SBOM|SAST|DAST|SCA|artifact signing|provenance" supply-chain "supply chain topics are documented"
}

run_detection() {
  section "detection" "攻撃仮説、telemetry、正規化、MITRE mapping、case判断を一つの検知運用にする。" "Suricata/Sigma/YARA/SIEM queryとfalse positive tuningを整理する。"
  has_text "Sigma|YARA|MITRE ATT&CK|false positive|SIEM query" detection "detection engineering topics are documented"
  has_file "docs/soc-playbook.md" detection "SOC playbook exists"
}

run_endpoint() {
  section "endpoint" "process tree、auditd、Sysmon相当telemetryから悪性/正常の振る舞いを判断する。" "auditd eventをprocess timelineへ変換し、Windows Sysmon fieldへ写像する。"
  has_file "auditd/audit.rules" endpoint "auditd rules exist"
  has_text "Sysmon|process tree|malware behavior|sandboxing" endpoint "endpoint/EDR topics are documented"
}

run_performance() {
  section "performance" "性能劣化をCPU、memory、GC、DB、network、poolに分解し証拠で改善する。" "load resultをp95/p99、flamegraph、query plan、N+1、memory leak観点へ接続する。"
  has_file "scripts/load_hands_on_tests.sh" performance "load test runner exists"
  has_text "flamegraph|query plan|memory leak|N\\+1|GC" performance "performance topics are documented"
}

run_governance() {
  section "governance" "OSSとして安全に公開し、review、release、advisory、licenseを継続運用する。" "SECURITY、CONTRIBUTING、LICENSE、CI、Dependabot、release/advisory手順を確認する。"
  has_file "LICENSE" governance "license exists"
  has_file "CONTRIBUTING.md" governance "contribution guide exists"
  has_file ".github/dependabot.yml" governance "Dependabot config exists"
  has_text "CVE|CVSS|responsible disclosure|branch protection|license compliance" governance "OSS governance topics are documented"
}

run_topic() {
  case "$1" in
    linux) run_linux ;;
    network) run_network ;;
    edge) run_edge ;;
    kubernetes) run_kubernetes ;;
    cloud) run_cloud ;;
    iac) run_iac ;;
    observability) run_observability ;;
    distributed) run_distributed ;;
    backend) run_backend ;;
    api-security) run_api_security ;;
    supply-chain) run_supply_chain ;;
    detection) run_detection ;;
    endpoint) run_endpoint ;;
    performance) run_performance ;;
    governance) run_governance ;;
    all)
      for topic in linux network edge kubernetes cloud iac observability distributed backend api-security supply-chain detection endpoint performance governance; do
        run_topic "$topic"
      done
      ;;
    *)
      echo "Unknown topic: $1" >&2
      echo "Use one of: linux network edge kubernetes cloud iac observability distributed backend api-security supply-chain detection endpoint performance governance all" >&2
      exit 2
      ;;
  esac
}

{
  echo "# Advanced Curriculum Evidence Inventory"
  echo
  echo "- Date: $(date -Iseconds)"
  echo "- Topic: $TOPIC"
} > "$REPORT_FILE"

run_topic "$TOPIC"

{
  echo
  echo "## Summary"
  echo
  echo "- VERIFIED: $verified_count"
  echo "- PRESENT: $present_count"
  echo "- DOCUMENTED: $documented_count"
  echo "- WARN: $warn_count"
  echo
  echo "VERIFIED means a command ran successfully. PRESENT and DOCUMENTED do not prove runtime behavior or production mastery."
} >> "$REPORT_FILE"

echo
echo "Summary: VERIFIED=$verified_count PRESENT=$present_count DOCUMENTED=$documented_count WARN=$warn_count"
echo "Report written to: $REPORT_FILE"
