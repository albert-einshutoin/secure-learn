#!/bin/bash
# SOC-Lab Attack Script: S8 - L2 ARP Observation
# Purpose: Observe ARP/neighbor behavior without poisoning the lab network.

set -euo pipefail

TARGET="${TARGET:-app}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"
BURST="${BURST:-8}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s8_l2_arp_observe_$(date +%Y%m%d_%H%M%S).txt"

resolve_target_ip() {
    getent hosts "$TARGET" | awk '{print $1; exit}'
}

TARGET_IP="${TARGET_IP:-$(resolve_target_ip)}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: Could not resolve target: $TARGET" >&2
    exit 1
fi

{
    echo "============================================"
    echo "SOC-Lab Scenario S8: L2 ARP Observation"
    echo "============================================"
    echo "Target: $TARGET ($TARGET_IP)"
    echo "Time: $(date -Iseconds)"
    echo ""

    echo "Phase 1: Current neighbor cache"
    ip neigh show || true
    echo ""

    echo "Phase 2: Create normal L3 traffic to populate L2 neighbor state"
    ping -c 2 -W 2 "$TARGET_IP" || true
    echo ""

    echo "Phase 3: ARP probes"
    # This intentionally sends small ARP probes instead of ARP spoofing. The lab
    # goal is to learn where L2 evidence appears without creating unsafe traffic.
    for i in $(seq 1 "$BURST"); do
        echo "ARP probe $i/$BURST"
        arping -c 1 -w 2 "$TARGET_IP" || true
    done
    echo ""

    echo "Phase 4: Neighbor cache after probes"
    ip neigh show || true
    echo ""

    echo "Check detection:"
    echo "  docker exec soc-lab-suricata jq 'select(.event_type==\"flow\" or .event_type==\"alert\")' /var/log/suricata/eve.json | tail"
    echo "  Note: this lab observes ARP through ip neigh/arping because the bundled Suricata image does not parse alert arp rules."
} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"
