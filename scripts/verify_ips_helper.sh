#!/bin/bash
# Verify that the IPS helper contains iptables and can own an NFQUEUE rule.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <image>" >&2
  exit 2
fi

image="$1"
image_pattern='^([a-z0-9]+([._-][a-z0-9]+)*)(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$'

if [[ "$image" == -* || ! "$image" =~ $image_pattern ]]; then
  echo "Unsafe Docker image reference: $image" >&2
  exit 2
fi

docker run --rm --network none "$image" iptables --version

# NET_ADMIN is limited to a disposable, networkless namespace because the
# production helper owns only the lab-local firewall and NFQUEUE lifecycle.
docker run --rm --network none --cap-add NET_ADMIN "$image" sh -euc '
  chain=SECURE_LEARN_VERIFY
  cleanup() {
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
  }
  trap cleanup EXIT
  iptables -N "$chain"
  iptables -A "$chain" -p tcp --dport 3000 -j NFQUEUE --queue-num 0
  iptables -C "$chain" -p tcp --dport 3000 -j NFQUEUE --queue-num 0
'
