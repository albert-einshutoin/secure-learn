#!/bin/bash
# Parse the fixed host-side `docker top -eo pid,ppid,comm` contract. The
# publisher image should contain only its main socat process and forked socat
# children, so any other row is evidence corruption rather than ignorable data.

set -euo pipefail

awk '
  NR == 1 {
    if (NF != 3 || $1 != "PID" || $2 != "PPID" || ($3 != "COMMAND" && $3 != "COMM")) {
      exit 2
    }
    next
  }
  {
    if (NF != 3 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ || $3 != "socat") {
      exit 2
    }
    total += 1
  }
  END {
    if (total < 1) {
      exit 2
    }
    print total, total - 1
  }
'
