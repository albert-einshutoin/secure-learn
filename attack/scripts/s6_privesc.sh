#!/bin/bash
# SOC-Lab Attack Script: S6 - Privilege Escalation
# Purpose: Demonstrate privilege escalation detection with Auditd

set -e

# Configuration
OUTPUT_DIR="/results"

echo "============================================"
echo "SOC-Lab Scenario S6: Privilege Escalation"
echo "============================================"
echo ""
echo "NOTE: This scenario requires Auditd in a disposable Linux VM, not Docker."
echo "      It uses side-effect-free identity commands and changes no accounts."
echo ""
echo "Time: $(date -Iseconds)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s6_privesc_$(date +%Y%m%d_%H%M%S).txt"

echo "============================================"
echo "Demonstration Commands (Run on HOST)"
echo "============================================"

cat << 'EOF'

# =====================================
# IMPORTANT: Run these only in a disposable Linux VM
# =====================================

# Phase 1: sudo to root
sudo -n /usr/bin/id

# Phase 2: Run a side-effect-free privileged command
sudo -n /usr/bin/true

# Phase 4: Check SUID binaries (reconnaissance)
find / -perm -4000 2>/dev/null | head -20

# Phase 5: Record the inventory; do not execute or modify SUID programs
find /usr/bin -perm -4000 -type f

# =====================================
# Check Audit Logs
# =====================================

# Search for privilege escalation
ausearch -k privilege_escalation
ausearch -k sudo_usage
ausearch -k su_usage

# Search for execve with euid=0
ausearch -sc execve -ui 0

# Generate summary report
aureport --auth --summary

EOF

echo "" | tee "$OUTPUT_FILE"
echo "============================================" | tee -a "$OUTPUT_FILE"
echo "Privilege Escalation Demonstration" | tee -a "$OUTPUT_FILE"
echo "============================================" | tee -a "$OUTPUT_FILE"

# Show current user info
echo "Current User Information:" | tee -a "$OUTPUT_FILE"
echo "  User: $(whoami)" | tee -a "$OUTPUT_FILE"
echo "  UID: $(id -u)" | tee -a "$OUTPUT_FILE"
echo "  Groups: $(id -G)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
    echo "WARNING: Already running as root!" | tee -a "$OUTPUT_FILE"
else
    echo "Running as non-root user (expected for demo)" | tee -a "$OUTPUT_FILE"
fi

echo ""
echo "============================================"
echo "SUID Binary Enumeration (in container)"
echo "============================================"
echo "Searching for SUID binaries..." | tee -a "$OUTPUT_FILE"
find / -perm -4000 2>/dev/null | head -10 | tee -a "$OUTPUT_FILE" || echo "No SUID binaries found"

echo ""
echo "============================================"
echo "Privilege Escalation Simulation Complete"
echo "============================================"
echo ""
echo "To collect real Auditd evidence, use a disposable Linux VM:"
echo ""
echo "1. Check Auditd is running:"
echo "   systemctl status auditd"
echo ""
echo "2. Verify audit rules are loaded:"
echo "   auditctl -l | grep privilege_escalation"
echo ""
echo "3. Perform privilege escalation:"
echo "   sudo -n /usr/bin/id"
echo "   sudo -n /usr/bin/true"
echo ""
echo "4. Check audit logs:"
echo "   ausearch -k privilege_escalation"
echo "   ausearch -k sudo_usage"
echo ""
echo "5. Check Kibana:"
echo "   - Search: event.module:auditd AND user.effective.id:0"
echo "   - Search: tags:privilege_escalation"
echo ""
echo "Verification still required:"
echo "  [ ] Auditd records execve with euid=0"
echo "  [ ] Original user (auid) and command are present"
echo "  [ ] Events are indexed when Filebeat is connected to the VM"
