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
echo "NOTE: This scenario requires Auditd running on the HOST, not in Docker."
echo "      Run the attack commands on the host system to generate audit logs."
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
# IMPORTANT: Run these on the HOST system
# =====================================

# Phase 1: sudo to root
sudo -u root whoami

# Phase 2: su to root
su - root -c "whoami"

# Phase 3: Run privileged command
sudo id

# Phase 4: Check SUID binaries (reconnaissance)
find / -perm -4000 2>/dev/null | head -20

# Phase 5: Execute a SUID binary
sudo /usr/bin/passwd --status root

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
echo "For real attack simulation, run the following on the HOST:"
echo ""
echo "1. Check Auditd is running:"
echo "   systemctl status auditd"
echo ""
echo "2. Verify audit rules are loaded:"
echo "   auditctl -l | grep privilege_escalation"
echo ""
echo "3. Perform privilege escalation:"
echo "   sudo -u root whoami"
echo "   su - root -c 'id'"
echo ""
echo "4. Check audit logs:"
echo "   ausearch -k privilege_escalation"
echo "   ausearch -k sudo_usage"
echo ""
echo "5. Check Kibana:"
echo "   - Search: event.module:auditd AND user.effective.id:0"
echo "   - Search: tags:privilege_escalation"
echo ""
echo "Success Criteria:"
echo "  [✓] Auditd records execve with euid=0"
echo "  [✓] Original user (auid) is recorded"
echo "  [✓] Executed command is recorded"
echo "  [✓] Events visible in Kibana"

