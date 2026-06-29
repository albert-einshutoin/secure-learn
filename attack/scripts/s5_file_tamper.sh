#!/bin/bash
# SOC-Lab Attack Script: S5 - Important File Tampering
# Purpose: Demonstrate OS-level file monitoring with Auditd

set -e

# Configuration
OUTPUT_DIR="/results"
TEST_FILE="/tmp/soc-lab-test-file.txt"

echo "============================================"
echo "SOC-Lab Scenario S5: File Tampering"
echo "============================================"
echo ""
echo "NOTE: This scenario requires Auditd running on the HOST, not in Docker."
echo "      Run the attack commands on the host system to generate audit logs."
echo ""
echo "Time: $(date -Iseconds)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s5_file_tamper_$(date +%Y%m%d_%H%M%S).txt"

echo "============================================"
echo "Demonstration Commands (Run on HOST)"
echo "============================================"

cat << 'EOF'

# =====================================
# IMPORTANT: Run these on the HOST system
# =====================================

# Phase 1: Modify /etc/passwd (simulated - use test user)
# WARNING: Do not run on production systems
# sudo echo "testuser:x:9999:9999:Test User:/home/testuser:/bin/bash" >> /etc/passwd.test

# Phase 2: Modify /etc/shadow (requires root)
# sudo touch /etc/shadow

# Phase 3: Modify /etc/sudoers (requires root)
# sudo visudo

# Phase 4: Modify cron jobs
# sudo echo "* * * * * root echo 'test'" >> /etc/cron.d/test-job

# Phase 5: Modify SSH config
# sudo touch /etc/ssh/sshd_config

# =====================================
# Check Audit Logs
# =====================================

# Search for file changes
ausearch -k passwd_changes
ausearch -k shadow_changes
ausearch -k sudoers_changes
ausearch -k cron_changes
ausearch -k sshd_config_changes

# Generate summary report
aureport --file --summary

EOF

echo "" | tee "$OUTPUT_FILE"
echo "============================================" | tee -a "$OUTPUT_FILE"
echo "Simulated File Tampering (Safe Version)" | tee -a "$OUTPUT_FILE"
echo "============================================" | tee -a "$OUTPUT_FILE"

# Create test files to demonstrate (safe operations)
echo "Creating test files for demonstration..."

# Create a test file
echo "Original content - $(date)" > "$TEST_FILE"
echo "Created: $TEST_FILE" | tee -a "$OUTPUT_FILE"

# Modify the test file
echo "Modified content - $(date)" >> "$TEST_FILE"
echo "Modified: $TEST_FILE" | tee -a "$OUTPUT_FILE"

# Read the test file
cat "$TEST_FILE" | tee -a "$OUTPUT_FILE"

# Delete the test file
rm -f "$TEST_FILE"
echo "Deleted: $TEST_FILE" | tee -a "$OUTPUT_FILE"

echo ""
echo "============================================"
echo "Attack Simulation Complete"
echo "============================================"
echo ""
echo "For real attack simulation, run the following on the HOST:"
echo ""
echo "1. Check Auditd is running:"
echo "   systemctl status auditd"
echo ""
echo "2. Verify audit rules are loaded:"
echo "   auditctl -l | grep -E 'passwd|shadow|sudoers'"
echo ""
echo "3. Perform file modifications (as root):"
echo "   sudo touch /etc/passwd"
echo "   sudo touch /etc/shadow"
echo ""
echo "4. Check audit logs:"
echo "   ausearch -k passwd_changes"
echo "   ausearch -k shadow_changes"
echo ""
echo "5. Check Kibana:"
echo "   - Search: event.module:auditd AND file.path:/etc/passwd"
echo ""
echo "Success Criteria:"
echo "  [✓] Auditd records SYSCALL + PATH events"
echo "  [✓] File path is correctly identified"
echo "  [✓] User (auid) is recorded"
echo "  [✓] Events visible in Kibana"

