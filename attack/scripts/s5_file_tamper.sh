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
echo "NOTE: This scenario requires Auditd in a disposable Linux VM, not Docker."
echo "      It never modifies account-control or system configuration files."
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
# IMPORTANT: Run these only in a disposable Linux VM
# =====================================

# Register one disposable target with Auditd
TEST_FILE=/tmp/secure-learn-audit-target
touch "$TEST_FILE"
sudo auditctl -w "$TEST_FILE" -p wa -k secure_learn_test_file

# Modify only the disposable target as the current user
printf 'baseline\n' > "$TEST_FILE"
printf 'tamper simulation\n' >> "$TEST_FILE"
chmod 600 "$TEST_FILE"

# =====================================
# Check Audit Logs
# =====================================

# Search for file changes
ausearch -k secure_learn_test_file

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
echo "To collect real Auditd evidence, use a disposable Linux VM:"
echo ""
echo "1. Check Auditd is running:"
echo "   systemctl status auditd"
echo ""
echo "2. Verify audit rules are loaded:"
echo "   auditctl -l | grep secure-learn-audit-target"
echo ""
echo "3. Modify only the disposable test file:"
echo "   printf 'tamper simulation\\n' >> /tmp/secure-learn-audit-target"
echo ""
echo "4. Check audit logs:"
echo "   ausearch -k secure_learn_test_file"
echo ""
echo "5. Check Kibana:"
echo "   - Search: event.module:auditd AND file.path:/tmp/secure-learn-audit-target"
echo ""
echo "Success Criteria:"
echo "  [✓] Auditd records SYSCALL + PATH events"
echo "  [✓] File path is correctly identified"
echo "  [✓] User (auid) is recorded"
echo "  [✓] Events visible in Kibana"
