#!/bin/bash
# SOC-Lab Exercise Stop Script
# Phase 3: Stop and generate exercise report

set -e

echo "============================================"
echo "Stopping SOC-Lab Exercise"
echo "============================================"
echo ""

# Calculate duration
if [ -f /tmp/soc-lab-exercise-start ]; then
    START_TIME=$(cat /tmp/soc-lab-exercise-start)
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    echo "Exercise Duration: $DURATION seconds"
else
    echo "Warning: Could not determine exercise duration"
fi

echo ""
echo "Generating exercise report..."

# Create report directory
REPORT_DIR="./reports/exercise_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# Export Suricata alerts
echo "Exporting Suricata alerts..."
docker exec soc-lab-exercise-suricata cat /var/log/suricata/fast.log > "$REPORT_DIR/suricata_alerts.log" 2>/dev/null || true

# Export Fail2ban bans
echo "Exporting Fail2ban bans..."
docker exec soc-lab-exercise-fail2ban fail2ban-client status > "$REPORT_DIR/fail2ban_status.txt" 2>/dev/null || true

# Export application logs
echo "Exporting application logs..."
docker exec soc-lab-target-app cat /var/log/app/auth.log > "$REPORT_DIR/auth.log" 2>/dev/null || true
docker exec soc-lab-target-app cat /var/log/app/access.log > "$REPORT_DIR/access.log" 2>/dev/null || true
docker exec soc-lab-target-app cat /var/log/app/error.log > "$REPORT_DIR/error.log" 2>/dev/null || true

# Generate summary
echo "Generating summary..."
cat > "$REPORT_DIR/summary.md" << EOF
# SOC-Lab Exercise Report

## Overview

- **Date**: $(date -Iseconds)
- **Duration**: ${DURATION:-Unknown} seconds

## Statistics

### Suricata Alerts
$(grep -c "" "$REPORT_DIR/suricata_alerts.log" 2>/dev/null || echo "0") total alerts

### Authentication Events
$(grep -c "login_failed" "$REPORT_DIR/auth.log" 2>/dev/null || echo "0") failed logins
$(grep -c "login_success" "$REPORT_DIR/auth.log" 2>/dev/null || echo "0") successful logins

### Fail2ban Actions
$(grep -c "Ban" "$REPORT_DIR/fail2ban_status.txt" 2>/dev/null || echo "0") IPs banned

## Files

- suricata_alerts.log - Suricata IDS alerts
- fail2ban_status.txt - Fail2ban status and bans
- auth.log - Authentication events
- access.log - Access logs
- error.log - Error logs

## Next Steps

1. Review Kibana dashboards for full timeline
2. Analyze attack patterns
3. Document lessons learned
4. Update detection rules as needed

EOF

echo ""
echo "Report saved to: $REPORT_DIR"
echo ""

# Stop containers
echo "Stopping containers..."
docker compose -f docker-compose.exercise.yml down

echo ""
echo "============================================"
echo "Exercise Complete!"
echo "============================================"
echo ""
echo "Report Location: $REPORT_DIR"
echo ""
echo "Review the report and Kibana data for post-exercise analysis."
