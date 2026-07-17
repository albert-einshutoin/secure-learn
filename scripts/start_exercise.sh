#!/bin/bash
# SOC-Lab Exercise Start Script
# Phase 3: Red vs Blue Team Exercise

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.exercise.yml"

EXERCISE_DURATION="${EXERCISE_DURATION:-3600}"  # Default 1 hour
EXERCISE_NAME="${EXERCISE_NAME:-SOC-Lab Exercise}"

echo "============================================"
echo "SOC-Lab Red vs Blue Exercise"
echo "============================================"
echo ""
echo "Exercise: $EXERCISE_NAME"
echo "Duration: $EXERCISE_DURATION seconds"
echo "Start Time: $(date -Iseconds)"
echo ""

# Start containers
echo "Starting exercise environment..."
docker compose --project-name secure-learn-exercise -f "$COMPOSE_FILE" up -d --build --wait

# Wait for services
echo "Waiting for services to be ready..."
# Check service status
echo ""
echo "============================================"
echo "Service Status"
echo "============================================"
docker compose --project-name secure-learn-exercise -f "$COMPOSE_FILE" ps

# Display access information
echo ""
echo "============================================"
echo "Access Information"
echo "============================================"
echo ""
echo "RED TEAM:"
echo "  - Kali Terminal: docker compose -f docker-compose.exercise.yml exec red_kali /bin/bash"
echo "  - Target IP: 172.32.0.100"
echo "  - Attack Scripts: /scripts/"
echo ""
echo "BLUE TEAM:"
echo "  - SOC Dashboard: http://localhost:5602"
echo "  - Terminal: docker compose -f docker-compose.exercise.yml exec blue_terminal sh"
echo "  - Target IP: 172.32.0.100"
echo ""
echo "SHARED:"
echo "  - Kibana (Main): http://localhost:5603"
echo "  - Elasticsearch: http://localhost:9201"
echo "  - Target App: http://localhost:3100"
echo ""

# Record start time
START_TIME=$(date +%s)
echo "$START_TIME" > /tmp/soc-lab-exercise-start

echo "============================================"
echo "Exercise Started!"
echo "============================================"
echo ""
echo "RED TEAM Objectives:"
echo "  1. Reconnaissance (nmap)"
echo "  2. Exploit vulnerabilities (SQLi, Brute Force)"
echo "  3. Maintain access"
echo "  4. Document findings"
echo ""
echo "BLUE TEAM Objectives:"
echo "  1. Monitor Kibana dashboards"
echo "  2. Detect and analyze attacks"
echo "  3. Respond to incidents"
echo "  4. Document incident timeline"
echo ""
echo "Exercise ends in $EXERCISE_DURATION seconds."
echo ""
echo "To stop: ./scripts/stop_exercise.sh"
