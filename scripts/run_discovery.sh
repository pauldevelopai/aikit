#!/bin/bash
# Discovery Pipeline Cron Script
#
# This script triggers the tool discovery pipeline via the API.
# Set up as a cron job to run daily or as needed.
#
# Example cron entries (edit with: crontab -e)
#
# Run full discovery daily at 3 AM:
#   0 3 * * * /path/to/aitools/scripts/run_discovery.sh
#
# Run GitHub only every 6 hours:
#   0 */6 * * * /path/to/aitools/scripts/run_discovery.sh github
#

# Configuration
API_URL="${DISCOVERY_API_URL:-http://localhost:8000}"
API_KEY="${DISCOVERY_API_KEY:-D5yIpnAI_UYqIXJzpA40zDCr7MqDYD8Uiuktat2_APQ}"

# Optional: specify source(s) as argument
SOURCES="${1:-}"

# Build URL
if [ -n "$SOURCES" ]; then
    ENDPOINT="${API_URL}/admin/discovery/run?sources=${SOURCES}"
else
    ENDPOINT="${API_URL}/admin/discovery/run"
fi

# Log file
LOG_FILE="/tmp/discovery_cron.log"

# Run discovery
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting discovery run" >> "$LOG_FILE"

RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Success: $BODY" >> "$LOG_FILE"
    echo "Discovery completed successfully"
    echo "$BODY"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Error (HTTP $HTTP_CODE): $BODY" >> "$LOG_FILE"
    echo "Discovery failed with HTTP $HTTP_CODE"
    echo "$BODY"
    exit 1
fi
