#!/bin/bash
# -------------------------------------------------------------------
# Streamworks Verteilskript (Linux → Windows/Linux Hosts)
# Autor: Nick Bembenneck
# Datum: 2025-11-04
# -------------------------------------------------------------------

# ==== configuration =================================================
SOURCE_HOST="degtluv4645"
SOURCE_FILE="/DBA/windows_test_bemb004/tomcat/version/apache-tomcat-11.0.13-windows-x64.zip"
DEST_DIR="C:/DBA"
LOG_DIR="/DBA/windows_test_bemb004/tomcat/log"
HOSTLIST=(
  #exogewvx20122
  #exogewvx20122
  #exogewvx20122
)

# ==== preparation ==================================================
# Check/create log directory
mkdir -p "$LOG_DIR"

# Log file with timestamp
LOGFILE="$LOG_DIR/streamworks_distribute_$(date +%Y%m%d_%H%M%S).log"

# ==== function ====================================================

function log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# ==== main ================================================

log "=== Streamworks distribution started ==="
log "Source: $SOURCE_HOST:$SOURCE_FILE"
log "Target-directory: $DEST_DIR"
log "Hosts: ${HOSTLIST[*]}"
log "Logfile: $LOGFILE"
echo "" | tee -a "$LOGFILE"

SUCCESS=0
FAILED=0

for HOST in "${HOSTLIST[@]}"; do
  log ">>> Start distribution on host: $HOST ..."

  sws_cp_file \
    --source_file "$SOURCE_FILE" \
    --source_host "$SOURCE_HOST" \
    --dest_dir "$DEST_DIR" \
    --dest_host "$HOST" >> "$LOGFILE" 2>&1

  RC=$?
  if [[ $RC -eq 0 ]]; then
    log "✅ Success: file successfully distributed to $HOST."
    ((SUCCESS++))
  else
    log "❌ Error: Distribution to $HOST failed (RC=$RC)."
    ((FAILED++))
  fi
  echo "" >> "$LOGFILE"
done

log "=== Streamworks distribution completed ==="
log "Successful: $SUCCESS | Failed: $FAILED"
log "Entire log below: $LOGFILE"