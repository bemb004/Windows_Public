#!/bin/bash
# -------------------------------------------------------------------
# Streamworks Verteilskript (Linux → Windows/Linux Hosts)
# Autor: Nick Bembenneck
# Datum: 2025-11-04
# -------------------------------------------------------------------

# ==== configuration =================================================
SOURCE_HOST="degtluv4645"
SOURCE_FILE="/DBA/windows_test_bemb004/tomcat/version/apache-tomcat-9.0.111-windows-x64.zip"
DEST_DIR="C:/DBA"
LOG_DIR="/DBA/windows_test_bemb004/tomcat/log"
HOSTLIST=(
  gtbfswve06557
  gttrtwvs11199
  as001507
  gut205146
  degutppwafsap03
  degutpvwbmgap20
  gtbfswvw06471
  gtbmewnp0000120
  gttrtwvx11178
  gttrtwva11181
  as001060
  as001041
  as001052
  as001508
  exlocwvs19987
  exewnwvp20608
  exlocwvt19728
  exewnwvp19204
  gtasswvi02479
  gut210146
  exogewvm11739
  exalfwvb14926
  gtalfwvb08972
  gtalfwvb13808
  exalfwva14925
  gtalfwvx15572
  dezirwnr
  gttrtwvd10898
  as001040
  as001051
  exlocwvp19932
  exewnwvt19182
  exlocwvw19705
  exogewvn11740
  gtlifswvm1041
  exalfwvb14900
  gtalfwvw12607
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