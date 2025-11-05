#!/bin/bash
# -------------------------------------------------------------------
# Streamworks Gesamt-Verteilskript
# Führt alle drei Verteiljobs nacheinander aus
# Datum: 2025-11-05
# -------------------------------------------------------------------

run_distribution() {
  local SOURCE_HOST="$1"
  local SOURCE_FILE="$2"
  local DEST_DIR="$3"
  local LOG_DIR="$4"
  shift 4
  local HOSTLIST=("$@")

  mkdir -p "$LOG_DIR"
  LOGFILE="$LOG_DIR/streamworks_distribute_$(date +%Y%m%d_%H%M%S).log"

  log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
  }

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
  echo ""
}

# -------------------------------------------------------------------
# JOB 1 – Tomcat 9.0.111
# -------------------------------------------------------------------
run_distribution \
  "degtluv4645" \
  "/DBA/windows_test_bemb004/tomcat/version/apache-tomcat-9.0.111-windows-x64.zip" \
  "C:/DBA" \
  "/DBA/windows_test_bemb004/tomcat/log" \
  gtbfswve06557 gttrtwvs11199 as001507 gut205146 degutppwafsap03 degutpvwbmgap20 \
  gtbfswvw06471 gtbmewnp0000120 gttrtwvx11178 gttrtwva11181 as001060 as001041 \
  as001052 as001508 exlocwvs19987 exewnwvp20608 exlocwvt19728 exewnwvp19204 \
  gtasswvi02479 gut210146 exogewvm11739 exalfwvb14926 gtalfwvb08972 gtalfwvb13808 \
  exalfwva14925 gtalfwvx15572 dezirwnr gttrtwvd10898 as001040 as001051 \
  exlocwvp19932 exewnwvt19182 exlocwvw19705 exogewvn11740 gtlifswvm1041 \
  exalfwvb14900 gtalfwvw12607

# -------------------------------------------------------------------
# JOB 2 – Tomcat 10.1.48
# -------------------------------------------------------------------
run_distribution \
  "degtluv4645" \
  "/DBA/windows_test_bemb004/tomcat/version/apache-tomcat-10.1.48-windows-x64.zip" \
  "C:/DBA" \
  "/DBA/windows_test_bemb004/tomcat/log" \
  gut205143 gut205141 exogewvj17352 exogewvw20381 exogewvx20122 exogewva22725 \
  exewnwvo19411 degutppwafsap03 gut210141 gut210143 exogewvc22727 exogewva17343 \
  exogewvb17344 exogewvz21138 exogewva21139 exogewvb21140 exogewvc21141 \
  exewnwvh17220 exogewvg20157 exogewvi20159 exogewvb22726 exalfwvw14895 exalfwvb14900

# -------------------------------------------------------------------
# JOB 3 – Tomcat 11.0.13
# -------------------------------bemb004-----------------------------
#run_distribution \
 # "degtluv4645" \
 # "/DBA/windows_test_bemb004/tomcat/version/apache-tomcat-11.0.13-windows-x64.zip" \
  #"C:/DBA" \
  #"/DBA/windows_test_bemb004/tomcat/log" \
 # exlocwvu19261 -> Testserver



echo "✅ All distribution jobs completed."




