#!/usr/bin/env bash
# Spike 1 build matrix. Usage: matrix.sh   (no switches; verbose by design)
set -uo pipefail
export PATH="/Users/jauderho/projects/detent/spikes/bin:$HOME/.local/bin:$PATH"
cd /Users/jauderho/projects/detent/spikes/xbuild
OUT=/Users/jauderho/projects/detent/spikes/matrix-results.txt
: > "$OUT"
TARGETS="aarch64-unknown-linux-musl x86_64-unknown-linux-musl armv7-unknown-linux-musleabihf riscv64gc-unknown-linux-musl x86_64-unknown-freebsd"
for prov in aws-lc ring; do
  if [[ $prov == aws-lc ]]; then FEAT=(); else FEAT=(--no-default-features --features crypto-ring); fi
  export CARGO_TARGET_DIR="/Users/jauderho/projects/detent/spikes/td-$prov"
  for t in $TARGETS; do
    echo "### $prov $t" | tee -a "$OUT"
    LOG=/tmp/xb-$prov-$t.log
    S=$(date +%s)
    cargo zigbuild --release --target "$t" ${FEAT[@]+"${FEAT[@]}"} > "$LOG" 2>&1
    RC=$?
    E=$(date +%s)
    BIN="$CARGO_TARGET_DIR/$t/release/xbuild"
    if [[ $RC -eq 0 && -f $BIN ]]; then
      echo "RESULT ok rc=$RC secs=$((E-S)) bytes=$(wc -c < "$BIN" | tr -d ' ')" | tee -a "$OUT"
      echo "FILE $(file -b "$BIN")" | tee -a "$OUT"
    else
      echo "RESULT FAIL rc=$RC secs=$((E-S))" | tee -a "$OUT"
      grep -E '^(error|  = note: |cargo:warning)' "$LOG" | head -15 | sed 's/^/ERR /' | tee -a "$OUT"
    fi
  done
done
echo MATRIX-DONE | tee -a "$OUT"
