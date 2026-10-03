#!/usr/bin/env bash
set -euo pipefail

budget="${FUZZ_TIME:-1m}"
targets=(
  ".:FuzzTextInputs"
  "./dns:FuzzWireAndIPPacketInputs"
  "./dns/meshnames:FuzzMeshNameInputs"
  "./routing:FuzzRoutingInputs"
  "./sniffer:FuzzPrefixFragmentation"
  "./sniffer:FuzzSniffPreservesStream"
  "./sniffer:FuzzProtocolClassifiers"
  "./sockowner:FuzzIPPacketInputs"
  "./tls:FuzzTLSConfigInputs"
  "./tlspolicy:FuzzPolicyInputs"
  "./tun:FuzzPacketInputs"
)

log_dir="$(mktemp -d)"
trap 'rm -r -- "$log_dir"' EXIT

printf 'Fuzzing %d targets for %s in parallel\n' "${#targets[@]}" "$budget"
pids=()
for index in "${!targets[@]}"; do
  target="${targets[$index]}"
  package="${target%%:*}"
  fuzz="${target#*:}"
  go test "$package" -run='^$' -fuzz="^${fuzz}$" \
    -fuzztime="$budget" -parallel=1 >"$log_dir/$index.log" 2>&1 &
  pids+=("$!")
done

status=0
for index in "${!pids[@]}"; do
  pid="${pids[$index]}"
  target="${targets[$index]}"
  if ! wait "$pid"; then
    printf 'FAIL %s\n' "$target"
    awk -v prefix="[$target] " '{print prefix $0}' "$log_dir/$index.log"
    status=1
  else
    printf 'PASS %s\n' "$target"
  fi
done
exit "$status"
