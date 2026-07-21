#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib.sh"

output_dir=$(new_evidence_dir positive)
trap cleanup EXIT INT TERM

compose down --volumes --remove-orphans >/dev/null 2>&1 || true
LAB_SAFE_MODE=false compose up -d --build artifact target
wait_for_target
record_environment "$output_dir"
run_request positive "$output_dir"

assert_runtime_facts "$output_dir/response.json"
assert_contains "$output_dir/response.json" '"safeMode":false'
assert_contains "$output_dir/response.json" '"parsedClass":"lab.modernfd.BoundEnvelope"'
assert_contains "$output_dir/response.json" '"bodyBytes":8706'
assert_contains "$output_dir/response.json" '"valueSize":159'
assert_contains "$output_dir/response.json" '"marker":"fastjson-modern-fd-marker-v1"'
assert_contains "$output_dir/response.json" '/tmp/jar_cache'
assert_contains "$output_dir/target.log" 'FASTJSON_MODERN_FD_MARKER=fastjson-modern-fd-marker-v1'
assert_count "$output_dir/artifact.log" 2 'GET /x HTTP/1.1" 200'

seal_evidence "$output_dir"
printf 'PASS marker-only one-body reproduction\nevidence=%s\n' "$output_dir"
