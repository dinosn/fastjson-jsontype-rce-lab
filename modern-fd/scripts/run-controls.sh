#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/lib.sh"

root_output=$(new_evidence_dir controls)
trap cleanup EXIT INT TERM

run_case() {
    case_name=$1
    mode=$2
    safe_mode=$3
    case_dir="$root_output/$case_name"
    mkdir -p "$case_dir"
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    LAB_SAFE_MODE=$safe_mode compose up -d artifact target
    wait_for_target
    record_environment "$case_dir"
    run_request "$mode" "$case_dir"
    assert_runtime_facts "$case_dir/response.json"
    assert_contains "$case_dir/response.json" '"marker":null'
    assert_not_contains "$case_dir/target.log" 'FASTJSON_MODERN_FD_MARKER=fastjson-modern-fd-marker-v1'
}

compose build artifact target

run_case ordinary ordinary false
assert_count "$root_output/ordinary/artifact.log" 0 'GET /x HTTP/1.1" 200'
assert_contains "$root_output/ordinary/response.json" '"safeMode":false'
assert_contains "$root_output/ordinary/response.json" '"parsedClass":"lab.modernfd.BoundEnvelope"'
assert_contains "$root_output/ordinary/response.json" '"valueSize":1'

run_case no-seed no-seed false
assert_count "$root_output/no-seed/artifact.log" 0 'GET /x HTTP/1.1" 200'
assert_contains "$root_output/no-seed/response.json" '"safeMode":false'
assert_contains "$root_output/no-seed/response.json" '"parsedClass":"lab.modernfd.BoundEnvelope"'
assert_contains "$root_output/no-seed/response.json" '"valueSize":158'

run_case wrong-fd wrong-fd false
assert_count "$root_output/wrong-fd/artifact.log" 2 'GET /x HTTP/1.1" 200'
assert_contains "$root_output/wrong-fd/response.json" '"safeMode":false'
assert_contains "$root_output/wrong-fd/response.json" '"parsedClass":"lab.modernfd.BoundEnvelope"'
assert_contains "$root_output/wrong-fd/response.json" '"valueSize":7'
assert_contains "$root_output/wrong-fd/response.json" '/tmp/jar_cache'

run_case safe-mode positive true
assert_contains "$root_output/safe-mode/response.json" '"safeMode":true'
assert_contains "$root_output/safe-mode/response.json" '"ok":false'
assert_contains "$root_output/safe-mode/response.json" '"errorClass":"com.alibaba.fastjson.JSONException"'
assert_contains "$root_output/safe-mode/response.json" '"errorMessage":"safeMode not support autoType : jar:http:..artifact:18081.x!.foo.Exception"'
assert_count "$root_output/safe-mode/artifact.log" 0 'GET /x HTTP/1.1" 200'

seal_evidence "$root_output"
printf 'PASS four decisive controls\nevidence=%s\n' "$root_output"
