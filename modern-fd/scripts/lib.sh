#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
COMPOSE_FILE="$LAB_DIR/compose.yml"
MODERN_FD_PROJECT_NAME=${MODERN_FD_PROJECT_NAME:-fj-modern-fd}
LAB_PORT=${LAB_PORT:-18080}

compose() {
    docker compose -p "$MODERN_FD_PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
    if [ "${KEEP_LAB:-0}" != "1" ]; then
        compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
}

wait_for_target() {
    attempt=0
    while [ "$attempt" -lt 90 ]; do
        if compose exec -T artifact python3 -c \
            'import urllib.request; urllib.request.urlopen("http://target:8080/health", timeout=2).read()' \
            >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    compose logs --no-color target >&2 || true
    return 1
}

payload() {
    mode=$1
    first=1
    printf '{"value":['
    if [ "$mode" = "ordinary" ]; then
        printf '{"note":"ordinary-control"}'
        first=0
    fi
    if [ "$mode" = "positive" ] || [ "$mode" = "wrong-fd" ]; then
        printf '{"@type":"jar:http:..artifact:18081.x!.foo.Exception"}'
        first=0
    fi
    case "$mode" in
        positive|no-seed)
            fd=3
            last_fd=160
            ;;
        wrong-fd)
            fd=4090
            last_fd=4095
            ;;
        ordinary)
            fd=1
            last_fd=0
            ;;
        *)
            echo "unknown payload mode: $mode" >&2
            return 2
            ;;
    esac
    while [ "$fd" -le "$last_fd" ]; do
        if [ "$first" -eq 0 ]; then
            printf ','
        fi
        printf '{"@type":"jar:file:.proc.self.fd.%s!.fd%s.Exception"}' "$fd" "$fd"
        first=0
        fd=$((fd + 1))
    done
    printf ']}'
}

new_evidence_dir() {
    label=$1
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    EVIDENCE_DIR=${EVIDENCE_DIR:-"$LAB_DIR/evidence/${timestamp}-${label}"}
    mkdir -p "$EVIDENCE_DIR"
    printf '%s\n' "$EVIDENCE_DIR"
}

record_environment() {
    output_dir=$1
    docker version >"$output_dir/docker-version.txt"
    docker compose version >"$output_dir/compose-version.txt"
    compose images --format json >"$output_dir/images.json"
    compose ps --format json >"$output_dir/containers.json"
    compose config >"$output_dir/effective-compose.yml"
    target_id=$(compose ps -q target)
    artifact_id=$(compose ps -q artifact)
    docker inspect "$target_id" "$artifact_id" >"$output_dir/docker-inspect.json"
    docker image inspect "$(docker inspect -f '{{.Image}}' "$target_id")" \
        "$(docker inspect -f '{{.Image}}' "$artifact_id")" >"$output_dir/image-inspect.json"
    docker cp "$artifact_id:/srv/x" "$output_dir/served-x.jar" >/dev/null
    compose exec -T artifact sha256sum /srv/x >"$output_dir/container-artifact-hashes.txt"
    compose exec -T target sha256sum /app/app.jar >>"$output_dir/container-artifact-hashes.txt"
    unzip -l "$output_dir/served-x.jar" >"$output_dir/served-x-inventory.txt"

    extract_dir=$(mktemp -d "${TMPDIR:-/tmp}/fj-modern-fd-artifacts.XXXXXX")
    docker cp "$target_id:/app/app.jar" "$extract_dir/app.jar" >/dev/null
    {
        unzip -p "$extract_dir/app.jar" BOOT-INF/lib/fastjson-1.2.83.jar \
            | shasum -a 256 | sed 's#  -#  BOOT-INF/lib/fastjson-1.2.83.jar#'
        unzip -p "$extract_dir/app.jar" BOOT-INF/lib/spring-boot-3.2.0.jar \
            | shasum -a 256 | sed 's#  -#  BOOT-INF/lib/spring-boot-3.2.0.jar#'
        unzip -p "$extract_dir/app.jar" BOOT-INF/lib/tomcat-embed-core-10.1.16.jar \
            | shasum -a 256 | sed 's#  -#  BOOT-INF/lib/tomcat-embed-core-10.1.16.jar#'
    } >"$output_dir/nested-dependency-hashes.txt"
    rm "$extract_dir/app.jar"
    rmdir "$extract_dir"
}

run_request() {
    mode=$1
    output_dir=$2
    payload "$mode" >"$output_dir/request.json"
    compose exec -T artifact python3 -c '
import sys
import urllib.request
body = sys.stdin.buffer.read()
request = urllib.request.Request(
    "http://target:8080/parse",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=30) as response:
    sys.stdout.buffer.write(response.read())
' <"$output_dir/request.json" >"$output_dir/response.json"
    sleep 1
    compose logs --no-color target >"$output_dir/target.log"
    compose logs --no-color artifact >"$output_dir/artifact.log"
}

seal_evidence() {
    output_dir=$1
    (
        cd "$output_dir"
        find . -type f ! -name SHA256SUMS.txt -print | LC_ALL=C sort \
            | while IFS= read -r evidence_file; do
                shasum -a 256 "$evidence_file"
              done >SHA256SUMS.txt
    )
}

assert_contains() {
    file=$1
    expected=$2
    if ! grep -F "$expected" "$file" >/dev/null; then
        echo "missing expected text '$expected' in $file" >&2
        return 1
    fi
}

assert_not_contains() {
    file=$1
    unexpected=$2
    if grep -F "$unexpected" "$file" >/dev/null; then
        echo "unexpected text '$unexpected' in $file" >&2
        return 1
    fi
}

assert_count() {
    file=$1
    expected=$2
    needle=$3
    actual=$(grep -F -c "$needle" "$file" || true)
    if [ "$actual" -ne "$expected" ]; then
        echo "expected $expected occurrence(s) of '$needle' in $file; found $actual" >&2
        return 1
    fi
}

assert_runtime_facts() {
    file=$1
    assert_contains "$file" '"fastjson":"1.2.83"'
    assert_contains "$file" '"java":"17.0.19+10"'
    assert_contains "$file" '"autoType":false'
    assert_contains "$file" '"parserLoader":"org.springframework.boot.loader.launch.LaunchedClassLoader"'
    assert_contains "$file" '"dtoLoader":"org.springframework.boot.loader.launch.LaunchedClassLoader"'
    assert_contains "$file" '"contextLoader":"org.springframework.boot.web.embedded.tomcat.TomcatEmbeddedWebappClassLoader"'
    assert_contains "$file" '"configuredDefaultLoader":null'
}
