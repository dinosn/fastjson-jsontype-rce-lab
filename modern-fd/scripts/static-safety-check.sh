#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if rg -n --glob '*.java' \
    'Runtime[.]getRuntime|ProcessBuilder|[.]exec[(]|cmd[.]exe|powershell|/bin/(sh|bash)|java[.]lang[.]reflect|MethodHandles|ScriptEngine|javax[.]script|System[.](load|loadLibrary)|sun[.]misc[.]Unsafe|jdk[.]internal[.]misc[.]Unsafe|java[.]net[.](Socket|URL|URLConnection)|JNI|invokedynamic|INVOKEDYNAMIC|visitInvokeDynamicInsn' \
    "$LAB_DIR"; then
    echo "unsafe process/reflection/native/network primitive found" >&2
    exit 1
fi

if rg -n --glob 'Dockerfile' \
    'ENTRYPOINT.*(sh|bash)|CMD.*(sh|bash)' "$LAB_DIR"; then
    echo "shell-based container entry point found" >&2
    exit 1
fi

rg -n 'final BoundEnvelope parsed = JSON[.]parseObject[(]body, BoundEnvelope[.]class[)]' \
    "$LAB_DIR/target/src/main/java/lab/modernfd/ParseController.java" >/dev/null
rg -n 'private List<Object> value' \
    "$LAB_DIR/target/src/main/java/lab/modernfd/BoundEnvelope.java" >/dev/null
rg -n 'setProperty' \
    "$LAB_DIR/artifact/src/main/java/lab/modernfd/artifact/MarkerJarBuilder.java" >/dev/null

python3 - "$LAB_DIR/artifact/src/main/java/lab/modernfd/artifact/MarkerJarBuilder.java" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
calls = re.findall(
    r'visitMethodInsn\(\s*([A-Z_]+),\s*"([^"]+)",\s*"([^"]+)"',
    source,
    flags=re.DOTALL,
)
expected = {
    ("INVOKESPECIAL", "java/lang/Object", "<init>"),
    ("INVOKESTATIC", "java/lang/System", "setProperty"),
    ("INVOKEVIRTUAL", "java/io/PrintStream", "println"),
}
if set(calls) != expected or len(calls) != len(expected):
    raise SystemExit(f"unexpected generated-bytecode method calls: {calls!r}")

fields = re.findall(
    r'visitFieldInsn\(\s*([A-Z_]+),\s*"([^"]+)",\s*"([^"]+)"',
    source,
    flags=re.DOTALL,
)
if fields != [("GETSTATIC", "java/lang/System", "out")]:
    raise SystemExit(f"unexpected generated-bytecode field accesses: {fields!r}")
PY

echo "PASS marker-only source/call-set guard and fixed-DTO sink checks"
