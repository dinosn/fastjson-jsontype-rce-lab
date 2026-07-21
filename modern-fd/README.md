# Fastjson 1.2.83 modern-JDK file-descriptor lab

This is an isolated, marker-only reconstruction of the Linux file-descriptor
continuation for Fastjson 1.2.83.  It models the application shape that matters
for the claim:

* Spring Boot 3.2.0, launched as an executable jar with its default embedded
  Tomcat and default `LaunchedClassLoader`;
* Eclipse Temurin JDK 17.0.19+10;
* Fastjson 1.2.83 with AutoType left at its default (`false`);
* a final DTO containing `List<Object>`; and
* the literal sink
  `final BoundEnvelope parsed = JSON.parseObject(body, BoundEnvelope.class)`.

The generated classes cannot run commands.  The success class only sets the
fixed JVM property `FASTJSON_MODERN_FD_MARKER` and prints a fixed token.  The
target and artifact server run on an internal Docker network.  Compose requests
a loopback-only target-port publication; Docker Desktop may decline to publish
that port for an internal-only network, so the scripts deliberately drive the
endpoint from the artifact container.  Both services run unprivileged with
read-only root filesystems and dropped capabilities.

## Mechanism under test

One JSON body contains an ordered array.  Its first `@type` causes the Boot/JDK
URL loader to retrieve an inert jar through a `jar:http:` resource name.  The
stage-one class has no `@JSONType`, no static initializer, and cannot be defined
under the requested URL-shaped binary name.  Fastjson 1.2.83's unresolved
`Exception` handling lets parsing continue.

Later elements probe `jar:file:/proc/self/fd/N!/fdN/Exception.class`.  The jar
contains one marker-only class for each candidate descriptor.  Each class-file
internal name exactly matches its URL-shaped `@type`.  If a candidate descriptor
is the still-open JDK jar cache, the resource scan sees `@JSONType`, Fastjson
loads the class, and its static initializer sets the fixed marker property.

## Run

From this directory:

```sh
./scripts/static-safety-check.sh
./scripts/run-positive.sh
./scripts/run-controls.sh
```

Both scripts build their own Compose project (`fj-modern-fd`), write complete
responses/logs/inspection data beneath `evidence/`, issue requests over the
internal network, and remove only containers and networks belonging to that
project. Set `MODERN_FD_PROJECT_NAME` to a unique value for an isolated parallel
run, for example:

```sh
MODERN_FD_PROJECT_NAME=fj-modern-fd-review ./scripts/run-positive.sh
```

Set `KEEP_LAB=1` to leave the final case running for manual inspection. If the
local Docker engine honors the requested publication, the manual endpoint is
`http://127.0.0.1:18080/parse`; otherwise use Compose exec from a lab service
and keep the network internal.

The positive script fails closed unless the exact pinned Java/Fastjson/loader
facts, body and value counts, marker, retained JAR cache, and exactly two
artifact GETs are present. The control script verifies those same runtime facts,
the exact per-case GET counts and parse outcomes, and the expected SafeMode
exception. Both Maven builds use a fixed output timestamp so identical source
builds produce byte-identical application and builder JARs. Generated evidence
and Maven targets are intentionally ignored; `SOURCE_SHA256SUMS.txt` seals the
15 tracked lab source and documentation files.

The controls are:

1. ordinary DTO body (no `@type`);
2. descriptor candidates without the HTTP seed;
3. HTTP seed followed only by deliberately impossible descriptors; and
4. the complete one-body payload with Fastjson SafeMode enabled.

These are lab reproduction tools, not a production scanner.  See the repository
scanner documentation for passive exposure detection and safe canary guidance.
