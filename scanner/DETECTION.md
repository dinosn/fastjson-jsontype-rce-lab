# Detection guide: Fastjson remote-JAR and FD-chain payloads

This guide covers the Fastjson 1.2.83 `@JSONType` resource path and the modern-JDK
Linux continuation that reopens a cached remote JAR through `/proc/self/fd/N`.
The exact single-body chain has been reproduced with AutoType disabled, a fixed
DTO, normal embedded-Tomcat request threads, JDK 17, and both Spring Boot 2.7 and
3.2 loaders. A normal DTO response does not rule out class initialization.

## Offline request/log detector

`fjdetect.py` is passive: it reads JSON from a file or stdin and makes no network
connections. It decodes JSON before looking for special keys, so Unicode-escaped
forms of `@type` and its value are covered. It also preserves duplicate object
keys in encounter order; a later benign duplicate cannot erase an earlier
resource probe from the analysis. Per-document walking stops with an explicit
error after 256 levels or 100,000 nodes, and later NDJSON records still run.

```bash
# One captured request body
python3 scanner/fjdetect.py request.json

# Structured logs, one JSON record per line. A JSON body stored as a string field
# is decoded recursively.
python3 scanner/fjdetect.py --ndjson gateway.jsonl

# Machine-readable output. Exit 2 means a remote-JAR or FD indicator was found.
python3 scanner/fjdetect.py --json request.json
```

Severity is intentionally evidence-based:

| Severity | Meaning |
|---|---|
| `CRITICAL` | A failure-soft remote `jar:http`/`jar:https` type ending in `Exception`/`Error` is followed in the same array by a dense process-FD candidate sequence. |
| `HIGH` | A remote resource-shaped `@type`, any remote seed plus an FD candidate, or a dense FD-only sequence consistent with a second request. |
| `MEDIUM` | An individual `jar:file:/proc/{self,thread-self,pid}/fd/N` or `/dev/fd/N` candidate. |
| `CLEAN` | No indicator for this specific chain. Other Fastjson risks may still exist. |

When a payload uses the public `fdN` class-naming convention, the detector checks
that `/fd/N` agrees with that class number. The convention is optional: an
arbitrary candidate class path such as `!/x/Payload` remains an FD indicator.

Run its regression suite with:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scanner/tests -v
```

## Detection logic for an application gateway or SIEM

Inspect the parsed JSON tree, not only raw bytes:

1. Recursively collect values whose decoded key is exactly `@type`.
2. Flag remote resource forms beginning with `jar:http:`, `jar:https:`, `http:`,
   or `https:` when they use the Fastjson dot-to-slash construction.
3. Flag any `jar:file:` type that addresses `/proc/self/fd/N`,
   `/proc/thread-self/fd/N`, `/proc/<pid>/fd/N`, or `/dev/fd/N`, regardless of
   the class entry following `!`.
4. Raise priority when one array contains a remote seed followed by several FD
   values, especially a consecutive or near-consecutive range.
5. Treat a dense FD-only request as a possible second stage: the JAR cache is
   process-global and may have been seeded by an earlier request.

Do not rely on a literal raw-body search for `@type`. JSON `\uXXXX` escapes are
decoded before Fastjson handles special keys, duplicate keys can be processed in
encounter order, and a request body may itself be stored as an escaped string
inside a structured log record. A parse/inspection error is not a clean result.

## Runtime and network correlations

High-value host/network evidence includes:

- two outbound HTTP GETs for the same extensionless JAR resource from one parse;
- creation of `/tmp/jar_cache*.tmp` (or the configured JVM temp directory) followed
  by the Java process retaining an open descriptor to it;
- subsequent JAR opens through `/proc/self/fd/N` or `/dev/fd/N`;
- class names or exceptions beginning with `jar:http:` or
  `jar:file:/proc/self/fd/`;
- a parse error or even a normal fixed-DTO response immediately after those events.

Container monitoring can correlate the Java PID's outbound connection, temp-file
creation, and `openat`/`readlink` activity on its own FD namespace. The exact FD
number is not stable, so alert on the sequence rather than a hard-coded number.

## Static inventory and safe active confirmation

`fjscan_static.py` reports `EXPOSED` only when Fastjson package content,
metadata-verified exact 1.2.83, and actual Boot loader class content occur in
the same inspected composition. POM/filename-only Fastjson versions and
manifest-only Boot launchers remain heuristic `REVIEW` evidence. Reproduced
Boot 2 and Boot 3 artifacts also receive `modern_fd_candidate=true`. Versions
1.2.48-1.2.82 contain the underlying resource probe but not the reproduced
1.2.83 single-body failure-soft continuation, so they are `REVIEW_PROBE` pending a
separate two-request/version test. Nested archives and exploded/thin layouts are
bounded; any limit or inspection error is explicit and forces `REVIEW`.

`fjscan_probe.py`'s built-in canary deliberately serves an empty HTTP 404 and no
class/JAR. Configure an external collaborator equivalently. A callback proves only
resource lookup and egress (`FETCH_REACHABLE`), not class definition or RCE.
Redirects are handled explicitly: cross-host destinations are blocked, and a
standard same-host HTTP:80-to-HTTPS:443 upgrade loses every caller-supplied
header except `Content-Type`, `User-Agent`, and `Accept`. HTTPS downgrade and
all other origin or port changes are blocked before contact. External mode cannot query the
collaborator, labels its requests `UNVERIFIED_SENT`, and exits 0.
Use the marker-only `modern-fd/` lab for end-to-end confirmation; do not turn the
fleet scanner into an execution probe.

## Response and mitigation

1. Preserve the decoded request, original bytes, process start time, loader/JDK
   identity, outbound transcript, temp-file metadata, and `/proc/<pid>/fd` links.
2. Isolate the workload and block unnecessary JVM egress.
3. Enable Fastjson SafeMode on the ordinary handler-free path and audit any
   installed `AutoTypeCheckHandler` because handlers run before SafeMode in 1.2.83.
4. Migrate untrusted parsing away from Fastjson 1.x, preferably to a pinned and
   regression-tested Fastjson2 release or another maintained parser.
5. Treat DTO binding and JDK 9+ as insufficient mitigations for this composition.

Linux is the reproduced FD namespace in this project. `/dev/fd` is detected as a
macOS-oriented sibling indicator, but the macOS and Windows runtime claims still
require separate OS-specific validation.
