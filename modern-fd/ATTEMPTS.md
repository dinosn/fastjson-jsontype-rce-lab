# Modern-FD attempt ledger

All attempts used independently authored marker-only bytecode.  The generated
classes contain no process-launching API: a successful class sets the fixed JVM
property `FASTJSON_MODERN_FD_MARKER` and prints a fixed token.  No public PoC
code or command-capable payload was executed.

## Attempt 0 — Docker Desktop host-publication preflight

Status: failed before `/parse`; no payload sent.

The first local launch used Docker Engine 29.4.0 on macOS.  Spring Boot reached
healthy embedded Tomcat startup, and `docker inspect` recorded the requested
`127.0.0.1:18080` binding under `HostConfig.PortBindings`.  With the service
attached only to an `internal: true` network, Docker Desktop left
`NetworkSettings.Ports` empty and the host health request received connection
refused.  The run was interrupted during its bounded health wait and the trap
removed only the `fj-modern-fd` project containers and network.

Adjustment: health and parse requests now originate from the unprivileged
artifact container over the internal network.  Compose still requests a
loopback-only publication for engines that support it, but validation does not
depend on that publication or weaken runtime isolation.  The detailed failure
record is in `evidence/FAILED_ATTEMPTS.md`.

## Attempt 1 — initial JDK 17.0.11 positive

Status: passed, then superseded by the article-matching JDK 17.0.19+10 run.

Evidence: `evidence/20260721T131213Z-positive/`

* one request, 8,706 bytes;
* Fastjson 1.2.83, AutoType false, SafeMode false;
* configured default loader null; parser and DTO loaded by Boot's default
  `org.springframework.boot.loader.launch.LaunchedClassLoader`;
* embedded Tomcat 10.1.16;
* two successful `GET /x` requests;
* fixed `lab.modernfd.BoundEnvelope` returned with 159 list values;
* marker value `fastjson-modern-fd-marker-v1`; and
* descriptors 14-30 pointed to the same `/tmp/jar_cache...tmp` file.

Manifest SHA-256:
`11a61bf82581d447271d1787d3279f68216992ae817bed78540b62a655b4b3a7`.

Response SHA-256:
`439b3d3209df018d92c5190bf2c214dd35c9763f05e37979588023796c057cbf`.

## Attempt 2 — initial JDK 17.0.11 controls

Status: passed, then superseded by the JDK 17.0.19+10 controls.

Evidence: `evidence/20260721T131306Z-controls/`

Fresh target processes were used for every case.  The ordinary body and the FD
candidates without a seed performed no artifact fetch and did not set the
marker.  The deliberately wrong-FD case fetched the jar twice and retained a
jar-cache descriptor but did not set the marker.  SafeMode rejected the first
URL-shaped type before any artifact fetch and did not set the marker.

Manifest SHA-256:
`a9e7064e67925fe3137dc6d1e34480367c07cab806dd1f6981d4a305e3aaa4f6`.

## Attempt 3 — pinned JDK 17.0.19+10 positive

Status: passed; superseded by the deterministic release-validation run in
Attempt 6.

Evidence: `evidence/20260721T131611Z-positive/`

The runtime image is pinned to the multi-platform Temurin
`17.0.19_10-jre-jammy` digest
`sha256:475d8e96b4b2bfe08999e5e854755c773af1581acdf959a4545d88f0696a2339`.
The local Linux/arm64 lab image IDs were:

* target: `sha256:eb866443f6073d92730fff9738b7f24c266a1eee8f1fdb377b0784129619c820`;
* artifact: `sha256:d78ff6be88e227b44d02d2a950237606295a142559bfa09246130547cedbc4c4`.

Observed facts:

* one 8,706-byte body and one invocation of the literal fixed-DTO sink;
* Fastjson 1.2.83, AutoType false, SafeMode false;
* `configuredDefaultLoader` null;
* parser and DTO loader Boot's default `LaunchedClassLoader`, request context
  loader embedded Tomcat's `TomcatEmbeddedWebappClassLoader`;
* Java `17.0.19+10`, Spring Boot 3.2.0, embedded Tomcat 10.1.16;
* two successful `GET /x` requests;
* `BoundEnvelope` returned successfully with 159 list values;
* fixed marker property present in the response and fixed token in stdout; and
* `/proc/self/fd` showed the retrieved `/tmp/jar_cache...tmp` open.  Probing a
  correct descriptor opened further handles to the same jar, so later adjacent
  candidates also resolved to it; this accounts for the descriptor cascade in
  the response and repeated fixed marker tokens.

Artifact hashes:

* request:
  `7b063c756d0b9be28233c2ed354ef30c9c4f8edd6b12dad9270afedab2af77d8`;
* response:
  `25545fbc98c2885d5146bf96b123541fd88e051f500b5c96bb05f81aeaed99d8`;
* served marker-only jar:
  `942e3aa5db64cca607930eaf3199c1b7c6e5f239aa65b528081ae60320ea0685`;
* executable application jar:
  `d8ccdbc7e5202d4c0e592740175fe60df809afcf3cfc7b186f9361de6f0d75ea`;
* nested Fastjson 1.2.83 jar:
  `641a4d65ab32fbfdccd9c718e3f83ebc4caabdb5e4fe5b3d51527c5fe692631d`;
* target log:
  `29604a7faffb2323b8b98d3583f8ac93e371a09c6e69eea937d261dfe58f08c5`;
* evidence manifest:
  `942cf7b7f511dc59b3f2c994989cdc5225c0afca5a8fa641706d32d38f1ace9f`.

Every entry in the evidence manifest verified successfully after cleanup.

## Attempt 4 — pinned JDK 17.0.19+10 controls

Status: passed; superseded by the assertion-hardened release controls in
Attempt 6.

Evidence: `evidence/20260721T131655Z-controls/`

Each case recreated both containers and therefore reset Fastjson mappings,
loaded classes, JVM properties, and descriptors.

| Control | Artifact fetch | Marker | Parse result |
| --- | ---: | ---: | --- |
| ordinary fixed DTO | 0 | absent | `BoundEnvelope`, one value |
| FD candidates, no seed | 0 | absent | `BoundEnvelope`, 158 values |
| seed plus FDs 4090-4095 | 2 | absent | `BoundEnvelope`, seven values |
| full body with SafeMode | 0 | absent | rejected at first URL-shaped type |

Response SHA-256 values:

* ordinary:
  `2df6fbddc0932d2ff807ade628d663de365ed015da9fda07aac4e335440fe0d6`;
* no seed:
  `eae6e2e174e0a4eb86b63b09c5d5d68d46614acaf4143784ddcafd27a3bb076b`;
* wrong FD:
  `78429b3da6a77be43b8b3a1ed71d97551cfd122c73dd08a18a00b8d877c48ed3`;
* SafeMode:
  `687328fba946a2daf0a579c235a446e6465df4a2350962c444398dea80376ef5`;
* evidence manifest:
  `91684426085259b03c8c18feeb5f7f35ef8fd272ceca9686f508cd6cae88b94f`.

Every entry in the control manifest verified successfully.  No
`fj-modern-fd` containers or networks remained after the run.

## Attempt 5 — independent no-cache review and remediation

Status: runtime proof passed; release-integrity findings remediated.

A fresh reviewer used a separate Compose project, rebuilt without relying on
the original images, audited all 159 served-JAR entries, and independently
checked the positive and four control outcomes. The marker JAR rebuilt exactly,
all class contents matched, the positive made exactly two GETs, and the controls
made 0/0/2/0 GETs. The reviewer found no process, reflection, socket, JNI,
native, or dynamic-invocation capability and left no containers or networks.

The review identified four release-quality gaps: executable-JAR ZIP timestamps
were not deterministic, the runner assertions did not cover every documented
runtime fact and exact GET count, the source guard was too narrow, and the fixed
Compose project name hindered isolated parallel review. The lab was changed to
use Maven `project.build.outputTimestamp`, exact runtime/result/count
assertions, an explicit generated-bytecode call/field allow-set plus broader
dangerous-API checks, and the `MODERN_FD_PROJECT_NAME` override. A follow-up
review confirmed those runtime fixes and correctly blocked shipment until the
attempt ledger and source checksums were refreshed.

## Attempt 6 — deterministic release positive and hardened controls

Status: passed; current release evidence.

Positive evidence: `evidence/20260721T133724Z-positive/`

Control evidence: `evidence/20260721T134502Z-controls/`

The positive used the isolated project `fj-modern-fd-final-review`. The final
control rerun used `fj-modern-fd-release-check` after adding exact SafeMode
exception assertions and the dynamic-invocation guard. The source/call-set
safety check passed before the controls. All cases were removed cleanly, with
no matching container or network remaining.

Release facts:

* the positive retained the exact Java/Fastjson/Boot/Tomcat loader facts, one
  8,706-byte body, 159 values, the fixed marker, a `jar_cache` descriptor, and
  exactly two artifact GETs;
* ordinary/no-seed/wrong-FD/SafeMode remained negative with exact GET counts
  0/0/2/0 and the expected parse outcomes;
* the SafeMode response was the expected `com.alibaba.fastjson.JSONException`
  for the first URL-shaped type and made zero GETs;
* the application JAR SHA-256 was identically
  `9b539ab140fc3cb8eeb16b939d4f24f4688037df102b113f0f5ddfa8eaedb560`
  in the positive and every control; all 159 ZIP entries use the fixed
  `2026-07-21T00:00:00` timestamp; and
* the marker-only served JAR remained
  `942e3aa5db64cca607930eaf3199c1b7c6e5f239aa65b528081ae60320ea0685`.

Positive request SHA-256:
`7b063c756d0b9be28233c2ed354ef30c9c4f8edd6b12dad9270afedab2af77d8`.

Positive response SHA-256:
`9b24373a19f05cb0b0a983589849d9caf6270a0d2fb98c854956f558420b1f66`.

Positive evidence-manifest SHA-256:
`fa0399a9253bdbc5ac798b463d09e3cbe6f601dbfc4e2dacca1d2c8b4c26f14c`.

Control evidence-manifest SHA-256:
`d694828ce82a784418f371373a995ec28dbfa88a4cd91153223d0d542a36ec09`.

Every entry in both manifests verified after cleanup. The tracked lab source is
sealed separately by `SOURCE_SHA256SUMS.txt`; generated evidence remains
ignored and is not part of the Git repository.
