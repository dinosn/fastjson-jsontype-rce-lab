# Fastjson `@JSONType` remote-JAR/FD-chain — detection tools

Detects exposure and request indicators for Fastjson 1.2.83's `@JSONType`
resource-probe RCE. `checkAutoType` asks a loader for
`typeName.replace('.','/')+".class"`; a remote `jar:http` seed can leave a cached
JAR open, and later `jar:file:/proc/self/fd/N` types can define an attacker class
from that JAR on modern JDKs. The exact single-body chain fires with **AutoType
off** and through `parseObject(body, Dto.class)`; binding is not a mitigation.

**Reproduced modern composition:** exact Fastjson **1.2.83** · Spring Boot fat-JAR
loader (Boot 2.7 and 3.2 reproduced) · normal embedded Tomcat · Linux
`/proc/self/fd` · JDK 17 · untrusted JSON reaching the fixed DTO · HTTP egress ·
SafeMode and `IgnoreAutoType` off. The resource-probe source first appears in
1.2.48, but older releases need their own continuation/version tests. **JDK 9+ is
not a complete mitigation.**

## Tools (Python 3 stdlib only — no install)

### 1. `fjdetect.py` — passive decoded-payload/log detection

Parses captured JSON before inspecting it, including Unicode-escaped `@type`
keys/values, duplicate keys in encounter order, and JSON request bodies stored
inside structured-log string fields. Per-document depth/node limits fail visibly
without aborting later NDJSON records.

```bash
python3 fjdetect.py request.json
python3 fjdetect.py --ndjson gateway.jsonl
python3 fjdetect.py --json request.json
```

It reports `CRITICAL` for a failure-soft remote seed followed by a dense FD
sequence, `HIGH` for remote seeds or second-stage-like FD runs, and exits `2` on
a suspicious remote/FD indicator. Class names after the FD JAR separator are not
assumed to use the public `fdN.Exception` convention. Full correlation guidance
is in [`DETECTION.md`](DETECTION.md).

### 2. `fjscan_static.py` — inventory (no traffic to apps)
Walks jars/wars/ears (or dirs) and flags the vulnerable *combination*.
```
python3 fjscan_static.py /path/to/artifacts /path/to/app.jar
python3 fjscan_static.py --json /srv/deployments > exposure.json   # CI gate: exit 2 if EXPOSED
```
Verdicts: `EXPOSED` (Fastjson package content + metadata-verified exact 1.2.83 +
actual Boot loader class content in the same composition) · `REVIEW_PROBE`
(1.2.48–1.2.82 contains the source probe, but this exact terminal is not proven) ·
`REVIEW` (other/unknown shaded 1.x, POM/filename-only version evidence,
manifest-only Boot hints, or incomplete inspection) · `FASTJSON_NO_SB`
(content-backed probe-bearing Fastjson, no Boot loader class in this artifact) ·
`FASTJSON2_OR_SAFE` · `NO_FASTJSON`.
Recurses nested JAR/WAR/EAR files and correlates exploded `BOOT-INF/lib`,
`WEB-INF/lib`, and thin `lib` layouts. Reads `Build-Jdk` as a hint — **confirm
the runtime JDK, OS, loader/TCCL, SafeMode, egress, temp directory and FD behavior
on the host. JSON output distinguishes content-backed
`spring_boot_loader_generations` from heuristic
`spring_boot_loader_manifest_candidates`; only the former can support
`modern_fd_candidate`. The candidate covers both reproduced Boot 2 and Boot 3
loader generations and still requires runtime confirmation. Archive limits,
read errors, and truncated inspection produce `REVIEW` and exit 1 rather than a
silent clean result.

### 3. `fjscan_probe.py` — active, SAFE reachability proof
Sends the crafted `@type` at a canary you control. Its **built-in listener serves
an empty 404**, so a callback proves lookup/egress only (`FETCH_REACHABLE`), never
class loading or RCE. When using an external collaborator, verify that it likewise
serves no class/JAR. The callback does not prove the exact Fastjson version or the
FD terminal. Authorized targets only.

**Simplest usage — `--auto`** (recommended). Point it at a domain list + your Collaborator; it
fires a baseline + plain DNS + Unicode-escaped comparison DNS probe per target and prints a per-target rollup —
no `--probe-type`/`--evasion`/`--wrap` to reason about:
```
python3 fjscan_probe.py --collaborator <sub>.oastify.com --auto --targets domains.txt
```
Everything below is the manual/advanced control for when you want a specific probe.
```
# self-contained canary (run on a host targets can reach):
python3 fjscan_probe.py --canary-ip <this-host-ip> --listen-port 19000 --targets targets.txt

# external Burp Collaborator / interactsh:
python3 fjscan_probe.py --collaborator <ip|int|host|collab-sub> --port 80 --targets targets.txt
```
`targets.txt`: one target per line (`-` = stdin); empty/comment-only input exits
nonzero before listener or request setup. Each line is a full `[METHOD ]URL` **or a
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
Nest the probe in a field with `--wrap '{"name":{{P}}}'`. Each request gets a
hostname prefix plus 64 random token bits. Requests are sent **concurrently** —
tune with `--threads N` (default 20). Built-in-canary mode exits `2` when it
observes a probe callback. External/`--auto` modes cannot query the collaborator,
print `UNVERIFIED_SENT`/correlation instructions, and exit `0`; confirm tokens in
the collaborator UI. `fjscan_static.py` is likewise parallel for artifact trees.

**`--probe-type` — which OOB primitive to send (important for Burp Collaborator):**

| value | payload | fires a **dotted** Collaborator? | proves |
|---|---|---|---|
| `jsontype` (default) | `@JSONType` `jar:http://<int-ip>…` | **no** — dots→slashes forces an int-IP host, so a public Collaborator can't attribute it; use a raw-IP listener you own | the remote-resource lookup path is reachable |
| `dns` | `{"@type":"java.net.Inet4Address","val":"<tok>.<collab>"}` | **yes** — accepts a dotted host, works with AutoType off | the InetAddress primitive + egress are reachable; prerequisite only |
| `both` | sends each | — | — |

```
# Gather supporting InetAddress-primitive + egress evidence against a Collaborator:
python3 fjscan_probe.py --collaborator <sub>.oastify.com --probe-type dns --targets domains.txt
```
Watch your Collaborator for **`<tok>.<sub>.oastify.com`** DNS/HTTP interactions — the `<tok>`
prefix maps to the request the tool printed. This is not a unique Fastjson
fingerprint. For the remote-resource (`jsontype`) callback you need an OOB
listener addressable by a **raw IPv4** (encoded as an integer), since a dotted Collaborator host
cannot survive the sink.

**CDN/WAF-fronted targets** (common on public endpoints): bare HTTP clients often get a
`405`/`403` *before* the request reaches the app, so `@type` is never parsed — an inconclusive
result, not a clean bill of health. A browser `User-Agent` is sent by default; add
`--header 'K: V'` (repeatable, e.g. `Origin`, `Referer`, cookies) and `--baseline '{"a":1}'` to
send a benign control body per target. If the **baseline** and **probe** receive
different responses, that is consistent with content-sensitive edge,
middleware, validation, or application handling; it does not by itself prove a
WAF or that either request reached the intended parser. If both are blocked, the
path/method remains inconclusive rather than a clean result.

When a literal probe appears content-filtered, use **`--evasion`** as a bounded
comparison — fastjson's lexer decodes `\uXXXX` inside
field names and string values, so an escaped payload still binds and may pass a filter that
matches only literal keywords: `ukey` escapes the `@type` key, `uval` escapes the class name,
`both` does both.
```
python3 fjscan_probe.py --collaborator <sub>.oastify.com --probe-type dns --evasion both \
    --baseline '{"a":1}' --targets domains.txt
```
A DNS callback appearing **only with `--evasion`** is consistent with decoded
probe data passing content-sensitive handling while the literal form is treated differently;
corroborate the parser, implementation, and version with artifact/runtime evidence.

Redirects stay on the exact origin except for the standard same-host
HTTP:80-to-HTTPS:443 upgrade. That upgrade drops every supplied header except
`Content-Type`, `User-Agent`, and `Accept`. HTTPS downgrade, arbitrary port or
origin changes, and cross-host redirects are blocked before contact;
`--max-redirects 0` disables redirect following completely. Point the scanner
directly at any other authorized origin.

**Bulk payloads for manual Burp testing** — `fjpayload.py --targets-file` emits one payload per
domain with a stable per-target token (`fj<sha1>`):
```
python3 fjpayload.py <collab> --targets-file domains.txt         # or -f -   for stdin
```

### 4. `fjpayload.py` — one-shot fetch-body generator (manual Burp Repeater)

This tool creates only the request body; it does not control the collaborator's
response. Use an empty/404 listener that never serves a class or JAR for a
non-executing reachability check.
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

1. Run `fjscan_static.py` across build artifacts/container images and prioritize
   exact 1.2.83 + Boot loader results.
2. Feed decoded gateway/application request bodies to `fjdetect.py`; correlate a
   remote seed with dense `/proc/self/fd` or `/dev/fd` candidates.
3. Confirm runtime loader/TCCL, JDK, OS, SafeMode/handlers, egress, temp directory,
   and retained JAR FDs. Do not classify JDK 9+ as SSRF-only.
4. Use `fjscan_probe.py` only when an authorized safe lookup/egress confirmation is
   needed; a 404 callback is not RCE proof.
5. Enable SafeMode on the ordinary handler-free path, audit handlers, restrict
   egress, and migrate untrusted parsing off Fastjson 1.x.

## Validation

The original one-stage lane is preserved for JDK 8. The marker-only `modern-fd/`
lab covers the single-body fixed-DTO Linux route on JDK 17 with a normal embedded
Tomcat thread. Its controls include ordinary JSON, SafeMode, no-seed FD candidates,
and a fetched seed followed by wrong FDs. Run the detector regression suite before
shipping rule changes.

The settled suite passes 58 tests covering passive parsing/correlation limits,
redirect scope and empty input, recursive static inspection, evidence
confidence, thin layouts, archive limits and error handling. The sealed full
chain classifies `CRITICAL`, and the deterministic marker-only Boot 3 application
classifies `EXPOSED`. The review/remediation history is preserved in
[`ATTEMPTS.md`](ATTEMPTS.md).
