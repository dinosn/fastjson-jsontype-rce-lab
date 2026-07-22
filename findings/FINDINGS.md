# Fastjson 1.2.83 security review findings

**Target:** Fastjson tag `1.2.83`, commit
`26f13f84fdd522de10678e43f55fde918ab7b347`

**Review denominator:** 2,041 callable/static-initializer rows across 193
production Java files, with 4,570 overlapping assignments across 15 independent
security workstreams.

This is an application-owner-oriented prioritization of the strongest results.
It separates demonstrated effects from prerequisites and does not imply that
every application, JDK, class loader, operating system, or parser configuration
is affected in the same way.

The repository directly reproduces F105 through the marker-only
[`modern-fd/`](../modern-fd/) lab and the isolated legacy JDK 8 lane. Other
entries summarize separately sealed source review and bounded lab validation;
they are not all implemented as runnable cases in this repository.

## Priority table

| Priority | Finding | Practical severity | Validation | Proven result | Important boundary |
|---:|---|---|---|---|---|
| 1 | **F105 — remote `@JSONType` bytecode execution** | Critical, conditional | Proven in controlled labs and independently reproduced | Attacker-supplied class initialization through compatible Spring Boot loaders, including the JDK 8 direct route and the Linux/JDK 17 retained-JAR `/proc/self/fd/N` continuation | Requires a parser-reachable `@type` carrier, compatible Boot/TCCL loader, egress, SafeMode/IgnoreAutoType off, and an exact attacker JAR. The modern fixed-DTO route additionally needs a generic value lane (the lab uses `List<Object>`), Linux procfs, a retained descriptor and exact name alignment; not universal across every JDK, loader, or OS |
| 2 | **F1/F45 — TemplatesImpl command execution** | Critical, configuration-gated | Proven in controlled labs | Marker command execution through `JSON.parseObject(body, Dto.class)`, including an ignored body property | Requires class admission, AutoType, and private-field population or equivalent server-side paths; pristine Fastjson 1.2.83 defaults block the tested chain |
| 3 | **F70/C016 — unbounded buffering and GZIP expansion** | High availability risk when exposed | Proven in bounded allocation labs and independent source review | Typed byte/InputStream and annotated DTO paths expand or buffer without an output cap; constrained-heap Java OOME was reproduced | Endpoint/schema and attacker-byte reachability are required; no production-wide outage or concurrency claim was established |
| 4 | **F18/C089 — parser-thread stack exhaustion** | High/Medium availability risk | Proven in controlled labs | Deeply nested ordinary object values can produce a parser-thread `StackOverflowError` under default parsing | Request-thread failure was shown; an invariant JVM crash or measured service-wide outage was not |
| 5 | **F120/C162 — fixed-schema HTTP SSRF/local-resource loading** | Medium, schema-dependent | Proven on both pinned JDK 8 lanes with independent judgment | Body-controlled `JEditorPane`/`JTextPane.page` performs HTTP requests and can load bounded `file:` content into Document state | Requires an application-declared Swing document type; no automatic response exfiltration, arbitrary class admission, or RCE was proven |
| 6 | **F118/C160 — hash-collision authorization/data-integrity failure** | Medium, application-dependent | Proven with multiple independently solved collisions | A distinct Unicode FNV-1a-64 collision can bind to a privileged enum constant or route JSONPath mutation to the wrong fixed bean setter | Requires a usable collision and downstream trust or an exposed JSONPath mutation operation; no AutoType admission, new authority, or RCE |
| 7 | **F121/C163 — fixed JdbcRowSet JNDI reachability** | Medium/Low, environment-dependent | Proven with two independent JDK-terminal judgments | Exact `dataSourceName` then `autoCommit` setter order caused one body-selected outbound JNDI/LDAP connection | Evidence stops at connection reachability; no naming response, object factory, returned object, bytecode loading, or RCE |
| 8 | **F2/F45 — default DNS resolution** | Low but broadly useful for OOB detection | Proven in controlled labs and on the wire | Attacker-controlled hostname resolution works under default configuration and through an ignored fixed-DTO property | DNS/OOB interaction only; `getByName` is not generic HTTP SSRF or RCE |

## Detailed owner impact

### F105 — conditional body-only remote bytecode execution

A fixed target class is not by itself a side-effect boundary. In the proven
Spring Boot loader topologies, `JSON.parseObject(body, Dto.class)` reaches
attacker-supplied annotated class bytes before or during final binding. The
classic JDK 8 lane can carry the value through an ignored property and return
the declared DTO normally; the modern lab uses a declared `List<Object>` field
and also returns the normally bound DTO.

Two distinct routes were reproduced:

- a classic JDK 8 Spring Boot loader directly defines the remote URL-shaped
  class; and
- exact Linux Spring Boot 2.7/3.2 plus JDK 17 artifacts retain a remote JAR
  descriptor and later load an exact annotated class through
  `/proc/self/fd/N` in the same body.

The common prerequisites are a parser-reachable `@type` carrier, a compatible
Boot/TCCL resource loader, outbound reachability, SafeMode and IgnoreAutoType
disabled, and an exact attacker-controlled JAR. The modern fixed-DTO route
additionally requires a body-controlled generic value lane (the reproduced DTO
uses `List<Object>`), Linux procfs, descriptor retention/range,
and exact class-name and annotation alignment. The classic JDK 8 root carrier
does not require a server-declared polymorphic base. Plain AppClassLoader,
arbitrary JDK/OS portability, and every servlet container were not proven.

The [FearsOff technical disclosure](https://fearsoff.org/research/fastjson-1-2-83-rce)
shows the original mechanism and a JDK 21 process-persistent, multi-request FD
sweep. Alibaba's
[maintainer advisory](https://github.com/alibaba/fastjson2/wiki/Security-Advisory%3A-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83)
reports a broader Fastjson, Spring Boot and JDK matrix. Those are external
results; this repository's direct end-to-end runtime evidence remains Fastjson
1.2.83 on its documented JDK 8 and single-body JDK 17 lanes.

### F1/F45 — configuration-gated TemplatesImpl execution

The tested `TemplatesImpl` translet executes supplied bytecode, but the clean
1.2.83 process blocks the class. The successful fixed-DTO case required
server-side class admission, AutoType, and non-public-field population, or
equivalent application-specific paths. Parsing an ignored property before
discarding it demonstrates why DTO binding does not remove the terminal's side
effects, but it does not remove those server configuration prerequisites.

### F70 and F18 — resource exhaustion

Fastjson exposes two independently demonstrated availability families:

- complete InputStream buffering and uncapped GZIP expansion in typed and
  annotation-selected paths, including a constrained-heap Java OOME; and
- missing ordinary-object depth protection leading to request-thread
  `StackOverflowError`.

Applications should enforce compressed and expanded byte limits, request size
limits, depth limits, per-request timeouts, and process/container resource
budgets. A front-door compressed-size limit alone does not bound expanded
output.

### F120 and F121 — fixed-schema outbound effects

SafeMode does not make every application-declared type inert. A declared Swing
document field can fetch a body-selected URL, while an ordered declared
`JdbcRowSetImpl` can reach JNDI lookup. These findings establish network/resource
effects, not a second general RCE chain. In particular, the JNDI tests used an
inert listener and returned no naming object or object-factory response.

### F118 — collision-based policy and mutation integrity

Several Fastjson lookup paths use FNV-1a-64 hashes without a final String
equality check. Independently generated, valid Unicode collision strings were
accepted as canonical enum values. The same design in JavaBean field lookup
allowed a public JSONPath mutation call to select the wrong fixed setter. The
impact depends on a security-relevant enum or mutation operation and on the
collision surviving upstream character restrictions.

### F2/F45 — default hostname resolution

Registered InetAddress decoding calls `InetAddress.getByName` on a
body-controlled hostname. Unknown DTO properties are fully parsed before being
discarded, so the same primitive is reachable through the exact fixed-DTO API.
This is useful for OOB detection and egress-policy testing, but it should not be
described as HTTP SSRF or command execution.

## Additional conditional findings

| Finding | Bounded result |
|---|---|
| **F51** | A deferred `$ref` hidden in an ignored DTO property can invoke a serialization-visible public getter after binding. No stock command terminal was proven. |
| **F122/C164** | Fixed `FileHandler` construction creates trusted-configuration-selected log/lock pairs and retains descriptors; body cardinality controls count, not arbitrary path or content. |
| **F123/C165** | Activated fixed `ORBImpl` binding creates connection/listener/thread state before a later failure loses cleanup; the listener was proven only inside an isolated namespace. |
| **F95/C126** | Specialized declared parsers can accept missing/mismatched object termination, creating validation or canonicalization disagreements. |
| **F96/C127** | Reader-backed single-quoted tokens can shift at a refill boundary, changing parsed data without memory corruption. |

## Remediation priorities

1. Migrate untrusted parsing away from Fastjson 1.x; do not treat DTO binding or
   JDK 9+ alone as a complete mitigation.
2. Enable `-Dfastjson.parser.safeMode=true` on ordinary handler-free paths and
   audit every installed `AutoTypeCheckHandler`, custom deserializer, accept
   entry, and mapping/cache seed.
3. Remove unnecessary Object-typed fields and dangerous JDK/application types
   from request DTOs. Reject unknown fields before parsing their nested values
   when the application contract permits it.
4. Restrict JVM egress and resolver access. Alert on decoded remote-JAR `@type`
   values, dense `/proc/self/fd` or `/dev/fd` sequences, and unexpected DNS/JNDI
   activity from parsing services.
5. Apply explicit request size, nesting-depth, expanded-output, heap, CPU,
   thread-stack, PID, and file-descriptor limits.
6. Treat parser output only as data. Do not use it as an authorization,
   signature, canonicalization, or mutation-policy decision without independent
   schema and semantic validation.

## Validation boundaries

- “Proven” means reproduced in the recorded controlled Fastjson 1.2.83 lab or
  an equivalent pinned runtime; it does not mean every deployment is affected.
- Network connection, class-resource fetch, class definition, initializer
  execution, command execution, request-thread failure, and service-wide outage
  are separate outcomes throughout this report.
- The severity labels above are practical triage labels, not formal CVSS scores.
- Public and supplied command-capable implementations were treated as untrusted
  and reviewed statically; the recommended modern lab uses only a fixed JVM
  marker.
