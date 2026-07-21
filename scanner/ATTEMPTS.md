# Detection-tool attempt ledger

All validation in this ledger was offline, against the isolated marker-only lab,
or against loopback test servers. No public or third-party target was probed.

## Attempt 0 — inherited scanner review

The repository's existing static and active tools were read as untrusted
security tooling rather than assumed correct. The original static scanner used
broad version/loader heuristics, and the active probe allowed urllib redirect
behavior and made claims stronger than a lookup callback supports.

Adjustment: separate passive payload detection, static composition evidence,
and active reachability evidence. A callback is never labeled class loading or
RCE.

## Attempt 1 — passive FD-chain detector

Added decoded-JSON inspection for failure-soft remote seeds and Linux/macOS FD
forms, plus NDJSON and structured-log body decoding. Initial tests covered the
public full-chain shape, Unicode escapes, ordinary JSON, wrong ordering, and
FD-only second-stage candidates.

An independent review found that ordinary JSON parsing erased duplicate keys,
terminal class names were too narrowly tied to `fdN.Exception`, non-soft seeds
could be over-scored, a leading decoy could hide later correlation, and deep
input could exhaust recursion. The detector now preserves duplicate object
pairs, accepts arbitrary JAR terminal paths, requires a post-failure-soft dense
run for `CRITICAL`, and enforces 256-level/100,000-node limits while continuing
later NDJSON records.

A second review found that direct arrays were pre-scanned outside the node
budget. Correlation now occurs only after every direct child passes the bounded
walk. Its regression lowers the budget to three nodes and proves that an
unvisited ten-item tail cannot create a sequence finding.

## Attempt 2 — bounded static composition scanner

The static scanner was expanded to recursively inspect JAR/WAR/EAR files and
exploded Boot layouts with entry, depth, expanded-size, compression-ratio, and
read-byte limits. Missing/unreadable/empty input and incomplete inspection now
exit nonzero and cannot silently produce a clean result.

Independent review then found three confidence/composition defects:

1. POM metadata without Fastjson class content could produce `EXPOSED`;
2. a Boot `Main-Class` without loader class content could count as a loader;
3. CLI walking missed thin sibling `lib/spring-boot-loader*.jar` plus
   `lib/fastjson-*.jar` compositions.

The scanner now requires package content plus version metadata and actual Boot
loader class content for `EXPOSED`. POM/filename-only versions and manifest-only
launchers remain explicit `REVIEW` evidence. Thin layouts are correlated as a
composition, while every archive is still reported independently.

## Attempt 3 — active-probe safety and evidence bounds

The probe was changed to a no-auto-redirect opener with an explicit policy,
64-bit random correlation tokens, qualified external-mode output, and a built-in
empty-404 listener. Loopback tests proved that `--max-redirects 0` does not
follow, exact-origin redirects do follow when requested, and cross-host
destinations are blocked.

Review found that the first policy still allowed HTTPS downgrade and arbitrary
same-host port changes while preserving the caller's POST body. The final policy
allows only exact-origin redirects and the standard same-host HTTP:80 to
HTTPS:443 upgrade. The upgrade strips every header except `Accept`,
`Content-Type`, and `User-Agent`; downgrade, other port/origin changes, and
cross-host redirects are blocked before contact. A two-listener loopback test
proves that a body is not sent to a same-host alternate port.

Empty/comment-only target input originally printed `UNVERIFIED_SENT` and exited
zero despite sending nothing. It now exits nonzero before listener, DNS, or job
setup, with a regression using comment-only stdin.

Documentation was narrowed alongside the code: response differentials and
evasion-only callbacks are evidence requiring corroboration, not proof of a WAF,
Fastjson version, class loading, or RCE.

## Attempt 4 — real-artifact and release validation

The final dependency-free suite passes 58/58 tests with warnings treated as
errors. All four Python files compile under an isolated bytecode-cache directory,
and `git diff --check` passes.

Two real evidence controls also pass:

- the sealed 62-FD generator body is `CRITICAL`, with 62 post-seed consecutive
  candidates and detector exit 2;
- the deterministic marker-only Boot 3 application JAR is `EXPOSED`, with
  package-backed `pom.properties` Fastjson 1.2.83, actual Boot 3 loader content,
  `modern_fd_candidate=true`, complete inspection, and static-scanner exit 2.

Three administrative validation errors were retained rather than hidden: the
first detector command named a nonexistent evidence path before switching to
the sealed `generated/payloads/full-chain.json`; zsh rejected `status` as a
read-only variable before the assertion was rerun with `detector_rc`; and an old
evidence image ID had already been replaced before extraction, so the exact
current deterministic release image was copied through a nonrunning temporary
container. No error changed a target or was counted as a passing result.
