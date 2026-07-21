#!/usr/bin/env python3
"""Detect Fastjson ``@JSONType`` remote-JAR and file-descriptor payloads.

The detector parses JSON before inspecting it.  This is important because Fastjson
decodes ``\\uXXXX`` escapes before it handles the special ``@type`` key; searching
raw request text for the literal string ``@type`` is therefore insufficient.
Object-pair order and duplicate keys are preserved so an early malicious
``@type`` cannot be erased by a later duplicate during detection.

Input is either one JSON document (the default) or newline-delimited JSON with
``--ndjson``.  JSON strings that themselves contain an object/array are decoded up
to two additional levels so common structured-log records such as
``{"request_body":"{...}"}`` are covered too.

Inspection is bounded to 256 tree levels and 100,000 nodes per document.  An
over-limit or otherwise unparseable record is reported without preventing later
NDJSON records from being inspected.

Exit status:
  0  no high-signal remote-JAR/FD pattern
  1  one or more input documents could not be parsed
  2  a suspicious remote-JAR or FD-chain pattern was found
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


SEVERITY_ORDER = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_TREE_DEPTH = 256
MAX_TREE_NODES = 100_000

# Both the serialized type form (dots) and the resource form (slashes) are
# accepted.  The class entry is intentionally unrestricted: ``fdN.Exception``
# is a public-generator convention, not a requirement of the JAR/FD primitive.
# Linux ``/proc/self/fd``, ``/proc/thread-self/fd`` and numeric PID forms are
# covered along with the macOS-oriented ``/dev/fd`` sibling.
FD_TYPE_RE = re.compile(
    r"^jar:file:[./]*(?P<namespace>"
    r"proc[./]+(?:self|thread-self|\d+)[./]+fd|dev[./]+fd)"
    r"[./]+(?P<fd>\d+)!(?P<class_path>.*)$",
    re.IGNORECASE,
)
CLASS_FD_RE = re.compile(r"(?:^|[./])fd(?P<class_fd>\d+)(?:[./]|$)", re.IGNORECASE)
REMOTE_TYPE_RE = re.compile(r"^(?:jar:)?https?:", re.IGNORECASE)
FAILURE_SOFT_RE = re.compile(r"(?:Exception|Error)$")


@dataclass
class JSONObjectPairs:
    """A JSON object that preserves duplicate keys and their encounter order."""

    pairs: List[Tuple[str, Any]]


class InspectionLimit(Exception):
    """Raised when a parsed document exceeds the bounded recursive inspection."""


@dataclass
class WalkBudget:
    nodes: int = 0

    def visit(self, depth: int) -> None:
        if depth > MAX_TREE_DEPTH:
            raise InspectionLimit(f"maximum tree depth {MAX_TREE_DEPTH} exceeded")
        self.nodes += 1
        if self.nodes > MAX_TREE_NODES:
            raise InspectionLimit(f"maximum node count {MAX_TREE_NODES} exceeded")


@dataclass
class TypeOccurrence:
    path: str
    value: str
    kind: str
    fd: Optional[int] = None
    class_fd: Optional[int] = None
    namespace: Optional[str] = None
    failure_soft: bool = False

    def as_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "value": self.value,
        }
        if self.fd is not None:
            result["fd"] = self.fd
        if self.class_fd is not None:
            result["class_fd"] = self.class_fd
        if self.namespace is not None:
            result["namespace"] = self.namespace
        if self.failure_soft:
            result["failure_soft"] = True
        return result


@dataclass
class SequenceFinding:
    path: str
    remote_indices: List[int]
    fd_indices: List[int]
    fds: List[int]
    longest_consecutive_run: int
    remote_before_fd: bool
    failure_soft_remote_indices: List[int]
    post_failure_soft_fd_count: int
    post_failure_soft_consecutive_run: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "remote_indices": self.remote_indices,
            "fd_indices": self.fd_indices,
            "fds": self.fds,
            "longest_consecutive_run": self.longest_consecutive_run,
            "remote_before_fd": self.remote_before_fd,
            "failure_soft_remote_indices": self.failure_soft_remote_indices,
            "post_failure_soft_fd_count": self.post_failure_soft_fd_count,
            "post_failure_soft_consecutive_run": self.post_failure_soft_consecutive_run,
        }


@dataclass
class Analysis:
    source: str
    document: int
    severity: str = "CLEAN"
    reasons: List[str] = field(default_factory=list)
    occurrences: List[TypeOccurrence] = field(default_factory=list)
    sequences: List[SequenceFinding] = field(default_factory=list)
    parse_error: Optional[str] = None

    def raise_severity(self, severity: str, reason: str) -> None:
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[self.severity]:
            self.severity = severity
        if reason not in self.reasons:
            self.reasons.append(reason)

    def as_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "source": self.source,
            "document": self.document,
            "severity": self.severity,
            "reasons": self.reasons,
            "occurrences": [item.as_dict() for item in self.occurrences],
            "sequences": [item.as_dict() for item in self.sequences],
        }
        if self.parse_error is not None:
            result["parse_error"] = self.parse_error
        return result


def classify_type(path: str, value: str) -> TypeOccurrence:
    match = FD_TYPE_RE.match(value)
    if match:
        class_fd_match = CLASS_FD_RE.search(match.group("class_path"))
        return TypeOccurrence(
            path=path,
            value=value,
            kind="fd_candidate",
            fd=int(match.group("fd")),
            class_fd=(int(class_fd_match.group("class_fd"))
                      if class_fd_match is not None else None),
            namespace=match.group("namespace").replace(".", "/"),
        )
    if REMOTE_TYPE_RE.match(value):
        kind = "remote_jar_seed" if value.lower().startswith("jar:http") else "remote_class_seed"
        return TypeOccurrence(
            path=path,
            value=value,
            kind=kind,
            failure_soft=bool(FAILURE_SOFT_RE.search(value)),
        )
    return TypeOccurrence(path=path, value=value, kind="other_type")


def object_items(item: Any) -> Iterable[Tuple[str, Any]]:
    if isinstance(item, JSONObjectPairs):
        return item.pairs
    if isinstance(item, dict):
        return item.items()
    return ()


def direct_array_types(item: Any) -> List[str]:
    return [
        value for key, value in object_items(item)
        if key == "@type" and isinstance(value, str)
    ]


def longest_consecutive(values: Sequence[int]) -> int:
    unique = sorted(set(values))
    if not unique:
        return 0
    best = current = 1
    for previous, value in zip(unique, unique[1:]):
        if value == previous + 1:
            current += 1
            best = max(best, current)
        else:
            current = 1
    return best


def inspect_array(path: str, value: List[Any], analysis: Analysis) -> None:
    remote_indices: List[int] = []
    failure_soft_remote_indices: List[int] = []
    fd_indices: List[int] = []
    fds: List[int] = []
    fd_occurrences: List[Tuple[int, TypeOccurrence]] = []
    for index, item in enumerate(value):
        for duplicate_index, type_value in enumerate(direct_array_types(item)):
            occurrence = classify_type(
                f"{path}[{index}].@type#{duplicate_index + 1}", type_value
            )
            if occurrence.kind in ("remote_jar_seed", "remote_class_seed"):
                remote_indices.append(index)
                if occurrence.failure_soft:
                    failure_soft_remote_indices.append(index)
            elif occurrence.kind == "fd_candidate" and occurrence.fd is not None:
                fd_indices.append(index)
                fds.append(occurrence.fd)
                fd_occurrences.append((index, occurrence))
    if not remote_indices and not fd_indices:
        return
    remote_before_fd = any(
        remote_index < fd_index
        for remote_index in remote_indices
        for fd_index in fd_indices
    )
    post_failure_soft_fds = [
        occurrence.fd
        for index, occurrence in fd_occurrences
        if occurrence.fd is not None
        and any(remote_index < index for remote_index in failure_soft_remote_indices)
    ]
    post_failure_soft_run = longest_consecutive(post_failure_soft_fds)
    sequence = SequenceFinding(
        path=path,
        remote_indices=remote_indices,
        fd_indices=fd_indices,
        fds=fds,
        longest_consecutive_run=longest_consecutive(fds),
        remote_before_fd=remote_before_fd,
        failure_soft_remote_indices=failure_soft_remote_indices,
        post_failure_soft_fd_count=len(post_failure_soft_fds),
        post_failure_soft_consecutive_run=post_failure_soft_run,
    )
    analysis.sequences.append(sequence)

    if len(post_failure_soft_fds) >= 3 and post_failure_soft_run >= 3:
        analysis.raise_severity(
            "CRITICAL",
            "failure-soft remote class/JAR seed followed by a dense process-FD candidate sequence",
        )
    elif post_failure_soft_fds:
        analysis.raise_severity(
            "HIGH",
            "failure-soft remote class/JAR seed precedes a process-FD candidate in the same array",
        )
    elif remote_before_fd and fd_indices:
        analysis.raise_severity(
            "HIGH",
            "remote resource and process-FD candidate occur in the same array, but the seed is not failure-soft",
        )
    elif len(fd_indices) >= 4 and sequence.longest_consecutive_run >= 3:
        analysis.raise_severity(
            "HIGH",
            "dense file-descriptor candidate sequence may be a second-stage request",
        )
    elif fd_indices:
        analysis.raise_severity("MEDIUM", "file-descriptor JAR candidate present")
    explicit_mismatches = [
        occurrence for _, occurrence in fd_occurrences
        if occurrence.class_fd is not None and occurrence.fd != occurrence.class_fd
    ]
    if explicit_mismatches:
        analysis.raise_severity(
            "MEDIUM",
            "one or more /fd/N resource paths do not match their fdN class names",
        )


def maybe_decode_nested_json(value: str) -> Optional[Any]:
    stripped = value.strip()
    if len(stripped) < 2 or stripped[0] not in "[{" or stripped[-1] not in "]}":
        return None
    try:
        return json.loads(stripped, object_pairs_hook=JSONObjectPairs)
    except (TypeError, ValueError, RecursionError):
        return None


def walk(
    value: Any,
    path: str,
    analysis: Analysis,
    string_depth: int = 0,
    tree_depth: int = 0,
    budget: Optional[WalkBudget] = None,
) -> None:
    if budget is None:
        budget = WalkBudget()
    budget.visit(tree_depth)

    if isinstance(value, (JSONObjectPairs, dict)):
        duplicate_counts: Dict[str, int] = {}
        for key, child in object_items(value):
            duplicate_counts[key] = duplicate_counts.get(key, 0) + 1
            duplicate_suffix = (
                f"#{duplicate_counts[key]}" if duplicate_counts[key] > 1 else ""
            )
            child_path = f"{path}.{key}"
            if duplicate_suffix:
                child_path += duplicate_suffix
            walk(child, child_path, analysis, string_depth, tree_depth + 1, budget)
            if key == "@type" and isinstance(child, str):
                occurrence = classify_type(child_path, child)
                analysis.occurrences.append(occurrence)
                if occurrence.kind in ("remote_jar_seed", "remote_class_seed"):
                    analysis.raise_severity(
                        "HIGH",
                        "remote resource-shaped @type value present"
                        + (" with a Fastjson 1.2.83 failure-soft suffix"
                           if occurrence.failure_soft else ""),
                    )
                elif occurrence.kind == "fd_candidate":
                    analysis.raise_severity("MEDIUM", "file-descriptor JAR @type value present")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(
                child,
                f"{path}[{index}]",
                analysis,
                string_depth,
                tree_depth + 1,
                budget,
            )
        # Correlate the direct array only after every child has passed the same
        # walk budget.  This prevents an oversized tail from being pre-scanned
        # into a complete sequence finding before the node limit is reported.
        inspect_array(path, value, analysis)
    elif isinstance(value, str) and string_depth < 2:
        decoded = maybe_decode_nested_json(value)
        if decoded is not None:
            walk(
                decoded,
                f"{path}<decoded-json>",
                analysis,
                string_depth + 1,
                tree_depth + 1,
                budget,
            )


def analyze_parsed(value: Any, source: str = "<memory>", document: int = 1) -> Analysis:
    analysis = Analysis(source=source, document=document)
    try:
        walk(value, "$", analysis)
    except (InspectionLimit, RecursionError) as exc:
        analysis.parse_error = f"inspection incomplete: {exc}"
    return analysis


def parse_documents(raw: str, source: str, ndjson: bool) -> List[Analysis]:
    if not ndjson:
        try:
            parsed = json.loads(raw, object_pairs_hook=JSONObjectPairs)
            return [analyze_parsed(parsed, source, 1)]
        except (TypeError, ValueError, RecursionError) as exc:
            return [Analysis(source=source, document=1, severity="CLEAN", parse_error=str(exc))]

    analyses: List[Analysis] = []
    document = 0
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        document += 1
        try:
            parsed = json.loads(line, object_pairs_hook=JSONObjectPairs)
            analyses.append(analyze_parsed(parsed, source, document))
        except (TypeError, ValueError, RecursionError) as exc:
            analyses.append(
                Analysis(
                    source=source,
                    document=document,
                    severity="CLEAN",
                    parse_error=f"line {line_number}: {exc}",
                )
            )
    return analyses


def render_text(analyses: Iterable[Analysis]) -> None:
    for analysis in analyses:
        label = f"{analysis.source}#{analysis.document}"
        if analysis.parse_error and analysis.severity == "CLEAN" and not analysis.occurrences:
            print(f"[ERROR   ] {label}: {analysis.parse_error}")
            continue
        print(f"[{analysis.severity:8}] {label}")
        if analysis.parse_error:
            print(f"    - {analysis.parse_error}")
        for reason in analysis.reasons:
            print(f"    - {reason}")
        for sequence in analysis.sequences:
            if sequence.remote_indices or sequence.fd_indices:
                print(
                    "    sequence "
                    f"path={sequence.path} remote={sequence.remote_indices} "
                    f"fd_count={len(sequence.fd_indices)} "
                    f"consecutive={sequence.longest_consecutive_run} "
                    f"soft_remote={sequence.failure_soft_remote_indices} "
                    f"post_soft_fd_count={sequence.post_failure_soft_fd_count}"
                )
        for occurrence in analysis.occurrences:
            if occurrence.kind == "other_type":
                continue
            suffix = f" fd={occurrence.fd}" if occurrence.fd is not None else ""
            print(f"    {occurrence.kind} {occurrence.path}{suffix}: {occurrence.value[:240]}")


def load_inputs(paths: Sequence[str]) -> List[Tuple[str, str]]:
    if not paths:
        return [("<stdin>", sys.stdin.read())]
    result: List[Tuple[str, str]] = []
    for path_string in paths:
        path = Path(path_string)
        result.append((str(path), path.read_text(encoding="utf-8")))
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="JSON files; stdin is used when omitted")
    parser.add_argument("--ndjson", action="store_true", help="treat each non-empty line as JSON")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    analyses: List[Analysis] = []
    input_error = False
    try:
        inputs = load_inputs(args.paths)
    except OSError as exc:
        print(f"fjdetect: {exc}", file=sys.stderr)
        return 1
    for source, raw in inputs:
        current = parse_documents(raw, source, args.ndjson)
        analyses.extend(current)
        input_error = input_error or any(item.parse_error for item in current)

    if args.json:
        print(json.dumps([item.as_dict() for item in analyses], indent=2, sort_keys=True))
    else:
        render_text(analyses)

    suspicious = any(SEVERITY_ORDER[item.severity] >= SEVERITY_ORDER["MEDIUM"] for item in analyses)
    if suspicious:
        return 2
    if input_error:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
