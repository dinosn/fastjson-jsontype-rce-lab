#!/usr/bin/env python3
"""
fjscan_static.py — bounded inventory scanner for the Fastjson @JSONType
remote-class-load issue.

The scanner correlates Fastjson and Spring Boot loader evidence inside regular
archives, nested archives, and exploded application directories.  It never
loads Java classes or accesses the network.

The reproduced one-body ``Exception`` continuation plus Linux file-descriptor
composition is specific to Fastjson 1.2.83 in this project.  A version derived
only from a JAR filename is reported as a heuristic and is never promoted to
that exact, metadata-verified finding.

Usage:
  fjscan_static.py <path> [<path> ...]
  fjscan_static.py --json <path>

Exit status:
  0  scan completed without an EXPOSED result or inspection failure
  1  invalid/empty input or an incomplete archive inspection
  2  at least one EXPOSED artifact was found
"""

import concurrent.futures
import io
import json
import os
import re
import sys
import zipfile


PROBE_LOW = (1, 2, 48)
PROBE_HIGH = (1, 2, 83)
SINGLE_BODY_FD = (1, 2, 83)

ARCHIVE_SUFFIXES = ('.jar', '.war', '.ear')
FASTJSON_JAR_RE = re.compile(
    r'(?:^|[/!])fastjson-([0-9]+(?:\.[0-9]+)+)\.jar$', re.IGNORECASE
)
SB_LOADER_JAR_RE = re.compile(
    r'^spring-boot-loader(?:-[0-9A-Za-z_.-]+)?\.jar$', re.IGNORECASE
)
POMPROPS = 'META-INF/maven/com.alibaba/fastjson/pom.properties'

# Spring Boot loader class names across versions (2.x = loader/, 3.2+ =
# loader/launch/).
SB_LOADER_CLASSES = {
    'boot2': ('org/springframework/boot/loader/LaunchedURLClassLoader.class',),
    'boot3': ('org/springframework/boot/loader/launch/LaunchedClassLoader.class',),
}
SB_LAUNCHERS = {
    'org.springframework.boot.loader.JarLauncher',
    'org.springframework.boot.loader.WarLauncher',
    'org.springframework.boot.loader.PropertiesLauncher',
    'org.springframework.boot.loader.launch.JarLauncher',
    'org.springframework.boot.loader.launch.WarLauncher',
    'org.springframework.boot.loader.launch.PropertiesLauncher',
}
NESTED_LIB_DIRS = ('BOOT-INF/lib/', 'WEB-INF/lib/', 'lib/')

# Archive-bomb and resource-exhaustion limits.  Metadata budgets apply across
# one requested artifact (including nested archives); read budgets apply to the
# bytes actually materialized for nested archive inspection.
MAX_NESTED_DEPTH = 3
MAX_ENTRIES_PER_ARCHIVE = 20_000
MAX_TOTAL_ENTRIES = 50_000
MAX_TOTAL_DECLARED_UNCOMPRESSED = 512 * 1024 * 1024
MAX_SINGLE_NESTED_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_NESTED_READ_BYTES = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200.0
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_POM_BYTES = 256 * 1024
MAX_EXPLODED_FILES = 50_000
MAX_EXPLODED_ARCHIVES = 2_000


def vtuple(version):
    """Return every numeric component; never truncate a version suffix."""
    if not version or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', version):
        return None
    try:
        return tuple(int(component) for component in version.split('.'))
    except ValueError:
        return None


def in_probe_range(version_tuple):
    return (
        version_tuple is not None
        and len(version_tuple) == 3
        and PROBE_LOW <= version_tuple <= PROBE_HIGH
    )


def version_from_filename(name):
    match = FASTJSON_JAR_RE.search(name.replace('\\', '/'))
    return match.group(1) if match else None


def exact_version(version, expected):
    return version == '.'.join(str(component) for component in expected)


def boot_loader_generations(names, manifest=None):
    """Return class-content-backed Spring Boot loader generations."""
    found = set()
    name_set = set(names)
    for generation, classes in SB_LOADER_CLASSES.items():
        if any(class_name in name_set for class_name in classes):
            found.add(generation)
    return found


def manifest_loader_generations(manifest):
    """Return heuristic loader generations named only by Main-Class."""
    found = set()
    main_class = (manifest or {}).get('Main-Class')
    if main_class in SB_LAUNCHERS:
        found.add('boot3' if '.loader.launch.' in main_class else 'boot2')
    return found


def parse_manifest(raw):
    manifest = {}
    key = None
    for line in raw.decode('utf-8', 'replace').splitlines():
        if line.startswith(' ') and key:
            manifest[key] += line[1:]
        elif ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            manifest[key] = value.strip()
    return manifest


def new_state():
    return {
        'warnings': [],
        'errors': [],
        'entries': 0,
        'declared_uncompressed': 0,
        'nested_bytes_read': 0,
        'manifest_loader_candidates': set(),
    }


def add_issue(state, kind, message):
    bucket = state[kind]
    if message not in bucket:
        bucket.append(message)


def bounded_infos(zf, label, state):
    """Return the inspectable ZipInfo prefix and record every truncation."""
    try:
        all_infos = zf.infolist()
    except (OSError, RuntimeError, ValueError, EOFError) as exc:
        add_issue(state, 'errors', f'{label}: cannot enumerate archive entries: {exc}')
        return []

    infos = all_infos
    if len(infos) > MAX_ENTRIES_PER_ARCHIVE:
        add_issue(
            state,
            'warnings',
            f'{label}: entry-count limit exceeded '
            f'({len(infos)} > {MAX_ENTRIES_PER_ARCHIVE}); inspection truncated',
        )
        infos = infos[:MAX_ENTRIES_PER_ARCHIVE]

    remaining = max(0, MAX_TOTAL_ENTRIES - state['entries'])
    if len(infos) > remaining:
        add_issue(
            state,
            'warnings',
            f'{label}: total entry-count limit {MAX_TOTAL_ENTRIES} reached; '
            'inspection truncated',
        )
        infos = infos[:remaining]

    accepted = []
    for info in infos:
        if info.file_size < 0 or info.compress_size < 0:
            add_issue(state, 'errors', f'{label}!{info.filename}: invalid ZIP sizes')
            continue
        projected = state['declared_uncompressed'] + info.file_size
        if projected > MAX_TOTAL_DECLARED_UNCOMPRESSED:
            add_issue(
                state,
                'warnings',
                f'{label}: declared-uncompressed-byte limit '
                f'{MAX_TOTAL_DECLARED_UNCOMPRESSED} reached; inspection truncated',
            )
            break
        state['declared_uncompressed'] = projected
        accepted.append(info)
    state['entries'] += len(accepted)
    return accepted


def compression_ratio(info):
    if info.file_size == 0:
        return 0.0
    return info.file_size / max(1, info.compress_size)


def safe_read(zf, info, label, state, byte_limit, nested=False):
    entry_label = f'{label}!{info.filename}'
    if info.file_size > byte_limit:
        add_issue(
            state,
            'warnings',
            f'{entry_label}: read-size limit exceeded '
            f'({info.file_size} > {byte_limit}); entry skipped',
        )
        return None
    ratio = compression_ratio(info)
    if ratio > MAX_COMPRESSION_RATIO:
        add_issue(
            state,
            'warnings',
            f'{entry_label}: compression-ratio limit exceeded '
            f'({ratio:.1f} > {MAX_COMPRESSION_RATIO:.1f}); entry skipped',
        )
        return None
    if nested and state['nested_bytes_read'] + info.file_size > MAX_TOTAL_NESTED_READ_BYTES:
        add_issue(
            state,
            'warnings',
            f'{entry_label}: total nested-read-byte limit '
            f'{MAX_TOTAL_NESTED_READ_BYTES} reached; entry skipped',
        )
        return None
    try:
        data = zf.read(info)
    except (OSError, RuntimeError, ValueError, EOFError, zipfile.BadZipFile) as exc:
        add_issue(state, 'errors', f'{entry_label}: cannot read entry: {exc}')
        return None
    if len(data) != info.file_size:
        add_issue(
            state,
            'errors',
            f'{entry_label}: read length {len(data)} differs from declared {info.file_size}',
        )
        return None
    if nested:
        state['nested_bytes_read'] += len(data)
    return data


def make_finding(
    where,
    version,
    detected_by,
    version_confidence,
    content_verified,
    version_verified,
    version_name_candidate=None,
):
    finding = {
        'where': where,
        'fastjson_version': version,
        'detected_by': detected_by,
        'version_confidence': version_confidence,
        'content_verified': content_verified,
        'version_verified': version_verified,
    }
    if version_name_candidate is not None:
        finding['version_name_candidate'] = version_name_candidate
    return finding


def filename_only_finding(label):
    candidate = version_from_filename(label)
    if candidate is None:
        return None
    return make_finding(
        label,
        candidate,
        'archive-filename',
        'filename-only',
        content_verified=False,
        version_verified=False,
        version_name_candidate=candidate,
    )


def fastjson_finding_from_zip(zf, infos, label, state):
    """Return content/metadata-backed Fastjson evidence for one archive."""
    by_name = {info.filename: info for info in infos}
    name_candidate = version_from_filename(label)
    package_present = any(
        info.filename.startswith('com/alibaba/fastjson/')
        and info.filename.endswith('.class')
        for info in infos
    )

    pom_info = by_name.get(POMPROPS)
    if pom_info is not None:
        raw = safe_read(zf, pom_info, label, state, MAX_POM_BYTES)
        if raw is not None:
            text = raw.decode('utf-8', 'replace')
            match = re.search(r'(?m)^\s*version\s*=\s*([^\s#]+)', text)
            if match and vtuple(match.group(1)) is not None:
                version = match.group(1)
                if name_candidate and name_candidate != version:
                    add_issue(
                        state,
                        'warnings',
                        f'{label}: filename version {name_candidate} differs from '
                        f'pom.properties version {version}',
                    )
                if package_present:
                    return make_finding(
                        label,
                        version,
                        'pom.properties',
                        'verified-metadata',
                        content_verified=True,
                        version_verified=True,
                        version_name_candidate=name_candidate,
                    )
                return make_finding(
                    label,
                    version,
                    'pom.properties-only',
                    'metadata-only-unverified',
                    content_verified=False,
                    version_verified=False,
                    version_name_candidate=name_candidate,
                )
            add_issue(state, 'warnings', f'{label}!{POMPROPS}: missing valid numeric version')

    if package_present and name_candidate:
        return make_finding(
            label,
            name_candidate,
            'archive-filename+package-content',
            'content-confirmed-version-heuristic',
            content_verified=True,
            version_verified=False,
            version_name_candidate=name_candidate,
        )
    if package_present:
        return make_finding(
            label,
            None,
            'package-content',
            'content-only',
            content_verified=True,
            version_verified=False,
        )
    if name_candidate:
        return filename_only_finding(label)
    return None


def inspect_zip(zf, label, depth, findings, state):
    infos = bounded_infos(zf, label, state)
    names = [info.filename for info in infos]
    by_name = {info.filename: info for info in infos}

    manifest = {}
    manifest_info = by_name.get('META-INF/MANIFEST.MF')
    if manifest_info is not None:
        raw = safe_read(zf, manifest_info, label, state, MAX_MANIFEST_BYTES)
        if raw is not None:
            manifest = parse_manifest(raw)

    loaders = boot_loader_generations(names)
    state['manifest_loader_candidates'].update(manifest_loader_generations(manifest))
    finding = fastjson_finding_from_zip(zf, infos, label, state)
    if finding is not None:
        findings.append(finding)

    nested_infos = [
        info for info in infos
        if not info.is_dir() and info.filename.lower().endswith(ARCHIVE_SUFFIXES)
    ]
    if nested_infos and depth >= MAX_NESTED_DEPTH:
        add_issue(
            state,
            'warnings',
            f'{label}: nested archive depth limit {MAX_NESTED_DEPTH} reached; '
            f'{len(nested_infos)} nested archive(s) skipped',
        )
        return loaders, manifest

    for info in nested_infos:
        nested_label = f'{label}!{info.filename}'
        raw = safe_read(
            zf,
            info,
            label,
            state,
            MAX_SINGLE_NESTED_ARCHIVE_BYTES,
            nested=True,
        )
        if raw is None:
            heuristic = filename_only_finding(nested_label)
            if heuristic is not None:
                findings.append(heuristic)
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as nested_zip:
                nested_loaders, _ = inspect_zip(
                    nested_zip, nested_label, depth + 1, findings, state
                )
                loaders.update(nested_loaders)
        except (
            OSError,
            RuntimeError,
            ValueError,
            EOFError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
        ) as exc:
            add_issue(state, 'errors', f'{nested_label}: invalid nested archive: {exc}')
            heuristic = filename_only_finding(nested_label)
            if heuristic is not None:
                findings.append(heuristic)
    return loaders, manifest


def inspect_exploded_fastjson(root, relative_names, state):
    pom_path = os.path.join(root, *POMPROPS.split('/'))
    name_set = set(relative_names)
    package_present = any(
        name.startswith('com/alibaba/fastjson/') and name.endswith('.class')
        for name in name_set
    )
    if os.path.isfile(pom_path):
        try:
            size = os.path.getsize(pom_path)
            if size > MAX_POM_BYTES:
                add_issue(
                    state,
                    'warnings',
                    f'{pom_path}: read-size limit exceeded ({size} > {MAX_POM_BYTES})',
                )
            else:
                with open(pom_path, 'rb') as handle:
                    raw = handle.read(MAX_POM_BYTES + 1)
                match = re.search(
                    r'(?m)^\s*version\s*=\s*([^\s#]+)',
                    raw.decode('utf-8', 'replace'),
                )
                if match and vtuple(match.group(1)) is not None:
                    if package_present:
                        return make_finding(
                            root,
                            match.group(1),
                            'exploded-pom.properties',
                            'verified-metadata',
                            content_verified=True,
                            version_verified=True,
                        )
                    return make_finding(
                        root,
                        match.group(1),
                        'exploded-pom.properties-only',
                        'metadata-only-unverified',
                        content_verified=False,
                        version_verified=False,
                    )
                add_issue(state, 'warnings', f'{pom_path}: missing valid numeric version')
        except OSError as exc:
            add_issue(state, 'errors', f'{pom_path}: cannot read: {exc}')
    if package_present:
        return make_finding(
            root,
            None,
            'exploded-package-content',
            'content-only',
            content_verified=True,
            version_verified=False,
        )
    return None


def scan_exploded_directory(path):
    state = new_state()
    findings = []
    relative_names = []
    archive_paths = []

    def walk_error(exc):
        add_issue(state, 'errors', f'{path}: directory traversal failed: {exc}')

    for root, _, files in os.walk(path, onerror=walk_error):
        for filename in files:
            if len(relative_names) >= MAX_EXPLODED_FILES:
                add_issue(
                    state,
                    'warnings',
                    f'{path}: exploded-file limit {MAX_EXPLODED_FILES} reached; '
                    'inspection truncated',
                )
                break
            full_path = os.path.join(root, filename)
            relative = os.path.relpath(full_path, path).replace(os.sep, '/')
            relative_names.append(relative)
            if relative.lower().endswith(ARCHIVE_SUFFIXES):
                archive_paths.append((full_path, relative))
        if len(relative_names) >= MAX_EXPLODED_FILES:
            break

    manifest = {}
    manifest_path = os.path.join(path, 'META-INF', 'MANIFEST.MF')
    if os.path.isfile(manifest_path):
        try:
            size = os.path.getsize(manifest_path)
            if size > MAX_MANIFEST_BYTES:
                add_issue(
                    state,
                    'warnings',
                    f'{manifest_path}: read-size limit exceeded '
                    f'({size} > {MAX_MANIFEST_BYTES})',
                )
            else:
                with open(manifest_path, 'rb') as handle:
                    manifest = parse_manifest(handle.read(MAX_MANIFEST_BYTES + 1))
        except OSError as exc:
            add_issue(state, 'errors', f'{manifest_path}: cannot read: {exc}')

    loaders = boot_loader_generations(relative_names)
    state['manifest_loader_candidates'].update(manifest_loader_generations(manifest))
    direct_finding = inspect_exploded_fastjson(path, relative_names, state)
    if direct_finding is not None:
        findings.append(direct_finding)

    if len(archive_paths) > MAX_EXPLODED_ARCHIVES:
        add_issue(
            state,
            'warnings',
            f'{path}: exploded-archive limit exceeded '
            f'({len(archive_paths)} > {MAX_EXPLODED_ARCHIVES}); inspection truncated',
        )
        archive_paths = archive_paths[:MAX_EXPLODED_ARCHIVES]

    archive_bytes = 0
    for full_path, relative in archive_paths:
        label = f'{os.path.basename(path) or path}!{relative}'
        try:
            size = os.path.getsize(full_path)
        except OSError as exc:
            add_issue(state, 'errors', f'{full_path}: cannot stat archive: {exc}')
            heuristic = filename_only_finding(label)
            if heuristic is not None:
                findings.append(heuristic)
            continue
        if size > MAX_SINGLE_NESTED_ARCHIVE_BYTES:
            add_issue(
                state,
                'warnings',
                f'{full_path}: read-size limit exceeded '
                f'({size} > {MAX_SINGLE_NESTED_ARCHIVE_BYTES}); archive skipped',
            )
            heuristic = filename_only_finding(label)
            if heuristic is not None:
                findings.append(heuristic)
            continue
        if archive_bytes + size > MAX_TOTAL_NESTED_READ_BYTES:
            add_issue(
                state,
                'warnings',
                f'{path}: total exploded-archive-byte limit '
                f'{MAX_TOTAL_NESTED_READ_BYTES} reached; archive skipped',
            )
            heuristic = filename_only_finding(label)
            if heuristic is not None:
                findings.append(heuristic)
            continue
        archive_bytes += size
        try:
            with zipfile.ZipFile(full_path) as archive:
                nested_loaders, _ = inspect_zip(
                    archive, label, depth=1, findings=findings, state=state
                )
                loaders.update(nested_loaders)
        except (
            OSError,
            RuntimeError,
            ValueError,
            EOFError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
        ) as exc:
            add_issue(state, 'errors', f'{full_path}: invalid archive: {exc}')
            heuristic = filename_only_finding(label)
            if heuristic is not None:
                findings.append(heuristic)

    return build_result(path, loaders, manifest, findings, state, exploded=True)


def build_result(path, loaders, manifest, findings, state, exploded=False):
    spring_boot = bool(loaders)
    manifest_loader_candidates = sorted(state['manifest_loader_candidates'])
    known_versions = [
        (finding, vtuple(finding['fastjson_version']))
        for finding in findings
        if finding['fastjson_version'] is not None
    ]
    verified_versions = [
        version_tuple
        for finding, version_tuple in known_versions
        if finding['version_verified'] and version_tuple is not None
    ]
    all_versions = [version_tuple for _, version_tuple in known_versions if version_tuple]

    verified_probe = any(in_probe_range(version) for version in verified_versions)
    heuristic_probe = any(in_probe_range(version) for version in all_versions)
    exact_single_body = any(
        finding['version_verified']
        and exact_version(finding['fastjson_version'], SINGLE_BODY_FD)
        for finding in findings
    )
    exact_name_candidate = any(
        exact_version(finding['fastjson_version'], SINGLE_BODY_FD)
        for finding in findings
    )
    legacy_1x = any(version and version[0] == 1 for version in all_versions)
    uncertain = any(not finding['version_verified'] for finding in findings)

    if spring_boot and exact_single_body:
        verdict = 'EXPOSED'
    elif spring_boot and verified_probe:
        verdict = 'REVIEW_PROBE'
    elif verified_probe:
        verdict = 'FASTJSON_NO_SB'
    elif findings and (legacy_1x or uncertain):
        verdict = 'REVIEW'
    elif findings:
        verdict = 'FASTJSON2_OR_SAFE'
    else:
        verdict = 'NO_FASTJSON'

    if manifest_loader_candidates and not spring_boot:
        verdict = 'REVIEW'

    # Any incomplete inspection can conceal contradictory or additional
    # evidence.  Preserve the positive evidence fields, but require manual
    # REVIEW instead of presenting a final composition verdict.
    inspection_incomplete = bool(state['warnings'] or state['errors'])
    if inspection_incomplete:
        verdict = 'REVIEW'

    return {
        'artifact': path,
        'artifact_kind': 'exploded-directory' if exploded else 'archive',
        'verdict': verdict,
        'spring_boot_loader': spring_boot,
        'spring_boot_loader_generations': sorted(loaders),
        'spring_boot_loader_manifest_candidates': manifest_loader_candidates,
        'build_jdk': manifest.get('Build-Jdk-Spec') or manifest.get('Build-Jdk'),
        'fastjson': findings,
        'resource_probe_present': verified_probe,
        'resource_probe_version_candidate': heuristic_probe,
        'single_body_fd_candidate': exact_single_body,
        'single_body_fd_version_name_candidate': exact_name_candidate,
        'modern_fd_candidate': exact_single_body and spring_boot,
        'inspection_complete': not inspection_incomplete,
        'inspection_warnings': list(state['warnings']),
        'inspection_errors': list(state['errors']),
        'inspection_stats': {
            'entries': state['entries'],
            'declared_uncompressed_bytes': state['declared_uncompressed'],
            'nested_bytes_read': state['nested_bytes_read'],
        },
    }


def scan_artifact(path):
    if os.path.isdir(path):
        return scan_exploded_directory(path)

    findings = []
    state = new_state()
    manifest = {}
    loaders = set()
    try:
        with zipfile.ZipFile(path) as archive:
            loaders, manifest = inspect_zip(
                archive,
                os.path.basename(path),
                depth=0,
                findings=findings,
                state=state,
            )
    except (
        OSError,
        RuntimeError,
        ValueError,
        EOFError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        add_issue(state, 'errors', f'{path}: cannot inspect archive: {exc}')
        heuristic = filename_only_finding(os.path.basename(path))
        if heuristic is not None:
            findings.append(heuristic)
    return build_result(path, loaders, manifest, findings, state)


def _exploded_root_from_loader(full_path):
    normalized = os.path.abspath(full_path)
    for classes in SB_LOADER_CLASSES.values():
        for class_name in classes:
            suffix = class_name.replace('/', os.sep)
            if normalized.endswith(suffix):
                root = normalized[:-len(suffix)].rstrip(os.sep)
                return root or os.sep
    return None


def _thin_composition_root_from_archive(full_path):
    """Return the root for root/lib, root/BOOT-INF/lib, or root/WEB-INF/lib."""
    archive_path = os.path.abspath(full_path)
    lib_directory = os.path.dirname(archive_path)
    if os.path.basename(lib_directory) != 'lib':
        return None
    owner = os.path.dirname(lib_directory)
    if os.path.basename(owner) in ('BOOT-INF', 'WEB-INF'):
        return os.path.dirname(owner)
    return owner


def walk(paths, errors=None):
    """Yield archives and exploded roots; record invalid requested inputs."""
    if errors is None:
        errors = []
    targets = set()
    for requested in paths:
        path = os.path.abspath(requested)
        if not os.path.exists(path):
            errors.append(f'requested input does not exist: {requested}')
            continue
        if not os.access(path, os.R_OK):
            errors.append(f'requested input is not readable: {requested}')
            continue
        if os.path.isfile(path):
            targets.add(path)
            continue
        if not os.path.isdir(path):
            errors.append(f'requested input is not a regular file or directory: {requested}')
            continue

        archives = []
        loader_roots = set()
        thin_roots = {}

        def walk_error(exc):
            errors.append(f'cannot traverse requested directory {requested}: {exc}')

        for root, _, files in os.walk(path, onerror=walk_error):
            for filename in files:
                full_path = os.path.join(root, filename)
                if filename.lower().endswith(ARCHIVE_SUFFIXES):
                    archives.append(full_path)
                    targets.add(full_path)
                    thin_root = _thin_composition_root_from_archive(full_path)
                    if thin_root and (
                        thin_root == path or thin_root.startswith(path + os.sep)
                    ):
                        thin_roots.setdefault(thin_root, []).append(full_path)
                exploded_root = _exploded_root_from_loader(full_path)
                if exploded_root and (
                    exploded_root == path or exploded_root.startswith(path + os.sep)
                ):
                    loader_roots.add(exploded_root)

        # Correlate only roots that actually contain a sibling nested archive;
        # this avoids treating arbitrary compiled Boot loader class copies as an
        # exploded application.
        for root in loader_roots:
            nested_prefixes = [
                os.path.join(root, *directory.rstrip('/').split('/')) + os.sep
                for directory in NESTED_LIB_DIRS
            ]
            if any(any(archive.startswith(prefix) for prefix in nested_prefixes)
                   for archive in archives):
                targets.add(root)

        # A Spring Boot thin layout keeps its loader and application
        # dependencies as sibling JARs.  Add the composition root so the CLI
        # correlates their inspected contents, while retaining each archive's
        # independent result.  Filenames are used only for root discovery; the
        # resulting verdict still requires content inspection.
        for root, sibling_archives in thin_roots.items():
            basenames = [os.path.basename(archive) for archive in sibling_archives]
            has_loader_name = any(SB_LOADER_JAR_RE.fullmatch(name) for name in basenames)
            has_fastjson_name = any(version_from_filename(name) for name in basenames)
            if has_loader_name and has_fastjson_name:
                targets.add(root)
    for target in sorted(targets):
        yield target


def main(argv):
    as_json = False
    threads = 8
    args = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == '--json':
            as_json = True
        elif argument == '--threads':
            index += 1
            if index >= len(argv):
                print('ERROR: --threads requires a positive integer', file=sys.stderr)
                return 1
            try:
                threads = int(argv[index])
            except ValueError:
                print('ERROR: --threads requires a positive integer', file=sys.stderr)
                return 1
        elif argument.startswith('--threads='):
            try:
                threads = int(argument.split('=', 1)[1])
            except ValueError:
                print('ERROR: --threads requires a positive integer', file=sys.stderr)
                return 1
        else:
            args.append(argument)
        index += 1

    if not args:
        print(__doc__)
        return 1
    if threads < 1:
        print('ERROR: --threads requires a positive integer', file=sys.stderr)
        return 1

    input_errors = []
    files = list(walk(args, input_errors))
    if not files:
        input_errors.append('no archive or exploded application artifacts were found')

    if files:
        workers = max(1, min(threads, len(files)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(scan_artifact, files))
    else:
        results = []

    for error in input_errors:
        print(f'ERROR: {error}', file=sys.stderr)

    exposed = [result for result in results if result['verdict'] == 'EXPOSED']
    incomplete = [result for result in results if not result['inspection_complete']]

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        order = {
            'EXPOSED': 0,
            'REVIEW_PROBE': 1,
            'REVIEW': 2,
            'FASTJSON_NO_SB': 3,
            'FASTJSON2_OR_SAFE': 4,
            'NO_FASTJSON': 5,
        }
        for result in sorted(results, key=lambda value: order.get(value['verdict'], 9)):
            if result['verdict'] == 'NO_FASTJSON':
                continue
            versions = ','.join(
                sorted({
                    finding['fastjson_version'] or '??'
                    for finding in result['fastjson']
                })
            ) or '-'
            print(f"[{result['verdict']:16}] {result['artifact']}")
            loaders = ','.join(result['spring_boot_loader_generations']) or '-'
            manifest_candidates = ','.join(
                result['spring_boot_loader_manifest_candidates']
            ) or '-'
            print(
                f"      fastjson={versions}  "
                f"spring_boot_loader={result['spring_boot_loader']} "
                f"generations={loaders}  "
                f"manifest_candidates={manifest_candidates}  "
                f"build_jdk={result['build_jdk']}"
            )
            if result['modern_fd_candidate']:
                print(
                    '      modern_fd_candidate=true '
                    '(runtime Linux/JDK/egress/temp/FD controls still apply)'
                )
            for finding in result['fastjson']:
                print(
                    f"        - {finding['fastjson_version'] or '??'}  "
                    f"({finding['detected_by']}; "
                    f"confidence={finding['version_confidence']})  "
                    f"{finding['where']}"
                )
            for warning in result['inspection_warnings']:
                print(f'        ! WARNING: {warning}')
            for error in result['inspection_errors']:
                print(f'        ! ERROR: {error}')
        print(
            f'\nscanned={len(results)}  EXPOSED={len(exposed)}  '
            f"REVIEW_PROBE={sum(1 for r in results if r['verdict'] == 'REVIEW_PROBE')}  "
            f"REVIEW={sum(1 for r in results if r['verdict'] == 'REVIEW')}  "
            f"fastjson-no-SB={sum(1 for r in results if r['verdict'] == 'FASTJSON_NO_SB')}"
        )
        if exposed:
            print(
                '\nEXPOSED = metadata-verified Fastjson 1.2.83 + a Spring Boot '
                'loader in the same composition.'
            )
            print(
                'Confirm the runtime loader/OS/JDK, egress, SafeMode, and '
                'temporary-file/FD state.'
            )

    if exposed:
        return 2
    if input_errors or incomplete:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
