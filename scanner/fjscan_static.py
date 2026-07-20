#!/usr/bin/env python3
"""
fjscan_static.py — inventory scanner for the fastjson @JSONType remote-class-load
RCE (github.com/wouijvziqy/Fastjson-JsonType-RCE-PoC; Firsov 2026-07).

Flags the vulnerable COMBINATION in build artifacts / fat jars / wars:
  (fastjson 1.2.66-1.2.83)  x  (Spring Boot fat-jar loader = LaunchedURLClassLoader)
JDK 8 at runtime turns SSRF into full RCE — checked separately on hosts (see README).

No network, no code execution. Pure zip inspection. Stdlib only.

Usage:
  fjscan_static.py <path> [<path> ...]        # dirs are walked for *.jar/*.war/*.ear
  fjscan_static.py --json <path>              # machine-readable output
Exit code 2 if any EXPOSED artifact is found (useful as a CI/pipeline gate).
"""
import concurrent.futures, io, json, os, re, sys, zipfile

VULN_LOW  = (1, 2, 66)   # PoC-tested lower bound
VULN_HIGH = (1, 2, 83)   # last 1.x release
FASTJSON_JAR_RE = re.compile(r'(?:^|/)fastjson-(\d+\.\d+\.\d+)\.jar$')
POMPROPS = 'META-INF/maven/com.alibaba/fastjson/pom.properties'
# Spring Boot loader class names across versions (2.x = loader/, 3.2+ = loader/launch/)
SB_LOADER_CLASSES = (
    'org/springframework/boot/loader/LaunchedURLClassLoader.class',
    'org/springframework/boot/loader/launch/LaunchedClassLoader.class',
)
SB_LAUNCHERS = {
    'org.springframework.boot.loader.JarLauncher',
    'org.springframework.boot.loader.WarLauncher',
    'org.springframework.boot.loader.PropertiesLauncher',
    'org.springframework.boot.loader.launch.JarLauncher',
    'org.springframework.boot.loader.launch.WarLauncher',
    'org.springframework.boot.loader.launch.PropertiesLauncher',
}
NESTED_LIB_DIRS = ('BOOT-INF/lib/', 'WEB-INF/lib/', 'lib/')


def vtuple(s):
    try:
        return tuple(int(x) for x in s.split('.')[:3])
    except Exception:
        return None


def in_vuln_range(v):
    return v is not None and VULN_LOW <= v <= VULN_HIGH


def parse_manifest(raw):
    d = {}
    key = None
    for line in raw.decode('utf-8', 'replace').splitlines():
        if line.startswith(' ') and key:          # continuation line
            d[key] += line[1:]
        elif ':' in line:
            key, val = line.split(':', 1)
            key = key.strip(); d[key] = val.strip()
    return d


def fastjson_version_from_zip(zf):
    """Return (version_str_or_None, how) if fastjson is present in this zip, else None."""
    names = zf.namelist()
    # 1) authoritative: maven pom.properties
    if POMPROPS in names:
        try:
            txt = zf.read(POMPROPS).decode('utf-8', 'replace')
            m = re.search(r'version=([\d.]+)', txt)
            if m:
                return (m.group(1), 'pom.properties')
        except Exception:
            pass
    # 2) any class of the fastjson package present (shaded/unknown version)
    if any(n.startswith('com/alibaba/fastjson/') and n.endswith('.class') for n in names):
        return (None, 'package-present')
    return None


def inspect_zip(zf, label, depth, findings):
    names = zf.namelist()
    # Spring Boot loader present in THIS archive?
    sb = any(c in names for c in SB_LOADER_CLASSES)
    manifest = {}
    if 'META-INF/MANIFEST.MF' in names:
        try:
            manifest = parse_manifest(zf.read('META-INF/MANIFEST.MF'))
        except Exception:
            pass
    if manifest.get('Main-Class') in SB_LAUNCHERS:
        sb = True

    # fastjson directly in this archive (top-level jar case)
    fj = fastjson_version_from_zip(zf)
    if fj:
        findings.append({'where': label, 'fastjson_version': fj[0], 'detected_by': fj[1]})

    # recurse into nested libs (fat jar / war)
    if depth > 0:
        for n in names:
            if not n.endswith('.jar'):
                continue
            if not any(n.startswith(d) for d in NESTED_LIB_DIRS):
                continue
            m = FASTJSON_JAR_RE.search(n)
            if m:
                findings.append({'where': f'{label}!{n}', 'fastjson_version': m.group(1),
                                 'detected_by': 'nested-jar-filename'})
                continue
            try:
                data = zf.read(n)
                with zipfile.ZipFile(io.BytesIO(data)) as nz:
                    fj2 = fastjson_version_from_zip(nz)
                    if fj2:
                        findings.append({'where': f'{label}!{n}',
                                         'fastjson_version': fj2[0], 'detected_by': fj2[1]})
                    if any(c in nz.namelist() for c in SB_LOADER_CLASSES):
                        sb = True
            except Exception:
                pass
    return sb, manifest


def scan_artifact(path):
    findings = []
    try:
        with zipfile.ZipFile(path) as zf:
            sb, manifest = inspect_zip(zf, os.path.basename(path), depth=1, findings=findings)
    except zipfile.BadZipFile:
        return None

    if not findings:
        return {'artifact': path, 'verdict': 'NO_FASTJSON', 'spring_boot_loader': sb,
                'build_jdk': manifest.get('Build-Jdk-Spec') or manifest.get('Build-Jdk'),
                'fastjson': []}

    versions = [f['fastjson_version'] for f in findings]
    any_vuln_range = any(in_vuln_range(vtuple(v)) for v in versions if v)
    any_1x = any((vtuple(v) and vtuple(v)[:2] == (1, 2)) for v in versions if v)
    unknown = any(v is None for v in versions)

    if sb and (any_vuln_range or (any_1x and unknown)):
        verdict = 'EXPOSED'          # vulnerable combo present
    elif sb and any_1x:
        verdict = 'REVIEW'           # fastjson 1.2.x but outside 1.2.66-83 tested range
    elif any_vuln_range or (any_1x and unknown):
        verdict = 'FASTJSON_NO_SB'   # fastjson at risk but no SB fat-jar loader here
    elif any_1x or unknown:
        verdict = 'REVIEW'
    else:
        verdict = 'FASTJSON2_OR_SAFE'

    return {'artifact': path, 'verdict': verdict, 'spring_boot_loader': sb,
            'build_jdk': manifest.get('Build-Jdk-Spec') or manifest.get('Build-Jdk'),
            'fastjson': findings}


def walk(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for fn in files:
                    if fn.endswith(('.jar', '.war', '.ear')):
                        yield os.path.join(root, fn)
        elif os.path.isfile(p):
            yield p


def main(argv):
    as_json = False
    threads = 8
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--json':
            as_json = True
        elif a == '--threads':
            i += 1; threads = int(argv[i])
        elif a.startswith('--threads='):
            threads = int(a.split('=', 1)[1])
        else:
            args.append(a)
        i += 1
    if not args:
        print(__doc__); return 1

    files = list(walk(args))
    workers = max(1, min(threads, len(files) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = [r for r in pool.map(scan_artifact, files) if r]
    exposed = [r for r in results if r['verdict'] == 'EXPOSED']

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        order = {'EXPOSED': 0, 'REVIEW': 1, 'FASTJSON_NO_SB': 2, 'FASTJSON2_OR_SAFE': 3, 'NO_FASTJSON': 4}
        for r in sorted(results, key=lambda x: order.get(x['verdict'], 9)):
            if r['verdict'] == 'NO_FASTJSON':
                continue
            vers = ','.join(sorted({f['fastjson_version'] or '??' for f in r['fastjson']})) or '-'
            print(f"[{r['verdict']:16}] {r['artifact']}")
            print(f"      fastjson={vers}  spring_boot_loader={r['spring_boot_loader']}  build_jdk={r['build_jdk']}")
            for f in r['fastjson']:
                print(f"        - {f['fastjson_version'] or '??'}  ({f['detected_by']})  {f['where']}")
        print(f"\nscanned={len(results)}  EXPOSED={len(exposed)}  "
              f"REVIEW={sum(1 for r in results if r['verdict']=='REVIEW')}  "
              f"fastjson-no-SB={sum(1 for r in results if r['verdict']=='FASTJSON_NO_SB')}")
        if exposed:
            print("\nEXPOSED = fastjson 1.2.66-1.2.83 + Spring Boot fat-jar loader in the same artifact.")
            print("Confirm runtime JDK is 8 (RCE) vs 9+ (SSRF-only), then probe live with fjscan_probe.py.")
    return 2 if exposed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
