import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / 'fjscan_static.py'
SPEC = importlib.util.spec_from_file_location('fjscan_static', MODULE_PATH)
fjscan_static = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = fjscan_static
SPEC.loader.exec_module(fjscan_static)


def archive_bytes(entries, compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return output.getvalue()


def fastjson_bytes(version, pom=True, package=True):
    entries = []
    if pom:
        entries.append(
            (
                'META-INF/maven/com.alibaba/fastjson/pom.properties',
                f'groupId=com.alibaba\nartifactId=fastjson\nversion={version}\n',
            )
        )
    if package:
        entries.append(('com/alibaba/fastjson/JSON.class', b'static-test-bytecode'))
    if not entries:
        entries.append(('README.txt', b'not fastjson content'))
    return archive_bytes(entries)


def write_app(path, version, loader=None, pom=True, package=True, nested_name=None):
    nested_name = nested_name or f'BOOT-INF/lib/fastjson-{version}.jar'
    entries = [(nested_name, fastjson_bytes(version, pom=pom, package=package))]
    if loader == 'boot2':
        entries.insert(
            0,
            (
                'org/springframework/boot/loader/LaunchedURLClassLoader.class',
                b'static-test-bytecode',
            ),
        )
    elif loader == 'boot3':
        entries.insert(
            0,
            (
                'org/springframework/boot/loader/launch/LaunchedClassLoader.class',
                b'static-test-bytecode',
            ),
        )
    path.write_bytes(archive_bytes(entries))


class StaticScannerTests(unittest.TestCase):
    def scan(self, version, loader=None, pom=True, package=True):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            write_app(path, version, loader, pom=pom, package=package)
            return fjscan_static.scan_artifact(str(path))

    def test_boot3_verified_fastjson_1283_is_modern_fd_candidate(self):
        result = self.scan('1.2.83', 'boot3')
        self.assertEqual('EXPOSED', result['verdict'])
        self.assertEqual(['boot3'], result['spring_boot_loader_generations'])
        self.assertTrue(result['resource_probe_present'])
        self.assertTrue(result['single_body_fd_candidate'])
        self.assertTrue(result['modern_fd_candidate'])
        self.assertEqual('verified-metadata', result['fastjson'][0]['version_confidence'])

    def test_boot2_verified_fastjson_1283_is_also_modern_fd_candidate(self):
        result = self.scan('1.2.83', 'boot2')
        self.assertEqual('EXPOSED', result['verdict'])
        self.assertTrue(result['modern_fd_candidate'])

    def test_probe_bearing_older_release_is_review_not_proven_rce(self):
        result = self.scan('1.2.67', 'boot2')
        self.assertEqual('REVIEW_PROBE', result['verdict'])
        self.assertTrue(result['resource_probe_present'])
        self.assertFalse(result['single_body_fd_candidate'])

    def test_pre_probe_release_is_review(self):
        result = self.scan('1.2.47', 'boot2')
        self.assertEqual('REVIEW', result['verdict'])
        self.assertFalse(result['resource_probe_present'])

    def test_exact_release_without_boot_loader_is_bounded(self):
        result = self.scan('1.2.83')
        self.assertEqual('FASTJSON_NO_SB', result['verdict'])
        self.assertFalse(result['spring_boot_loader'])

    def test_filename_only_exact_name_is_heuristic_not_exposed(self):
        result = self.scan('1.2.83', 'boot3', pom=False, package=False)
        self.assertEqual('REVIEW', result['verdict'])
        self.assertFalse(result['single_body_fd_candidate'])
        self.assertTrue(result['single_body_fd_version_name_candidate'])
        finding = result['fastjson'][0]
        self.assertEqual('filename-only', finding['version_confidence'])
        self.assertFalse(finding['content_verified'])
        self.assertFalse(finding['version_verified'])

    def test_filename_plus_package_is_content_confirmed_but_version_heuristic(self):
        result = self.scan('1.2.83', 'boot3', pom=False, package=True)
        self.assertEqual('REVIEW', result['verdict'])
        self.assertFalse(result['single_body_fd_candidate'])
        self.assertEqual(
            'content-confirmed-version-heuristic',
            result['fastjson'][0]['version_confidence'],
        )
        self.assertTrue(result['fastjson'][0]['content_verified'])
        self.assertFalse(result['fastjson'][0]['version_verified'])

    def test_archive_pom_without_fastjson_classes_is_metadata_only_review(self):
        result = self.scan('1.2.83', 'boot3', pom=True, package=False)
        self.assertEqual('REVIEW', result['verdict'])
        self.assertFalse(result['resource_probe_present'])
        self.assertFalse(result['single_body_fd_candidate'])
        self.assertFalse(result['modern_fd_candidate'])
        finding = result['fastjson'][0]
        self.assertEqual('metadata-only-unverified', finding['version_confidence'])
        self.assertFalse(finding['content_verified'])
        self.assertFalse(finding['version_verified'])

    def test_four_component_12831_is_not_truncated_to_exact_1283(self):
        result = self.scan('1.2.83.1', 'boot3')
        self.assertEqual((1, 2, 83, 1), fjscan_static.vtuple('1.2.83.1'))
        self.assertEqual('REVIEW', result['verdict'])
        self.assertFalse(result['resource_probe_present'])
        self.assertFalse(result['single_body_fd_candidate'])

    def test_leading_zero_version_is_not_called_exact_1283(self):
        result = self.scan('1.2.083', 'boot3')
        self.assertEqual('REVIEW_PROBE', result['verdict'])
        self.assertTrue(result['resource_probe_present'])
        self.assertFalse(result['single_body_fd_candidate'])

    def test_fastjson_11x_is_never_called_fastjson2_or_safe(self):
        result = self.scan('1.1.75', 'boot3')
        self.assertEqual('REVIEW', result['verdict'])

    def test_exploded_directory_correlates_loader_and_sibling_jar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / 'exploded'
            loader = (
                root
                / 'org/springframework/boot/loader/launch/LaunchedClassLoader.class'
            )
            dependency = root / 'BOOT-INF/lib/fastjson-1.2.83.jar'
            loader.parent.mkdir(parents=True)
            dependency.parent.mkdir(parents=True)
            loader.write_bytes(b'static-test-bytecode')
            dependency.write_bytes(fastjson_bytes('1.2.83'))

            result = fjscan_static.scan_artifact(str(root))
            self.assertEqual('EXPOSED', result['verdict'])
            self.assertEqual('exploded-directory', result['artifact_kind'])
            self.assertEqual(['boot3'], result['spring_boot_loader_generations'])

            errors = []
            discovered = list(fjscan_static.walk([str(root)], errors))
            self.assertIn(os.path.abspath(str(root)), discovered)
            self.assertEqual([], errors)

    def test_exploded_pom_without_fastjson_classes_is_metadata_only_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / 'exploded'
            loader = (
                root
                / 'org/springframework/boot/loader/launch/LaunchedClassLoader.class'
            )
            pom = (
                root
                / 'META-INF/maven/com.alibaba/fastjson/pom.properties'
            )
            loader.parent.mkdir(parents=True)
            pom.parent.mkdir(parents=True)
            loader.write_bytes(b'static-test-bytecode')
            pom.write_text('version=1.2.83\n')

            result = fjscan_static.scan_artifact(str(root))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertFalse(result['resource_probe_present'])
            self.assertFalse(result['single_body_fd_candidate'])
            self.assertFalse(result['modern_fd_candidate'])
            finding = result['fastjson'][0]
            self.assertEqual('metadata-only-unverified', finding['version_confidence'])
            self.assertFalse(finding['content_verified'])
            self.assertFalse(finding['version_verified'])

    def test_exploded_pom_plus_fastjson_class_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / 'exploded'
            loader = (
                root
                / 'org/springframework/boot/loader/launch/LaunchedClassLoader.class'
            )
            pom = root / 'META-INF/maven/com.alibaba/fastjson/pom.properties'
            fastjson_class = root / 'com/alibaba/fastjson/JSON.class'
            loader.parent.mkdir(parents=True)
            pom.parent.mkdir(parents=True)
            fastjson_class.parent.mkdir(parents=True)
            loader.write_bytes(b'static-test-bytecode')
            pom.write_text('version=1.2.83\n')
            fastjson_class.write_bytes(b'static-test-bytecode')

            result = fjscan_static.scan_artifact(str(root))
            self.assertEqual('EXPOSED', result['verdict'])
            self.assertTrue(result['resource_probe_present'])
            self.assertTrue(result['modern_fd_candidate'])

    def test_cli_walk_correlates_thin_loader_and_fastjson_sibling_jars(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / 'thin-app'
            library = root / 'lib'
            library.mkdir(parents=True)
            (library / 'spring-boot-loader.jar').write_bytes(
                archive_bytes(
                    [
                        (
                            'org/springframework/boot/loader/launch/LaunchedClassLoader.class',
                            b'static-test-bytecode',
                        )
                    ]
                )
            )
            (library / 'fastjson-1.2.83.jar').write_bytes(
                fastjson_bytes('1.2.83')
            )

            errors = []
            discovered = list(fjscan_static.walk([str(root)], errors))
            self.assertEqual([], errors)
            self.assertIn(os.path.abspath(str(root)), discovered)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                status = fjscan_static.main(['--json', str(root)])
            self.assertEqual(2, status)
            results = json.loads(stdout.getvalue())
            composition = next(
                result
                for result in results
                if result['artifact'] == os.path.abspath(str(root))
            )
            self.assertEqual('EXPOSED', composition['verdict'])
            self.assertEqual('exploded-directory', composition['artifact_kind'])
            self.assertTrue(composition['modern_fd_candidate'])

    def test_manifest_launcher_without_loader_class_is_heuristic_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            path.write_bytes(
                archive_bytes(
                    [
                        (
                            'META-INF/MANIFEST.MF',
                            b'Manifest-Version: 1.0\n'
                            b'Main-Class: org.springframework.boot.loader.launch.JarLauncher\n',
                        ),
                        (
                            'BOOT-INF/lib/fastjson-1.2.83.jar',
                            fastjson_bytes('1.2.83'),
                        ),
                    ]
                )
            )
            result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertFalse(result['spring_boot_loader'])
            self.assertEqual(
                ['boot3'], result['spring_boot_loader_manifest_candidates']
            )
            self.assertTrue(result['resource_probe_present'])
            self.assertFalse(result['modern_fd_candidate'])

    def test_nested_jar_war_ear_are_recursively_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            deepest = fastjson_bytes('1.2.83')
            ear = archive_bytes([('lib/fastjson-1.2.83.jar', deepest)])
            war = archive_bytes([('WEB-INF/lib/component.ear', ear)])
            root_entries = [
                (
                    'org/springframework/boot/loader/launch/LaunchedClassLoader.class',
                    b'static-test-bytecode',
                ),
                ('BOOT-INF/lib/component.war', war),
            ]
            path.write_bytes(archive_bytes(root_entries))
            result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('EXPOSED', result['verdict'])
            self.assertIn('component.war', result['fastjson'][0]['where'])
            self.assertIn('component.ear', result['fastjson'][0]['where'])

    def test_depth_limit_is_explicit_review_not_silent_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            level_two = archive_bytes(
                [('lib/fastjson-1.2.83.jar', fastjson_bytes('1.2.83'))]
            )
            root_entries = [
                (
                    'org/springframework/boot/loader/launch/LaunchedClassLoader.class',
                    b'static-test-bytecode',
                ),
                ('BOOT-INF/lib/container.jar', level_two),
            ]
            path.write_bytes(archive_bytes(root_entries))
            with mock.patch.object(fjscan_static, 'MAX_NESTED_DEPTH', 1):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertFalse(result['inspection_complete'])
            self.assertTrue(
                any('depth limit' in warning for warning in result['inspection_warnings'])
            )

    def test_entry_count_limit_is_explicit_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            path.write_bytes(
                archive_bytes(
                    [
                        ('one.txt', b'1'),
                        ('two.txt', b'2'),
                        ('three.txt', b'3'),
                    ]
                )
            )
            with mock.patch.object(fjscan_static, 'MAX_ENTRIES_PER_ARCHIVE', 1):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertTrue(
                any('entry-count limit' in warning for warning in result['inspection_warnings'])
            )

    def test_total_entry_count_limit_across_nested_archives_is_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            nested = archive_bytes([('one.txt', b'1'), ('two.txt', b'2')])
            path.write_bytes(archive_bytes([('BOOT-INF/lib/child.jar', nested)]))
            with mock.patch.object(fjscan_static, 'MAX_TOTAL_ENTRIES', 2):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertTrue(
                any(
                    'total entry-count limit' in warning
                    for warning in result['inspection_warnings']
                )
            )

    def test_uncompressed_byte_limit_is_explicit_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            path.write_bytes(archive_bytes([('large.bin', b'A' * 32)]))
            with mock.patch.object(
                fjscan_static, 'MAX_TOTAL_DECLARED_UNCOMPRESSED', 8
            ):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertTrue(
                any(
                    'declared-uncompressed-byte limit' in warning
                    for warning in result['inspection_warnings']
                )
            )

    def test_compression_ratio_limit_is_explicit_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            nested = fastjson_bytes('1.2.83')
            path.write_bytes(
                archive_bytes(
                    [('BOOT-INF/lib/fastjson-1.2.83.jar', nested)],
                    compression=zipfile.ZIP_DEFLATED,
                )
            )
            with mock.patch.object(fjscan_static, 'MAX_COMPRESSION_RATIO', 0.5):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertTrue(
                any('compression-ratio limit' in warning for warning in result['inspection_warnings'])
            )

    def test_nested_read_size_limit_is_explicit_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            write_app(path, '1.2.83', 'boot3')
            with mock.patch.object(
                fjscan_static, 'MAX_SINGLE_NESTED_ARCHIVE_BYTES', 1
            ):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertFalse(result['single_body_fd_candidate'])
            self.assertTrue(
                any('read-size limit' in warning for warning in result['inspection_warnings'])
            )

    def test_total_nested_read_byte_limit_is_explicit_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            write_app(path, '1.2.83', 'boot3')
            with mock.patch.object(fjscan_static, 'MAX_TOTAL_NESTED_READ_BYTES', 1):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertFalse(result['single_body_fd_candidate'])
            self.assertTrue(
                any(
                    'total nested-read-byte limit' in warning
                    for warning in result['inspection_warnings']
                )
            )

    def test_malformed_nested_archive_is_review_with_filename_only_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            path.write_bytes(
                archive_bytes(
                    [
                        (
                            'org/springframework/boot/loader/launch/LaunchedClassLoader.class',
                            b'static-test-bytecode',
                        ),
                        ('BOOT-INF/lib/fastjson-1.2.83.jar', b'not-a-zip'),
                    ]
                )
            )
            result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertFalse(result['inspection_complete'])
            self.assertEqual('filename-only', result['fastjson'][0]['version_confidence'])
            self.assertTrue(result['inspection_errors'])

    def test_inspection_error_downgrades_otherwise_exposed_result_to_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'app.jar'
            path.write_bytes(
                archive_bytes(
                    [
                        (
                            'org/springframework/boot/loader/launch/LaunchedClassLoader.class',
                            b'static-test-bytecode',
                        ),
                        (
                            'BOOT-INF/lib/fastjson-1.2.83.jar',
                            fastjson_bytes('1.2.83'),
                        ),
                        ('BOOT-INF/lib/broken.jar', b'not-a-zip'),
                    ]
                )
            )
            result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertTrue(result['modern_fd_candidate'])
            self.assertTrue(result['inspection_errors'])

    def test_invalid_requested_archive_is_review_and_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'broken.jar'
            path.write_bytes(b'not-a-zip')
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = fjscan_static.main(['--json', str(path)])
            self.assertEqual(1, status)
            self.assertIn('"verdict": "REVIEW"', stdout.getvalue())
            self.assertIn('cannot inspect archive', stdout.getvalue())

    def test_unreadable_requested_archive_is_review_and_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'unreadable.jar'
            path.write_bytes(fastjson_bytes('1.2.83'))
            stderr = io.StringIO()
            with mock.patch.object(fjscan_static.os, 'access', return_value=False):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                    status = fjscan_static.main([str(path)])
            self.assertEqual(1, status)
            self.assertIn('not readable', stderr.getvalue())

    def test_permission_error_during_archive_open_is_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'unreadable.jar'
            path.write_bytes(fastjson_bytes('1.2.83'))
            with mock.patch.object(
                fjscan_static.zipfile,
                'ZipFile',
                side_effect=PermissionError('permission denied'),
            ):
                result = fjscan_static.scan_artifact(str(path))
            self.assertEqual('REVIEW', result['verdict'])
            self.assertFalse(result['inspection_complete'])
            self.assertTrue(
                any('permission denied' in error for error in result['inspection_errors'])
            )

    def test_nonexistent_input_is_explicit_error_and_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = pathlib.Path(directory) / 'missing.jar'
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = fjscan_static.main(['--json', str(missing)])
            self.assertEqual(1, status)
            self.assertEqual('[]', stdout.getvalue().strip())
            self.assertIn('does not exist', stderr.getvalue())
            self.assertIn('no archive or exploded', stderr.getvalue())

    def test_directory_with_zero_artifacts_is_explicit_error_and_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = fjscan_static.main([directory])
            self.assertEqual(1, status)
            self.assertIn('no archive or exploded', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
