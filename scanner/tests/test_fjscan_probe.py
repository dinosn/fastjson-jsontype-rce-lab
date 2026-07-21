import http.server
import io
import importlib.util
import pathlib
import sys
import threading
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "fjscan_probe.py"
SPEC = importlib.util.spec_from_file_location("fjscan_probe", MODULE_PATH)
fjscan_probe = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = fjscan_probe
SPEC.loader.exec_module(fjscan_probe)


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    paths = []
    port_redirect_url = None

    def _handle(self):
        type(self).paths.append(self.path)
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/port-redirect":
            self.send_response(302)
            self.send_header("Location", type(self).port_redirect_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *_args):
        pass


class ProbeRedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        RedirectHandler.paths = []
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.other_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        cls.other_thread = threading.Thread(target=cls.other_server.serve_forever, daemon=True)
        cls.other_thread.start()
        cls.other_base = f"http://127.0.0.1:{cls.other_server.server_port}"
        RedirectHandler.port_redirect_url = cls.other_base + "/final"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.other_server.shutdown()
        cls.other_server.server_close()
        cls.other_thread.join(timeout=2)

    def setUp(self):
        RedirectHandler.paths = []

    def test_max_redirects_zero_prevents_urllib_auto_follow(self):
        result = fjscan_probe.send(
            "POST",
            self.base + "/start",
            "{}",
            {"Content-Type": "application/json"},
            timeout=2,
            max_redirects=0,
        )
        self.assertEqual("HTTP 302", result)
        self.assertEqual(["/start"], RedirectHandler.paths)

    def test_same_origin_redirect_is_followed_only_when_enabled(self):
        result = fjscan_probe.send(
            "POST",
            self.base + "/start",
            "{}",
            {"Content-Type": "application/json"},
            timeout=2,
            max_redirects=1,
        )
        self.assertEqual("HTTP 204 (+1r)", result)
        self.assertEqual(["/start", "/final"], RedirectHandler.paths)

    def test_cross_host_redirect_is_blocked(self):
        headers, reason = fjscan_probe.redirect_policy(
            "http://127.0.0.1:8080/start",
            "http://localhost:8080/final",
            {"Authorization": "Bearer secret"},
        )
        self.assertIsNone(headers)
        self.assertEqual("cross-host", reason)

    def test_standard_http_to_https_upgrade_strips_all_non_base_headers(self):
        headers, reason = fjscan_probe.redirect_policy(
            "http://example.test:80/start",
            "https://example.test/final",
            {
                "Accept": "*/*",
                "Content-Type": "application/json",
                "User-Agent": "fjscan-test",
                "Authorization": "Bearer secret",
                "Cookie": "session=secret",
                "X-Api-Key": "secret",
            },
        )
        self.assertIsNone(reason)
        self.assertEqual(
            {"Accept", "Content-Type", "User-Agent"},
            set(headers),
        )

    def test_https_downgrade_is_blocked(self):
        headers, reason = fjscan_probe.redirect_policy(
            "https://app.example/start",
            "http://app.example/final",
            {"Content-Type": "application/json"},
        )
        self.assertIsNone(headers)
        self.assertEqual("https-downgrade", reason)

    def test_arbitrary_same_host_port_change_is_blocked(self):
        headers, reason = fjscan_probe.redirect_policy(
            "https://app.example/start",
            "https://app.example:8443/final",
            {"Content-Type": "application/json"},
        )
        self.assertIsNone(headers)
        self.assertEqual("origin-change", reason)

    def test_send_does_not_contact_same_host_different_port(self):
        result = fjscan_probe.send(
            "POST",
            self.base + "/port-redirect",
            '{"secret":"must-not-move"}',
            {"Content-Type": "application/json"},
            timeout=2,
            max_redirects=1,
        )
        self.assertEqual("redirect-blocked-origin-change HTTP 302", result)
        self.assertEqual(["/port-redirect"], RedirectHandler.paths)

    def test_empty_target_input_fails_before_probe_setup(self):
        original_stdin = fjscan_probe.sys.stdin
        try:
            fjscan_probe.sys.stdin = io.StringIO("# comment only\n\n")
            with self.assertRaises(SystemExit) as raised:
                fjscan_probe.main([
                    "--collaborator", "example.test",
                    "--probe-type", "dns",
                    "--targets", "-",
                ])
        finally:
            fjscan_probe.sys.stdin = original_stdin
        self.assertIn("no targets loaded", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
