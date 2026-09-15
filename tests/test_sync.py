"""
Lightweight tests for sync_shelly_certs.py covering:
- argument parsing for all new flags
- auth option validation (username without password → exit 2)
- logging setup behaviour
- dry-run unauthenticated path
- dry-run authenticated path
- HA discovery path (supervisor env detection)
"""

import importlib.util
import logging
import os
import sys
import types
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Import the script as a module (it is not a package, so use importlib)
# ---------------------------------------------------------------------------
_SCRIPT = Path(__file__).parent.parent / "sync_shelly_certs.py"
spec = importlib.util.spec_from_file_location("sync_shelly_certs", _SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TestParseArgs(unittest.TestCase):
    """Argument parsing for new and existing flags."""

    def _parse(self, *argv):
        return m.parse_args(list(argv))

    def test_hosts_explicit(self):
        args = self._parse("--hosts", "1.2.3.4", "--cert-file", "/f.pem")
        self.assertEqual(args.hosts, "1.2.3.4")

    def test_debug_flag(self):
        args = self._parse("--hosts", "1.2.3.4", "--ca-file", "/ca.pem", "--debug")
        self.assertTrue(args.debug)

    def test_log_file_flag(self):
        args = self._parse("--hosts", "1.2.3.4", "--ca-file", "/ca.pem",
                           "--log-file", "/tmp/out.log")
        self.assertEqual(args.log_file, "/tmp/out.log")

    def test_device_password_only(self):
        args = self._parse("--hosts", "1.2.3.4", "--cert-file", "/c.pem",
                           "--device-password", "secret")
        self.assertEqual(args.device_password, "secret")
        self.assertIsNone(args.device_username)  # main() fills the default

    def test_device_username_and_password(self):
        args = self._parse("--hosts", "1.2.3.4", "--cert-file", "/c.pem",
                           "--device-username", "myuser", "--device-password", "mypass")
        self.assertEqual(args.device_username, "myuser")
        self.assertEqual(args.device_password, "mypass")

    def test_no_enforce_ssl_only(self):
        args = self._parse("--hosts", "1.2.3.4", "--cert-file", "/c.pem",
                           "--no-enforce-ssl-only")
        self.assertTrue(args.no_enforce_ssl_only)

    def test_ha_url_and_token(self):
        args = self._parse("--ha-url", "http://ha:8123", "--ha-token", "tok",
                           "--cert-file", "/c.pem")
        self.assertEqual(args.ha_url, "http://ha:8123")
        self.assertEqual(args.ha_token, "tok")

    def test_dry_run(self):
        args = self._parse("--hosts", "1.2.3.4", "--ca-file", "/ca.pem", "--dry-run")
        self.assertTrue(args.dry_run)


class TestAuthValidation(unittest.TestCase):
    """main() should enforce auth flag consistency."""

    def _main(self, *argv):
        return m.main(list(argv))

    def test_username_without_password_returns_2(self):
        rc = self._main("--hosts", "1.2.3.4", "--ca-file", "/dev/null",
                        "--device-username", "admin")
        self.assertEqual(rc, 2)

    def test_password_without_username_defaults_username(self):
        """--device-password alone should succeed (username defaults to 'admin')."""
        with patch.object(m, "process_host", return_value=True):
            rc = self._main("--hosts", "1.2.3.4", "--ca-file", "/dev/null",
                            "--device-password", "secret", "--dry-run")
        self.assertEqual(rc, 0)

    def test_no_file_returns_2(self):
        rc = self._main("--hosts", "1.2.3.4")
        self.assertEqual(rc, 2)

    def test_hosts_and_ha_url_mutually_exclusive(self):
        rc = self._main("--hosts", "1.2.3.4", "--ha-url", "http://ha:8123",
                        "--ca-file", "/dev/null")
        self.assertEqual(rc, 2)


class TestLoggingSetup(unittest.TestCase):
    """setup_logging() should configure level and handlers correctly."""

    def setUp(self):
        # Remove all handlers from the root logger between tests
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)

    def test_info_level_by_default(self):
        m.setup_logging(debug=False, log_file=None)
        self.assertEqual(logging.getLogger().level, logging.INFO)

    def test_debug_level_when_debug_true(self):
        m.setup_logging(debug=True, log_file=None)
        self.assertEqual(logging.getLogger().level, logging.DEBUG)

    def test_file_handler_added(self):
        path = "/tmp/_shelly_test_log.txt"
        try:
            m.setup_logging(debug=False, log_file=path)
            handlers = logging.getLogger().handlers
            file_handlers = [h for h in handlers if isinstance(h, logging.FileHandler)]
            self.assertTrue(any(h.baseFilename == path for h in file_handlers))
        finally:
            for h in logging.getLogger().handlers[:]:
                if isinstance(h, logging.FileHandler) and h.baseFilename == path:
                    h.close()
                    logging.getLogger().removeHandler(h)
            if os.path.exists(path):
                os.unlink(path)


class TestDryRunPaths(unittest.TestCase):
    """End-to-end dry-run through main() without network calls."""

    # Firmware check now always runs (even in dry-run) for accurate method
    # selection — mock it so tests don't require network access.
    _fw_patch = staticmethod(lambda: patch.object(
        m, "check_firmware",
        return_value=(True, "Gen-2, firmware 1.5.0 (ListMethods OK)",
                      {"Shelly.PutUserCA",
                       "Shelly.PutHTTPServerCert", "Shelly.PutHTTPServerKey"})
    ))

    def _main(self, *argv):
        with self._fw_patch():
            return m.main(list(argv))

    def test_unauthenticated_dry_run(self):
        rc = self._main("--hosts", "1.2.3.4", "--ca-file", "/dev/null", "--dry-run")
        self.assertEqual(rc, 0)

    def test_authenticated_dry_run(self):
        rc = self._main(
            "--hosts", "1.2.3.4",
            "--ca-file", "/dev/null",
            "--device-username", "admin",
            "--device-password", "pass",
            "--dry-run",
        )
        self.assertEqual(rc, 0)

    def test_debug_dry_run(self):
        rc = self._main("--hosts", "1.2.3.4", "--cert-file", "/dev/null",
                        "--dry-run", "--debug")
        self.assertEqual(rc, 0)

    def test_dry_run_uses_http_server_method_when_advertised(self):
        """Dry-run must log PutHTTPServerCert when device advertises it."""
        import io
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setLevel(logging.DEBUG)
        root = logging.getLogger()
        old_level = root.level
        root.setLevel(logging.DEBUG)
        try:
            root.addHandler(handler)
            self._main("--hosts", "1.2.3.4", "--cert-file", "/dev/null", "--dry-run", "--debug")
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        output = buf.getvalue()
        self.assertIn("PutHTTPServerCert", output)
        self.assertNotIn("PutTLSClientCert", output)


class TestHADiscovery(unittest.TestCase):
    """HA discovery path: supervisor env detection."""

    def test_supervisor_env_used_when_no_ha_url(self):
        """When SUPERVISOR_TOKEN is set and no --ha-url, supervisor URL is used."""
        with patch.dict(os.environ, {"SUPERVISOR_TOKEN": "fake_tok"}):
            with patch.object(m, "discover_shelly_hosts", return_value=["192.168.1.50"]) as mock_disc:
                with patch.object(m, "process_host", return_value=True):
                    rc = m.main(["--cert-file", "/dev/null", "--dry-run"])
        mock_disc.assert_called_once_with(
            m._SUPERVISOR_API_URL, "fake_tok", unittest.mock.ANY
        )
        self.assertEqual(rc, 0)

    def test_no_supervisor_token_and_no_hosts_returns_2(self):
        env = {k: v for k, v in os.environ.items() if k != "SUPERVISOR_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            rc = m.main(["--cert-file", "/dev/null"])
        self.assertEqual(rc, 2)


class TestDeviceOpener(unittest.TestCase):
    """Verify _device_opener covers both HTTP and HTTPS and that all device
    helpers use the shared opener rather than building their own."""

    def test_unauthenticated_opener_has_https_handler(self):
        """Unauthenticated opener should still use the no-verify HTTPS handler."""
        import urllib.request as ur
        opener = m._device_opener("1.2.3.4", 80, None, None)
        handler_types = [type(h).__name__ for h in opener.handlers]
        self.assertIn("HTTPSHandler", handler_types)

    def test_authenticated_opener_has_digest_and_https_handlers(self):
        import urllib.request as ur
        opener = m._device_opener("1.2.3.4", 80, "admin", "secret")
        handler_types = [type(h).__name__ for h in opener.handlers]
        self.assertIn("HTTPSHandler", handler_types)
        self.assertIn("HTTPDigestAuthHandler", handler_types)

    def test_authenticated_opener_registers_both_schemes(self):
        """Password manager must have credentials for both http and https URIs."""
        import urllib.request as ur
        opener = m._device_opener("1.2.3.4", 80, "admin", "secret")
        digest_handler = next(
            h for h in opener.handlers if isinstance(h, ur.HTTPDigestAuthHandler)
        )
        mgr = digest_handler.passwd
        http_creds = mgr.find_user_password(None, "http://1.2.3.4:80/rpc/Shelly.GetDeviceInfo")
        https_creds = mgr.find_user_password(None, "https://1.2.3.4/rpc/Shelly.GetDeviceInfo")
        self.assertEqual(http_creds, ("admin", "secret"))
        self.assertEqual(https_creds, ("admin", "secret"))

    def test_rpc_call_uses_passed_opener(self):
        """_rpc_call must use the provided opener, not build its own."""
        mock_opener = MagicMock()
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"result": "ok"}'
        mock_opener.open.return_value = mock_resp
        result = m._rpc_call("1.2.3.4", 80, "GetDeviceInfo", {}, 5, mock_opener)
        mock_opener.open.assert_called_once()
        self.assertEqual(result, {"result": "ok"})

    def test_test_tls_uses_passed_opener(self):
        """_test_tls must use the provided opener (not build its own)."""
        mock_opener = MagicMock()
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        mock_opener.open.return_value = mock_resp
        ok, reason = m._test_tls("1.2.3.4", 5, mock_opener)
        mock_opener.open.assert_called_once()
        self.assertTrue(ok)

    def test_check_firmware_uses_passed_opener(self):
        """check_firmware must use the provided opener for all its requests."""
        import json as _json
        mock_opener = MagicMock()

        def fake_open(req, timeout):
            resp = MagicMock()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.status = 200
            if "GetDeviceInfo" in req.full_url:
                resp.read.return_value = _json.dumps({"gen": 2, "fw_id": "1.5.0"}).encode()
            else:
                resp.read.return_value = _json.dumps(
                    {"methods": ["Shelly.PutUserCA", "Shelly.PutTLSClientCert",
                                 "Shelly.PutTLSClientKey"]}
                ).encode()
            return resp

        mock_opener.open.side_effect = fake_open
        ok, reason, methods = m.check_firmware("1.2.3.4", 80, 5, mock_opener)
        self.assertTrue(ok)
        self.assertIsNotNone(methods)
        self.assertGreaterEqual(mock_opener.open.call_count, 1)

    def test_uses_password_mgr_with_default_realm(self):
        """Opener must use HTTPPasswordMgrWithDefaultRealm so credentials are
        returned for any realm string the Shelly device includes in its
        Digest challenge (e.g. 'Shelly', device name, etc.)."""
        import urllib.request as ur
        opener = m._device_opener("1.2.3.4", 80, "admin", "secret")
        digest_handler = next(
            h for h in opener.handlers if isinstance(h, ur.HTTPDigestAuthHandler)
        )
        self.assertIsInstance(digest_handler.passwd,
                              ur.HTTPPasswordMgrWithDefaultRealm,
                              "Must use HTTPPasswordMgrWithDefaultRealm, not HTTPPasswordMgr")

    def test_realm_mismatch_still_returns_credentials(self):
        """Credentials must be returned even when the realm from the server
        challenge does not match the realm registered (None)."""
        import urllib.request as ur
        opener = m._device_opener("1.2.3.4", 80, "admin", "secret")
        digest_handler = next(
            h for h in opener.handlers if isinstance(h, ur.HTTPDigestAuthHandler)
        )
        mgr = digest_handler.passwd
        # Shelly devices send realm values like "Shelly" in their 401 challenge;
        # HTTPPasswordMgr would return (None, None) here — DefaultRealm must not.
        for realm in ("Shelly", "admin", "ShellyPro4PM", ""):
            with self.subTest(realm=realm):
                creds = mgr.find_user_password(realm, "http://1.2.3.4:80/rpc/Shelly.ListMethods")
                self.assertEqual(creds, ("admin", "secret"),
                                 f"No credentials returned for realm={realm!r}")

    def test_regression_all_rpc_paths_use_same_opener(self):
        """Regression: GetDeviceInfo, ListMethods, and PutUserCA must all go
        through the same authenticated opener — not individual builds per call."""
        import json as _json
        import urllib.request as ur

        calls = []
        # Save the real function before patching
        real_device_opener = m._device_opener

        def make_opener_with_tracking(host, port, username, password):
            """Wrap real opener to track every open() call."""
            real_opener = real_device_opener(host, port, username, password)

            class TrackingOpener:
                def __init__(self, inner):
                    self._inner = inner
                    self.handlers = inner.handlers

                def open(self, req, timeout=None):
                    calls.append(req.full_url)
                    resp = MagicMock()
                    resp.__enter__ = lambda s: s
                    resp.__exit__ = MagicMock(return_value=False)
                    resp.status = 200
                    if "GetDeviceInfo" in req.full_url:
                        resp.read.return_value = _json.dumps(
                            {"gen": 2, "fw_id": "1.5.0"}
                        ).encode()
                    elif "ListMethods" in req.full_url:
                        resp.read.return_value = _json.dumps(
                            {"methods": ["Shelly.PutUserCA",
                                         "Shelly.PutTLSClientCert",
                                         "Shelly.PutTLSClientKey"]}
                        ).encode()
                    else:
                        resp.read.return_value = b"{}"
                    return resp

            return TrackingOpener(real_opener)

        with patch.object(m, "_device_opener", side_effect=make_opener_with_tracking):
            rc = m.main([
                "--hosts", "1.2.3.4",
                "--ca-file", "/dev/null",
                "--no-enforce-ssl-only",  # skip TLS test so we focus on upload path
            ])

        # All device calls (GetDeviceInfo, ListMethods, PutUserCA) must appear
        self.assertTrue(any("GetDeviceInfo" in u for u in calls), f"Missing GetDeviceInfo in {calls}")
        self.assertTrue(any("ListMethods" in u for u in calls), f"Missing ListMethods in {calls}")
        self.assertTrue(any("PutUserCA" in u for u in calls), f"Missing PutUserCA in {calls}")


class TestMethodSelection(unittest.TestCase):
    """Verify process_host picks PutHTTPServerCert/Key when available,
    falls back to PutTLSClientCert/Key otherwise."""

    def _run_with_methods(self, device_methods, argv_extra=None):
        """Run process_host with a mocked check_firmware returning device_methods.
        Returns the list of RPC method names that were passed to _upload_file."""
        import json as _json
        upload_calls = []

        def fake_upload(host, port, method, pem_text, chunk_size, timeout, dry_run, opener):
            upload_calls.append(method)
            return True

        def fake_check_firmware(host, port, timeout, opener):
            return True, "Gen-2, firmware 1.5.0 (ListMethods OK)", device_methods

        with patch.object(m, "check_firmware", side_effect=fake_check_firmware):
            with patch.object(m, "_upload_file", side_effect=fake_upload):
                with patch.object(m, "_test_tls", return_value=(False, "skipped")):
                    argv = [
                        "--hosts", "1.2.3.4",
                        "--cert-file", "/dev/null",
                        "--key-file", "/dev/null",
                        "--no-enforce-ssl-only",
                    ]
                    if argv_extra:
                        argv += argv_extra
                    m.main(argv)
        return upload_calls

    def test_prefers_http_server_methods_when_advertised(self):
        """When device advertises PutHTTPServerCert/Key, those must be used."""
        methods = {
            "Shelly.PutUserCA",
            "Shelly.PutHTTPServerCert", "Shelly.PutHTTPServerKey",
            "Shelly.PutTLSClientCert",  "Shelly.PutTLSClientKey",
        }
        calls = self._run_with_methods(methods)
        self.assertIn("PutHTTPServerCert", calls)
        self.assertIn("PutHTTPServerKey",  calls)
        self.assertNotIn("PutTLSClientCert", calls)
        self.assertNotIn("PutTLSClientKey",  calls)

    def test_falls_back_to_tls_client_methods_when_http_server_absent(self):
        """When device only advertises PutTLSClientCert/Key (no HTTP server pair)."""
        methods = {
            "Shelly.PutUserCA",
            "Shelly.PutTLSClientCert", "Shelly.PutTLSClientKey",
        }
        calls = self._run_with_methods(methods)
        self.assertIn("PutTLSClientCert", calls)
        self.assertIn("PutTLSClientKey",  calls)
        self.assertNotIn("PutHTTPServerCert", calls)

    def test_falls_back_to_tls_client_methods_when_list_methods_unavailable(self):
        """When device_methods is None (ListMethods unavailable), use fallback pair."""
        calls = self._run_with_methods(None)
        self.assertIn("PutTLSClientCert", calls)
        self.assertIn("PutTLSClientKey",  calls)
        self.assertNotIn("PutHTTPServerCert", calls)

    def test_check_firmware_returns_methods_set_on_success(self):
        """check_firmware must return the methods set as third element."""
        import json as _json
        mock_opener = MagicMock()
        http_server_methods = [
            "Shelly.PutUserCA",
            "Shelly.PutHTTPServerCert", "Shelly.PutHTTPServerKey",
        ]

        def fake_open(req, timeout):
            resp = MagicMock()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.status = 200
            if "GetDeviceInfo" in req.full_url:
                resp.read.return_value = _json.dumps({"gen": 2, "fw_id": "1.5.0"}).encode()
            else:
                resp.read.return_value = _json.dumps({"methods": http_server_methods}).encode()
            return resp

        mock_opener.open.side_effect = fake_open
        ok, reason, methods = m.check_firmware("1.2.3.4", 80, 5, mock_opener)
        self.assertTrue(ok)
        self.assertIn("Shelly.PutHTTPServerCert", methods)
        self.assertIn("Shelly.PutHTTPServerKey",  methods)


if __name__ == "__main__":
    unittest.main()
