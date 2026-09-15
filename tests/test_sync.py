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

    def _main(self, *argv):
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
            if "GetDeviceInfo" in req.full_url:
                resp.read.return_value = _json.dumps({"gen": 2, "fw_id": "1.5.0"}).encode()
            else:
                resp.read.return_value = _json.dumps(
                    {"methods": ["Shelly.PutUserCA", "Shelly.PutTLSClientCert",
                                 "Shelly.PutTLSClientKey"]}
                ).encode()
            return resp

        mock_opener.open.side_effect = fake_open
        ok, reason = m.check_firmware("1.2.3.4", 80, 5, mock_opener)
        self.assertTrue(ok)
        self.assertGreaterEqual(mock_opener.open.call_count, 1)


if __name__ == "__main__":
    unittest.main()
