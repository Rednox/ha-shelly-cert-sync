#!/usr/bin/env python3
"""
sync_shelly_certs.py – Upload Let's Encrypt (or any PEM) certificates to
Shelly Gen-2+ devices via the HTTP RPC interface, then optionally enforce
SSL-only mode after a successful TLS connectivity test.

Device hosts can be supplied explicitly via --hosts or discovered
automatically from a running Home Assistant instance via --ha-url /
--ha-token (Shelly integration devices only).

When running as a Home Assistant shell_command the HA Supervisor injects
the SUPERVISOR_TOKEN environment variable and the internal API is reachable
at http://supervisor/core — both --ha-url and --ha-token can be omitted in
that case and are detected automatically.

If the Shelly devices are password-protected, supply credentials via
--device-username (default: admin) and --device-password.
Both flags must be provided together; the same credentials apply to all hosts.
"""

import argparse
import base64
import json
import logging
import os
import re
import ssl
import sys
import urllib.request
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum firmware version that supports the TLS certificate RPC methods.
# Allterco's own AWS-IoT provisioning tooling enforces >= 1.4.2 before
# calling PutUserCA / PutTLSClientCert / PutTLSClientKey, and treats
# firmware below 1.3.0 as "too old to update automatically".
# Gen-1 devices use a completely different REST API and are not supported.
MIN_FW_VERSION = (1, 4, 2)

# Supervisor-injected env vars available inside HA add-ons / shell_commands
_SUPERVISOR_TOKEN_ENV = "SUPERVISOR_TOKEN"
_SUPERVISOR_API_URL = "http://supervisor/core"

# Default device username for Shelly Gen-2/Gen-3
_DEFAULT_DEVICE_USERNAME = "admin"

log = logging.getLogger("shelly_cert_sync")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(debug: bool, log_file: Optional[str]) -> None:
    """Configure the root logger based on CLI flags."""
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(asctime)s %(levelname)-8s %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, handlers=handlers)


# ---------------------------------------------------------------------------
# Home Assistant discovery
# ---------------------------------------------------------------------------

def _ha_request(ha_url: str, token: str, path: str, timeout: int,
                payload: Optional[dict] = None) -> object:
    """Perform a GET (or POST when payload is given) against the HA REST API."""
    url = ha_url.rstrip("/") + path
    method = "POST" if payload is not None else "GET"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method=method,
    )
    log.debug("HA API %s %s", method, url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def discover_shelly_hosts(ha_url: str, token: str, timeout: int) -> list[str]:
    """
    Query the Home Assistant REST API to find all Shelly devices and return
    their IP addresses / hostnames.

    Strategy (pure REST, no WebSocket required):
      1. POST /api/template with integration_entities("shelly") to get all
         entity_ids belonging to the Shelly integration.
      2. For each unique device (deduplicated via device_id(entity_id)),
         resolve its configuration_url via device_attr(..., "configuration_url").
         The Shelly coordinator stores this as "http://<host>:<port>".
    """
    log.info("Discovering Shelly devices from Home Assistant …")

    # Step 1: collect all entity_ids from the shelly integration
    try:
        raw = _ha_request(
            ha_url, token, "/api/template", timeout,
            payload={"template": "{{ integration_entities('shelly') | list | tojson }}"},
        )
        entity_ids: list[str] = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as exc:
        log.error("Could not fetch Shelly entity list from HA: %s", exc)
        return []

    if not entity_ids:
        log.warning("No Shelly entities found in Home Assistant.")
        return []

    log.debug("Found %d Shelly entity_id(s) in HA", len(entity_ids))

    # Step 2: resolve configuration_url for each unique device.
    # Validate entity_id format before embedding in Jinja2 template to
    # prevent template injection from a malformed or malicious entity_id.
    _SAFE_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
    urls: set[str] = set()
    for entity_id in entity_ids:
        if not _SAFE_ENTITY_ID.match(entity_id):
            log.warning("Skipping entity_id with unexpected characters: %r", entity_id)
            continue
        try:
            tmpl = (
                f"{{% set dev_id = device_id('{entity_id}') %}}"
                "{% if dev_id %}"
                "{{ device_attr(dev_id, 'configuration_url') }}"
                "{% endif %}"
            )
            raw_url = _ha_request(
                ha_url, token, "/api/template", timeout,
                payload={"template": tmpl},
            )
            config_url = str(raw_url).strip() if isinstance(raw_url, str) else ""
            if config_url and config_url not in ("None", "null", ""):
                log.debug("entity %s → configuration_url %s", entity_id, config_url)
                urls.add(config_url)
        except Exception as exc:
            log.debug("Could not resolve configuration_url for %s: %s", entity_id, exc)

    # Extract host from "http://<host>:<port>" or "https://<host>:<port>"
    hosts: list[str] = []
    for url in sorted(urls):
        if "://" in url:
            host_port = url.split("://", 1)[1].rstrip("/")
            host = host_port.split(":")[0]
            if host:
                hosts.append(host)

    if hosts:
        log.info("Found %d Shelly device(s): %s", len(hosts), ", ".join(hosts))
    else:
        log.warning("No Shelly devices with a configuration_url found.")

    return hosts


# ---------------------------------------------------------------------------
# Firmware version check
# ---------------------------------------------------------------------------

def _parse_fw_version(ver_str: str) -> tuple[int, ...]:
    """
    Parse a Shelly firmware version string such as '1.4.2-g6d2a586' or
    '20231219-133223/1.1.0@6b5e5587' into a comparable integer tuple.
    """
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
    if m:
        return tuple(int(x) for x in m.groups())
    m = re.search(r"(\d+)\.(\d+)", ver_str)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)
    return (0, 0, 0)


def check_firmware(host: str, port: int, timeout: int,
                   opener: urllib.request.OpenerDirector) -> tuple[bool, str]:
    """
    Verify the device is Gen-2+ and capable of TLS certificate uploads.

    Two-step approach recommended by Allterco's own fleet management tooling:
      1. Call Shelly.ListMethods and confirm all three Put* methods are present.
      2. If ListMethods is unavailable, fall back to firmware version check
         (>= 1.4.2 per Allterco's AWS-IoT provisioning script).
    """
    url = f"http://{host}:{port}/rpc/Shelly.GetDeviceInfo"
    req = urllib.request.Request(url, method="GET")
    log.debug("Firmware check: GET %s", url)
    try:
        with opener.open(req, timeout=timeout) as resp:
            info = json.loads(resp.read().decode())
    except Exception as exc:
        return False, f"Could not reach device: {exc}"

    gen = info.get("gen", 1)
    log.debug("Device gen=%s fw_id=%s", gen, info.get("fw_id") or info.get("ver"))
    if gen < 2:
        return False, f"Gen-{gen} device – RPC TLS methods not supported"

    # Preferred: runtime capability check via Shelly.ListMethods
    try:
        lm_url = f"http://{host}:{port}/rpc/Shelly.ListMethods"
        lm_req = urllib.request.Request(lm_url, method="GET")
        log.debug("ListMethods: GET %s", lm_url)
        with opener.open(lm_req, timeout=timeout) as lm_resp:
            methods_resp = json.loads(lm_resp.read().decode())
        methods = set(methods_resp.get("methods", []))
        required = {"Shelly.PutUserCA", "Shelly.PutTLSClientCert", "Shelly.PutTLSClientKey"}
        missing = required - methods
        if missing:
            return False, (
                f"Device does not advertise required methods: "
                f"{', '.join(sorted(missing))}"
            )
        fw_str = info.get("fw_id") or info.get("ver") or "unknown"
        log.debug("ListMethods OK; required methods present")
        return True, f"Gen-{gen}, firmware {fw_str} (ListMethods OK)"
    except Exception as exc:
        log.debug("ListMethods unavailable (%s); falling back to version check", exc)

    # Fallback: firmware version comparison
    fw_str = info.get("fw_id") or info.get("ver") or ""
    fw_tuple = _parse_fw_version(fw_str)
    if fw_tuple < MIN_FW_VERSION:
        min_str = ".".join(str(x) for x in MIN_FW_VERSION)
        return False, f"Firmware {fw_str} is below minimum {min_str}"

    return True, f"Gen-{gen}, firmware {fw_str}"


# ---------------------------------------------------------------------------
# Device HTTP helpers (with optional Digest auth)
# ---------------------------------------------------------------------------

def _device_opener(host: str, port: int,
                   device_username: Optional[str],
                   device_password: Optional[str]) -> urllib.request.OpenerDirector:
    """
    Build a single urllib opener for all device calls (HTTP and HTTPS).

    Registers credentials for both http:// and https:// base URIs so that
    Digest auth fires correctly for plain-HTTP RPC calls, the HTTPS TLS test,
    and any other device endpoint — all using the same nonce state.

    Certificate verification is intentionally disabled for HTTPS because we
    just pushed a new cert and the device CA is unlikely to be trusted by the
    calling machine.
    """
    # No-verify SSL context used for the HTTPS TLS test
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if device_username and device_password:
        mgr = urllib.request.HTTPPasswordMgr()
        # Register for both http and https so auth works regardless of scheme
        for uri in (f"http://{host}:{port}/", f"https://{host}/"):
            mgr.add_password(None, uri, device_username, device_password)
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPDigestAuthHandler(mgr),
        )
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def _rpc_call(host: str, port: int, method: str, params: dict, timeout: int,
              opener: urllib.request.OpenerDirector) -> dict:
    """Send a single HTTP RPC call and return the parsed JSON response."""
    url = f"http://{host}:{port}/rpc/Shelly.{method}"
    body = json.dumps(params).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    log.debug("RPC POST %s", url)
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _upload_file(host: str, port: int, method: str, pem_text: str,
                 chunk_size: int, timeout: int, dry_run: bool,
                 opener: urllib.request.OpenerDirector) -> bool:
    """
    Upload a PEM file to a Shelly device using the given RPC method name.
    Returns True on success, False on any error.
    """
    encoded = base64.b64encode(pem_text.encode()).decode()
    chunks = [encoded[i:i + chunk_size]
              for i in range(0, len(encoded), chunk_size)]
    log.debug("%s: %d byte(s) → %d chunk(s) of ≤%d", method, len(encoded), len(chunks), chunk_size)

    # Step 1: clear existing data
    if dry_run:
        log.info("  [dry-run] %s: clear (data=null)", method)
    else:
        try:
            _rpc_call(host, port, method, {"data": None}, timeout, opener)
        except Exception as exc:
            log.error("  %s: clear failed: %s", method, exc)
            return False

    # Step 2: upload chunks
    for idx, chunk in enumerate(chunks):
        if dry_run:
            log.info("  [dry-run] %s: chunk %d/%d", method, idx + 1, len(chunks))
            continue
        log.debug("  %s: uploading chunk %d/%d", method, idx + 1, len(chunks))
        try:
            _rpc_call(host, port, method, {"data": chunk, "append": True}, timeout, opener)
        except Exception as exc:
            log.error("  %s: chunk %d/%d failed: %s", method, idx + 1, len(chunks), exc)
            return False

    if not dry_run:
        log.info("  %s: OK (%d chunk(s))", method, len(chunks))
    return True


# ---------------------------------------------------------------------------
# TLS connectivity test
# ---------------------------------------------------------------------------

def _test_tls(host: str, timeout: int,
              opener: urllib.request.OpenerDirector) -> tuple[bool, str]:
    """
    Try an HTTPS GET to the device using the shared opener (which already has
    the no-verify SSL context and any Digest auth configured). Returns (ok, reason).
    """
    url = f"https://{host}/rpc/Shelly.GetDeviceInfo"
    log.debug("TLS test: GET %s (cert verification disabled)", url)
    try:
        req = urllib.request.Request(url, method="GET")
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
        if status == 200:
            return True, "HTTP 200"
        return False, f"HTTP {status}"
    except Exception as exc:
        log.debug("TLS test exception: %s", exc)
        return False, str(exc)


# ---------------------------------------------------------------------------
# SSL-only enforcement (Gen-2 / Gen-3 devices)
# ---------------------------------------------------------------------------

def _enforce_ssl_only(host: str, port: int, timeout: int, dry_run: bool,
                      opener: urllib.request.OpenerDirector) -> bool:
    """
    Enable SSL-only mode via Shelly.SetConfig (ssl_ca = "*").
    Returns True on success.
    """
    params = {"config": {"sys": {"device": {"ssl_ca": "*"}}}}
    if dry_run:
        log.info("  [dry-run] Shelly.SetConfig: ssl_ca=* (SSL-only)")
        return True
    log.debug("Enforcing SSL-only on %s", host)
    try:
        _rpc_call(host, port, "SetConfig", params, timeout, opener)
        log.info("  Shelly.SetConfig: SSL-only enforced")
        return True
    except Exception as exc:
        log.error("  Shelly.SetConfig failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Per-host processing
# ---------------------------------------------------------------------------

def process_host(host: str, args: argparse.Namespace,
                 ca_text: Optional[str],
                 cert_text: Optional[str],
                 key_text: Optional[str]) -> bool:
    """Process one host; return True if every step succeeded."""
    log.info("")
    log.info("=== Host: %s ===", host)

    # Build one opener for this host — shared by all HTTP and HTTPS calls so
    # Digest auth nonce state is preserved across GetDeviceInfo, ListMethods,
    # all Put* uploads, the HTTPS TLS test, and SetConfig.
    opener = _device_opener(host, args.port, args.device_username, args.device_password)

    # --- firmware / generation check ---
    if args.dry_run:
        log.info("  [dry-run] firmware check skipped")
    else:
        log.debug("Running firmware/capability check …")
        supported, fw_reason = check_firmware(host, args.port, args.timeout, opener)
        if not supported:
            log.warning("  SKIP: %s", fw_reason)
            return False
        log.info("  Firmware OK: %s", fw_reason)

    host_ok = True

    # --- uploads ---
    uploads = []
    if ca_text is not None:
        uploads.append(("PutUserCA", ca_text))
    if cert_text is not None:
        uploads.append(("PutTLSClientCert", cert_text))
    if key_text is not None:
        uploads.append(("PutTLSClientKey", key_text))

    for method, pem_text in uploads:
        ok = _upload_file(
            host, args.port, method, pem_text,
            args.chunk_size, args.timeout, args.dry_run, opener,
        )
        if not ok:
            host_ok = False

    # --- TLS test ---
    if args.dry_run:
        log.info("  [dry-run] TLS test skipped")
        tls_ok = False
    else:
        tls_ok, reason = _test_tls(host, args.timeout, opener)
        if tls_ok:
            log.info("  TLS test: PASS (%s)", reason)
        else:
            log.warning("  TLS test: FAIL (%s)", reason)
            host_ok = False

    # --- SSL-only enforcement ---
    if args.no_enforce_ssl_only:
        log.info("  SSL-only: skipped (--no-enforce-ssl-only)")
    elif not tls_ok:
        log.info("  SSL-only: skipped (TLS test did not pass)")
    else:
        ssl_ok = _enforce_ssl_only(host, args.port, args.timeout, args.dry_run, opener)
        if not ssl_ok:
            host_ok = False

    return host_ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Upload Let's Encrypt certs to Shelly devices via HTTP RPC. "
            "Hosts can be supplied explicitly (--hosts) or discovered "
            "automatically from Home Assistant (--ha-url + --ha-token). "
            "When running as an HA shell_command both flags are optional: "
            "the Supervisor token and API URL are read from the environment."
        )
    )

    # Host selection
    host_group = parser.add_argument_group("host selection (use one)")
    host_group.add_argument(
        "--hosts",
        default=None,
        help="Comma-separated list of Shelly IPs/hostnames.",
    )
    host_group.add_argument(
        "--ha-url",
        default=None,
        metavar="URL",
        help=(
            "Home Assistant base URL, e.g. http://homeassistant.local:8123. "
            "Defaults to http://supervisor/core when SUPERVISOR_TOKEN is set."
        ),
    )
    host_group.add_argument(
        "--ha-token",
        default=None,
        metavar="TOKEN",
        help=(
            "Home Assistant long-lived access token. "
            "Defaults to $SUPERVISOR_TOKEN when running inside HA."
        ),
    )

    # PEM files
    parser.add_argument("--ca-file", default=None, help="Path to CA PEM file.")
    parser.add_argument("--cert-file", default=None, help="Path to TLS client cert PEM.")
    parser.add_argument("--key-file", default=None, help="Path to TLS client key PEM.")

    # Device auth
    auth_group = parser.add_argument_group("device authentication")
    auth_group.add_argument(
        "--device-username",
        default=None,
        metavar="USER",
        help=(
            f"Device username for HTTP Digest auth (default: {_DEFAULT_DEVICE_USERNAME}). "
            "Must be used together with --device-password."
        ),
    )
    auth_group.add_argument(
        "--device-password",
        default=None,
        metavar="PASSWORD",
        help=(
            "Device password for HTTP Digest auth. "
            "Applied to all hosts. Must be used together with --device-username "
            f"(or alone, in which case username defaults to {_DEFAULT_DEVICE_USERNAME!r})."
        ),
    )

    # Behaviour
    parser.add_argument("--port", type=int, default=80, help="HTTP port (default 80).")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds.")
    parser.add_argument("--chunk-size", type=int, default=1024,
                        help="Base64 chunk size for upload (default 1024).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without sending mutating requests.")
    parser.add_argument("--no-enforce-ssl-only", action="store_true",
                        help="Skip SSL-only switch even if TLS test passes.")

    # Logging
    log_group = parser.add_argument_group("logging")
    log_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    log_group.add_argument(
        "--log-file",
        default=None,
        metavar="PATH",
        help="Append log output to this file in addition to stdout.",
    )

    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    # Set up logging first so all subsequent messages are formatted
    setup_logging(args.debug, args.log_file)

    # Validate auth args: if either is given, apply default username and require password
    if args.device_password and not args.device_username:
        args.device_username = _DEFAULT_DEVICE_USERNAME
        log.debug("--device-username defaulted to %r", args.device_username)
    if args.device_username and not args.device_password:
        log.error(
            "--device-username was set but --device-password is missing. "
            "Provide both flags or neither."
        )
        return 2

    # Validate: at least one file must be provided
    if not any([args.ca_file, args.cert_file, args.key_file]):
        log.error(
            "At least one of --ca-file, --cert-file, --key-file is required."
        )
        return 2

    # Validate mutual exclusion of host-selection modes
    if args.hosts and args.ha_url:
        log.error("Use either --hosts or --ha-url, not both.")
        return 2

    # Resolve host list
    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
        log.debug("Explicit hosts: %s", hosts)
    else:
        supervisor_token = os.environ.get(_SUPERVISOR_TOKEN_ENV, "")
        ha_url = args.ha_url or (_SUPERVISOR_API_URL if supervisor_token else None)
        ha_token = args.ha_token or supervisor_token or None

        if not ha_url:
            log.error(
                "Provide --hosts or --ha-url to specify target device(s), "
                "or run inside Home Assistant where $%s is set.",
                _SUPERVISOR_TOKEN_ENV,
            )
            return 2
        if not ha_token:
            log.error("--ha-token is required when using --ha-url.")
            return 2

        if ha_url == _SUPERVISOR_API_URL and not args.ha_url:
            log.debug("Using HA Supervisor API at %s (auto-detected)", ha_url)

        hosts = discover_shelly_hosts(ha_url, ha_token, args.timeout)
        if not hosts:
            log.error("No Shelly hosts discovered; nothing to do.")
            return 1

    # Log selected file paths (never log contents)
    log.debug("ca-file:   %s", args.ca_file or "(not set)")
    log.debug("cert-file: %s", args.cert_file or "(not set)")
    log.debug("key-file:  %s", args.key_file or "(not set)")

    # Read PEM files once
    def read_pem(path: Optional[str], label: str) -> Optional[str]:
        if path is None:
            return None
        try:
            with open(path) as fh:
                return fh.read()
        except OSError as exc:
            log.error("Cannot read %s file %r: %s", label, path, exc)
            raise

    try:
        ca_text = read_pem(args.ca_file, "CA")
        cert_text = read_pem(args.cert_file, "cert")
        key_text = read_pem(args.key_file, "key")
    except OSError:
        return 1

    results = {}
    for host in hosts:
        results[host] = process_host(host, args, ca_text, cert_text, key_text)

    # Summary
    log.info("")
    log.info("=== Summary ===")
    passed = sum(1 for ok in results.values() if ok)
    failed = len(results) - passed
    for host, ok in results.items():
        log.info("  %s: %s", host, "OK" if ok else "FAILED")
    log.info("%d succeeded, %d failed.", passed, failed)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())


