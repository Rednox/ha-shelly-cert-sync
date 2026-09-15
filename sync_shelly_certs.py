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

If the Shelly devices have a password set, supply it via --device-password.
The same password is used for all devices (HTTP Digest auth, user "admin").
"""

import argparse
import base64
import json
import os
import re
import ssl
import sys
import urllib.request
from typing import Optional


# Minimum firmware version that supports the TLS certificate RPC methods.
# Allterco's own AWS-IoT provisioning tooling enforces >= 1.4.2 before
# calling PutUserCA / PutTLSClientCert / PutTLSClientKey, and treats
# firmware below 1.3.0 as "too old to update automatically".
# Gen-1 devices use a completely different REST API and are not supported.
MIN_FW_VERSION = (1, 4, 2)

# Supervisor-injected env vars available inside HA add-ons / shell_commands
_SUPERVISOR_TOKEN_ENV = "SUPERVISOR_TOKEN"
_SUPERVISOR_API_URL = "http://supervisor/core"

# Fixed username used by Shelly Gen-2/Gen-3 devices
_DEVICE_USERNAME = "admin"


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
    print("Discovering Shelly devices from Home Assistant …")

    # Step 1: collect all entity_ids from the shelly integration
    try:
        raw = _ha_request(
            ha_url, token, "/api/template", timeout,
            payload={"template": "{{ integration_entities('shelly') | list | tojson }}"},
        )
        # The template API returns a plain string (the rendered template)
        entity_ids: list[str] = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as exc:
        print(f"  ERROR fetching Shelly entity list from HA: {exc}")
        return []

    if not entity_ids:
        print("  No Shelly entities found in Home Assistant.")
        return []

    # Step 2: resolve configuration_url for each unique device.
    # Validate entity_id format before embedding in Jinja2 template to
    # prevent template injection from a malformed or malicious entity_id.
    _SAFE_ENTITY_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
    urls: set[str] = set()
    for entity_id in entity_ids:
        if not _SAFE_ENTITY_ID.match(entity_id):
            print(f"  WARNING: skipping entity_id with unexpected characters: {entity_id!r}")
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
                urls.add(config_url)
        except Exception:
            pass  # skip entities we can't resolve

    # Extract host from "http://<host>:<port>" or "https://<host>:<port>"
    hosts: list[str] = []
    for url in sorted(urls):
        if "://" in url:
            host_port = url.split("://", 1)[1].rstrip("/")
            # Strip port, keep only host
            host = host_port.split(":")[0]
            if host:
                hosts.append(host)

    if hosts:
        print(f"  Found {len(hosts)} Shelly device(s): {', '.join(hosts)}")
    else:
        print("  No Shelly devices with a configuration_url found.")

    return hosts


# ---------------------------------------------------------------------------
# Firmware version check
# ---------------------------------------------------------------------------

def _parse_fw_version(ver_str: str) -> tuple[int, ...]:
    """
    Parse a Shelly firmware version string such as '1.4.2-g6d2a586' or
    '20231219-133223/1.1.0@6b5e5587' into a comparable integer tuple.
    """
    # Extract the first dotted-decimal portion
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
    if m:
        return tuple(int(x) for x in m.groups())
    # Fallback: try just major.minor
    m = re.search(r"(\d+)\.(\d+)", ver_str)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)
    return (0, 0, 0)


def check_firmware(host: str, port: int, timeout: int,
                   device_password: Optional[str] = None) -> tuple[bool, str]:
    """
    Verify the device is Gen-2+ and capable of TLS certificate uploads.

    Two-step approach recommended by Allterco's own fleet management tooling:
      1. Call Shelly.ListMethods and confirm all three Put* methods are present
         (runtime capability detection — more reliable than version comparison).
      2. If ListMethods is unavailable, fall back to firmware version check
         (>= 1.4.2 per Allterco's AWS-IoT provisioning script).

    Gen-1 devices do not implement Shelly.GetDeviceInfo on /rpc and will
    fail the initial request, which we treat as "not supported".
    """
    opener = _device_opener(host, port, device_password)
    url = f"http://{host}:{port}/rpc/Shelly.GetDeviceInfo"
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            info = json.loads(resp.read().decode())
    except Exception as exc:
        return False, f"Could not reach device: {exc}"

    # "gen" field: 1 = Gen-1, 2 = Gen-2, 3 = Gen-3
    gen = info.get("gen", 1)
    if gen < 2:
        return False, f"Gen-{gen} device – RPC TLS methods not supported"

    # Preferred: runtime capability check via Shelly.ListMethods
    try:
        lm_url = f"http://{host}:{port}/rpc/Shelly.ListMethods"
        lm_req = urllib.request.Request(lm_url, method="GET")
        with opener.open(lm_req, timeout=timeout) as lm_resp:
            methods_resp = json.loads(lm_resp.read().decode())
        methods = set(methods_resp.get("methods", []))
        required = {"Shelly.PutUserCA", "Shelly.PutTLSClientCert", "Shelly.PutTLSClientKey"}
        missing = required - methods
        if missing:
            return False, f"Device does not advertise required methods: {', '.join(sorted(missing))}"
        fw_str = info.get("fw_id") or info.get("ver") or "unknown"
        return True, f"Gen-{gen}, firmware {fw_str} (ListMethods OK)"
    except Exception:
        pass  # ListMethods unavailable; fall back to version check

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
                   device_password: Optional[str]) -> urllib.request.OpenerDirector:
    """
    Build an urllib opener for a Shelly device.
    When device_password is set, attaches an HTTPDigestAuthHandler so that
    401 challenges are answered automatically with user "admin" + password.
    """
    if device_password:
        mgr = urllib.request.HTTPPasswordMgr()
        mgr.add_password(
            realm=None,
            uri=f"http://{host}:{port}/",
            user=_DEVICE_USERNAME,
            passwd=device_password,
        )
        return urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))
    return urllib.request.build_opener()


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def _rpc_call(host: str, port: int, method: str, params: dict,
              timeout: int, device_password: Optional[str] = None) -> dict:
    """Send a single HTTP RPC call and return the parsed JSON response."""
    url = f"http://{host}:{port}/rpc/Shelly.{method}"
    body = json.dumps(params).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = _device_opener(host, port, device_password)
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _upload_file(host: str, port: int, method: str, pem_text: str,
                 chunk_size: int, timeout: int, dry_run: bool,
                 device_password: Optional[str] = None) -> bool:
    """
    Upload a PEM file to a Shelly device using the given RPC method name.
    Returns True on success, False on any error.
    """
    # Step 1: clear existing data
    if dry_run:
        print(f"    [dry-run] {method}: clear (data=null)")
    else:
        try:
            _rpc_call(host, port, method, {"data": None}, timeout, device_password)
        except Exception as exc:
            print(f"    ERROR clearing {method}: {exc}")
            return False

    # Step 2: upload chunks as base64
    encoded = base64.b64encode(pem_text.encode()).decode()
    chunks = [encoded[i:i + chunk_size]
              for i in range(0, len(encoded), chunk_size)]

    for idx, chunk in enumerate(chunks):
        if dry_run:
            print(f"    [dry-run] {method}: chunk {idx + 1}/{len(chunks)}")
            continue
        try:
            _rpc_call(host, port, method, {"data": chunk, "append": True}, timeout,
                      device_password)
        except Exception as exc:
            print(f"    ERROR uploading chunk {idx + 1} via {method}: {exc}")
            return False

    if not dry_run:
        print(f"    {method}: OK ({len(chunks)} chunk(s))")
    return True


# ---------------------------------------------------------------------------
# TLS connectivity test
# ---------------------------------------------------------------------------

def _test_tls(host: str, timeout: int,
              device_password: Optional[str] = None) -> tuple[bool, str]:
    """
    Try an HTTPS GET to the device. Returns (success, reason).
    Certificate verification is intentionally disabled because we just pushed
    a new cert and the device CA trust may not match the calling machine.
    When a device password is set, Digest auth is applied over HTTPS as well.
    """
    url = f"https://{host}/rpc/Shelly.GetDeviceInfo"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method="GET")
        if device_password:
            mgr = urllib.request.HTTPPasswordMgr()
            mgr.add_password(None, f"https://{host}/", _DEVICE_USERNAME, device_password)
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx),
                urllib.request.HTTPDigestAuthHandler(mgr),
            )
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
        else:
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                status = resp.status
        if status == 200:
            return True, "HTTP 200"
        return False, f"HTTP {status}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# SSL-only enforcement (Gen-2 / Gen-3 devices)
# ---------------------------------------------------------------------------

def _enforce_ssl_only(host: str, port: int, timeout: int, dry_run: bool,
                      device_password: Optional[str] = None) -> bool:
    """
    Enable SSL-only mode via Shelly.SetConfig (ssl_ca = "*").
    Returns True on success.
    """
    params = {
        "config": {
            "sys": {
                "device": {
                    "ssl_ca": "*"  # '*' = use uploaded CA; enforces HTTPS-only
                }
            }
        }
    }
    if dry_run:
        print("    [dry-run] Shelly.SetConfig: ssl_ca=* (SSL-only)")
        return True
    try:
        _rpc_call(host, port, "SetConfig", params, timeout, device_password)
        print("    Shelly.SetConfig: SSL-only enforced")
        return True
    except Exception as exc:
        print(f"    ERROR enforcing SSL-only via Shelly.SetConfig: {exc}")
        return False


# ---------------------------------------------------------------------------
# Per-host processing
# ---------------------------------------------------------------------------

def process_host(host: str, args: argparse.Namespace,
                 ca_text: Optional[str],
                 cert_text: Optional[str],
                 key_text: Optional[str]) -> bool:
    """Process one host; return True if every step succeeded."""
    print(f"\n=== Host: {host} ===")
    pwd = args.device_password  # None if not set

    # --- firmware / generation check ---
    if args.dry_run:
        print("    [dry-run] firmware check skipped")
    else:
        supported, fw_reason = check_firmware(host, args.port, args.timeout, pwd)
        if not supported:
            print(f"    SKIP: {fw_reason}")
            return False
        print(f"    Firmware OK: {fw_reason}")

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
            args.chunk_size, args.timeout, args.dry_run, pwd,
        )
        if not ok:
            host_ok = False

    # --- TLS test ---
    if args.dry_run:
        print("    [dry-run] TLS test skipped")
        tls_ok = False  # don't proceed to SSL-only in dry-run
    else:
        tls_ok, reason = _test_tls(host, args.timeout, pwd)
        if tls_ok:
            print(f"    TLS test: PASS ({reason})")
        else:
            print(f"    TLS test: FAIL ({reason})")
            host_ok = False

    # --- SSL-only enforcement ---
    if args.no_enforce_ssl_only:
        print("    SSL-only: skipped (--no-enforce-ssl-only)")
    elif not tls_ok:
        print("    SSL-only: skipped (TLS test did not pass)")
    else:
        ssl_ok = _enforce_ssl_only(host, args.port, args.timeout, args.dry_run, pwd)
        if not ssl_ok:
            host_ok = False

    return host_ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Upload Let's Encrypt certs to Shelly devices via HTTP RPC. "
            "Hosts can be supplied explicitly (--hosts) or discovered "
            "automatically from Home Assistant (--ha-url + --ha-token). "
            "When running as an HA shell_command both flags are optional: "
            "the Supervisor token and API URL are read from the environment."
        )
    )

    # Host selection (one of the two groups is required; validated in main)
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

    parser.add_argument("--ca-file", default=None, help="Path to CA PEM file.")
    parser.add_argument("--cert-file", default=None, help="Path to TLS client cert PEM.")
    parser.add_argument("--key-file", default=None, help="Path to TLS client key PEM.")
    parser.add_argument(
        "--device-password",
        default=None,
        metavar="PASSWORD",
        help=(
            "Device password (HTTP Digest auth, user 'admin'). "
            "Applied to all hosts. Omit if devices have no password set."
        ),
    )
    parser.add_argument("--port", type=int, default=80, help="HTTP port (default 80).")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds.")
    parser.add_argument("--chunk-size", type=int, default=1024,
                        help="Base64 chunk size for upload (default 1024).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without sending mutating requests.")
    parser.add_argument("--no-enforce-ssl-only", action="store_true",
                        help="Skip SSL-only switch even if TLS test passes.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Validate: at least one file must be provided
    if not any([args.ca_file, args.cert_file, args.key_file]):
        print("ERROR: at least one of --ca-file, --cert-file, --key-file is required.")
        return 1

    # Resolve host list
    if args.hosts and args.ha_url:
        print("ERROR: use either --hosts or --ha-url, not both.")
        return 1

    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    else:
        # Auto-detect HA Supervisor environment when neither --ha-url nor
        # --ha-token was passed (e.g. when invoked as an HA shell_command).
        supervisor_token = os.environ.get(_SUPERVISOR_TOKEN_ENV, "")
        ha_url = args.ha_url or (_SUPERVISOR_API_URL if supervisor_token else None)
        ha_token = args.ha_token or supervisor_token or None

        if not ha_url:
            print(
                "ERROR: provide --hosts or --ha-url to specify target device(s), "
                f"or run inside Home Assistant where ${_SUPERVISOR_TOKEN_ENV} is set."
            )
            return 1
        if not ha_token:
            print("ERROR: --ha-token is required when using --ha-url.")
            return 1

        hosts = discover_shelly_hosts(ha_url, ha_token, args.timeout)
        if not hosts:
            print("No Shelly hosts discovered; nothing to do.")
            return 1

    # Read PEM files once
    def read_pem(path: Optional[str]) -> Optional[str]:
        if path is None:
            return None
        with open(path) as fh:
            return fh.read()

    try:
        ca_text = read_pem(args.ca_file)
        cert_text = read_pem(args.cert_file)
        key_text = read_pem(args.key_file)
    except OSError as exc:
        print(f"ERROR reading file: {exc}")
        return 1

    results = {}
    for host in hosts:
        results[host] = process_host(host, args, ca_text, cert_text, key_text)

    # Summary
    print("\n=== Summary ===")
    passed = sum(1 for ok in results.values() if ok)
    failed = len(results) - passed
    for host, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"  {host}: {status}")
    print(f"\n{passed} succeeded, {failed} failed.")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

