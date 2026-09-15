#!/usr/bin/env python3
"""
sync_shelly_certs.py – Upload Let's Encrypt (or any PEM) certificates to
Shelly Gen-2+ devices via the HTTP RPC interface, then optionally enforce
SSL-only mode after a successful TLS connectivity test.
"""

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from typing import Optional


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def _rpc_call(host: str, port: int, method: str, params: dict,
              timeout: int) -> dict:
    """Send a single HTTP RPC call and return the parsed JSON response."""
    url = f"http://{host}:{port}/rpc/Shelly.{method}"
    body = json.dumps(params).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _upload_file(host: str, port: int, method: str, pem_text: str,
                 chunk_size: int, timeout: int, dry_run: bool) -> bool:
    """
    Upload a PEM file to a Shelly device using the given RPC method name.
    Returns True on success, False on any error.
    """
    # Step 1: clear existing data
    if dry_run:
        print(f"    [dry-run] {method}: clear (data=null)")
    else:
        try:
            _rpc_call(host, port, method, {"data": None}, timeout)
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
            _rpc_call(host, port, method, {"data": chunk, "append": True}, timeout)
        except Exception as exc:
            print(f"    ERROR uploading chunk {idx + 1} via {method}: {exc}")
            return False

    if not dry_run:
        print(f"    {method}: OK ({len(chunks)} chunk(s))")
    return True


# ---------------------------------------------------------------------------
# TLS connectivity test
# ---------------------------------------------------------------------------

def _test_tls(host: str, timeout: int) -> tuple[bool, str]:
    """
    Try an HTTPS GET to the device. Returns (success, reason).
    Certificate verification is intentionally disabled because we just pushed
    a new cert and the device CA trust may not match the calling machine.
    """
    url = f"https://{host}/rpc/Shelly.GetDeviceInfo"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                return True, "HTTP 200"
            return False, f"HTTP {resp.status}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# SSL-only enforcement (Gen-2 / Gen-3 devices)
# ---------------------------------------------------------------------------

def _enforce_ssl_only(host: str, port: int, timeout: int, dry_run: bool) -> bool:
    """
    Enable SSL-only mode via Shelly.SetConfig (https_ca_required = true).
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
        _rpc_call(host, port, "SetConfig", params, timeout)
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
            args.chunk_size, args.timeout, args.dry_run,
        )
        if not ok:
            host_ok = False

    # --- TLS test ---
    if args.dry_run:
        print("    [dry-run] TLS test skipped")
        tls_ok = False  # don't proceed to SSL-only in dry-run
    else:
        tls_ok, reason = _test_tls(host, args.timeout)
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
        ssl_ok = _enforce_ssl_only(host, args.port, args.timeout, args.dry_run)
        if not ssl_ok:
            host_ok = False

    return host_ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload Let's Encrypt certs to Shelly devices via HTTP RPC."
    )
    parser.add_argument(
        "--hosts", required=True,
        help="Comma-separated list of Shelly IPs/hostnames.",
    )
    parser.add_argument("--ca-file", default=None, help="Path to CA PEM file.")
    parser.add_argument("--cert-file", default=None, help="Path to TLS client cert PEM.")
    parser.add_argument("--key-file", default=None, help="Path to TLS client key PEM.")
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

    # Read files once
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

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
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
