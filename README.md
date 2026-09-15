# ha-shelly-cert-sync

A minimal Python script that propagates Let's Encrypt (or any PEM) TLS certificates to Shelly Gen-2/Gen-3 devices via their HTTP RPC interface. It can be run manually, by cron, or triggered from a Home Assistant automation after certificate renewal.

---

## What the script does

1. Resolves the target device list – either from `--hosts` (explicit IPs) or automatically by querying the Home Assistant device registry for all devices registered under the Shelly integration (`--ha-url` + `--ha-token`).
2. For each device, calls `Shelly.GetDeviceInfo` and `Shelly.ListMethods` to verify it is a **Gen-2 or Gen-3** device with all three TLS certificate RPC methods available (firmware **≥ 1.4.2** is the tested minimum). Gen-1 devices and devices below the minimum firmware are skipped.
3. Reads one or more PEM files (CA, client cert, client key) from disk.
4. Uploads each file to every listed Shelly device using the appropriate `Shelly.Put*` RPC method (chunked, base64-encoded).
5. After uploading, performs a quick HTTPS connectivity test to verify the device accepted the certificate.
6. If the TLS test passes (and `--no-enforce-ssl-only` is not set), switches the device to SSL-only mode via `Shelly.SetConfig`.
7. Prints a per-host status summary and exits with code `0` only if all hosts succeeded.

---

## Prerequisites

- Python 3.11 or newer (stdlib only – no extra packages needed).
- Shelly **Gen-2 or Gen-3** device running firmware **≥ 1.4.2**. The `Shelly.PutUserCA` / `Shelly.PutTLSClientCert` / `Shelly.PutTLSClientKey` RPC methods require at least this version (per Allterco's own AWS IoT provisioning tooling). The script also does a runtime `Shelly.ListMethods` check before uploading, so devices advertising all three methods are accepted regardless of the reported version number. Gen-1 devices use a completely different REST API and are not supported.
- Network access from the machine running the script to the Shelly device(s) on port 80 (or the configured `--port`).
- For HA auto-discovery: a running Home Assistant instance with the Shelly integration configured and a [long-lived access token](https://developers.home-assistant.io/docs/auth_api/#long-lived-access-token).

---

## CLI usage

```
python sync_shelly_certs.py (--hosts <ip1>[,<ip2>,...] | --ha-url <url> --ha-token <token>) [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--hosts` | — | Comma-separated Shelly IPs or hostnames *(mutually exclusive with --ha-url)* |
| `--ha-url` | — | Home Assistant base URL, e.g. `http://homeassistant.local:8123` |
| `--ha-token` | — | HA long-lived access token (required with `--ha-url`) |
| `--ca-file` | — | Path to CA PEM file |
| `--cert-file` | — | Path to TLS client certificate PEM |
| `--key-file` | — | Path to TLS client key PEM |
| `--port` | `80` | HTTP port of Shelly device |
| `--timeout` | `10` | Request timeout in seconds |
| `--chunk-size` | `1024` | Base64 chunk size for uploads |
| `--dry-run` | off | Print actions without sending mutating requests |
| `--no-enforce-ssl-only` | off | Skip SSL-only enforcement even if TLS test passes |

At least one of `--ca-file`, `--cert-file`, `--key-file` is required.

### Examples

**Auto-discover all Shelly devices from Home Assistant**
```bash
python sync_shelly_certs.py \
  --ha-url http://homeassistant.local:8123 \
  --ha-token YOUR_LONG_LIVED_TOKEN \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem
```

**Upload CA only**
```bash
python sync_shelly_certs.py \
  --hosts 192.168.1.50 \
  --ca-file /ssl/fullchain.pem
```

**Upload cert + key**
```bash
python sync_shelly_certs.py \
  --hosts 192.168.1.50,192.168.1.51 \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem
```

**Upload all three**
```bash
python sync_shelly_certs.py \
  --hosts 192.168.1.50 \
  --ca-file /ssl/chain.pem \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem
```

**Dry run (no mutating calls)**
```bash
python sync_shelly_certs.py \
  --hosts 192.168.1.50 \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem \
  --dry-run
```

**Upload certs but skip SSL-only enforcement**
```bash
python sync_shelly_certs.py \
  --hosts 192.168.1.50 \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem \
  --no-enforce-ssl-only
```

---

## Automating after Let's Encrypt renewal

### Cron (every 12 hours)

```cron
# Using HA auto-discovery (recommended)
0 */12 * * * python /config/scripts/sync_shelly_certs.py \
  --ha-url http://homeassistant.local:8123 \
  --ha-token YOUR_LONG_LIVED_TOKEN \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem >> /var/log/shelly_cert_sync.log 2>&1

# Or with explicit host list
0 */12 * * * python /config/scripts/sync_shelly_certs.py \
  --hosts 192.168.1.50,192.168.1.51 \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem >> /var/log/shelly_cert_sync.log 2>&1
```

### Home Assistant `shell_command` + automation

When the script runs as an HA `shell_command`, the Supervisor automatically injects `SUPERVISOR_TOKEN` into the process environment and the internal API is reachable at `http://supervisor/core`. Both `--ha-url` and `--ha-token` can be omitted — the script detects them automatically.

Add to `configuration.yaml`:

```yaml
shell_command:
  # No --ha-url or --ha-token needed when running inside HA
  sync_shelly_certs: >
    python /config/scripts/sync_shelly_certs.py
    --cert-file /ssl/fullchain.pem
    --key-file /ssl/privkey.pem
```

If you need to run the script externally (e.g. from cron on a different machine) you must supply the URL and token explicitly:

```yaml
shell_command:
  sync_shelly_certs_external: >
    python /config/scripts/sync_shelly_certs.py
    --ha-url http://homeassistant.local:8123
    --ha-token YOUR_LONG_LIVED_TOKEN
    --cert-file /ssl/fullchain.pem
    --key-file /ssl/privkey.pem
```

Trigger after renewal (e.g. after the `certbot` or `Let's Encrypt` integration renews):

```yaml
automation:
  - alias: "Sync Shelly certs after renewal"
    trigger:
      - platform: event
        event_type: folder_watcher
        event_data:
          event_type: modified
          path: /ssl/fullchain.pem
    action:
      - service: shell_command.sync_shelly_certs
```

---

## Security notes

- **Private key handling**: `--key-file` passes your private key over plain HTTP to the Shelly device during the initial upload. This is unavoidable for the first upload because the device doesn't yet have a valid certificate. Ensure the upload happens on a trusted local network segment. After a successful TLS test the device is switched to SSL-only mode, securing subsequent communication.
- **Local network trust**: The script disables TLS certificate verification for the post-upload connectivity test (`ssl.CERT_NONE`). This is intentional: the machine running the script may not trust the newly uploaded CA. The test only checks that a TLS handshake succeeds; it does **not** validate the certificate chain.
- **`--dry-run`**: Use this in CI or testing environments to confirm the correct hosts and files are targeted before making live changes.

---

## Known limitations

- RPC method names (`Shelly.PutUserCA`, `Shelly.PutTLSClientCert`, `Shelly.PutTLSClientKey`, `Shelly.SetConfig`) are documented for Gen-2/Gen-3 firmware. Gen-1 devices use a different REST API and are **not supported**.
- The script performs a `Shelly.ListMethods` probe before uploading — if a device reports all three methods as available, the firmware version requirement is waived. This matches the approach used by Allterco's own fleet management tooling.
- Firmware behaviour (accepted chunk size, CA format, `ssl_ca` config key) may vary between models and firmware versions. The minimum tested version is **1.4.2**. Test against a single device before deploying to many.
- Plain HTTP is used for the initial upload. If the device is already in SSL-only mode and you need to re-upload, temporarily disable SSL-only mode via the Shelly web UI first.
- HA auto-discovery uses `integration_entities("shelly")` and `device_attr(..., "configuration_url")` via the `/api/template` REST endpoint. Renamed entities that no longer belong to the Shelly integration domain will still be found correctly since the filter is by integration domain, not entity name.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Connection refused` on port 80 | Device already in SSL-only mode | Access the Shelly web UI over HTTPS and disable SSL-only, then re-run |
| `timed out` | Wrong IP / device offline | Verify IP and network connectivity |
| `ERROR clearing PutUserCA` | Device doesn't support this RPC | Check firmware version; upgrade to Gen-2+ firmware |
| TLS test FAIL after upload | Cert/CA mismatch or chunking issue | Verify the PEM files are correct and the device rebooted |
| `Shelly.SetConfig` error | Config key differs on this firmware | Use `--no-enforce-ssl-only` and set SSL-only manually via web UI |

---

## Recovery / rollback

If a device becomes unreachable after SSL-only mode is enabled:

1. **Physical reset**: Hold the reset button on the Shelly device for ~10 seconds to restore factory defaults. This clears the SSL configuration.
2. **Network-level access**: If you have access to the device on port 443, connect via HTTPS (`https://<host>/`) and navigate to *Settings → Security* to disable SSL-only.
3. **Re-flash**: As a last resort, use the Shelly OTA / recovery mode to restore firmware.

> **Tip**: Always test with `--no-enforce-ssl-only` first, verify HTTPS access manually, then re-run without that flag.  
