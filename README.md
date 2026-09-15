# ha-shelly-cert-sync

A minimal Python script that propagates Let's Encrypt (or any PEM) TLS certificates to Shelly Gen-2/Gen-3 devices via their HTTP RPC interface. It can be run manually, by cron, or triggered from a Home Assistant automation after certificate renewal.

---

## What the script does

1. Reads one or more PEM files (CA, client cert, client key) from disk.
2. Uploads each file to every listed Shelly device using the appropriate `Shelly.Put*` RPC method (chunked, base64-encoded).
3. After uploading, performs a quick HTTPS connectivity test to verify the device accepted the certificate.
4. If the TLS test passes (and `--no-enforce-ssl-only` is not set), switches the device to SSL-only mode via `Shelly.SetConfig`.
5. Prints a per-host status summary and exits with code `0` only if all hosts succeeded.

---

## Prerequisites

- Python 3.11 or newer (stdlib only – no extra packages needed).
- Shelly Gen-2 or Gen-3 device with firmware that supports `Shelly.PutUserCA` / `Shelly.PutTLSClientCert` / `Shelly.PutTLSClientKey`.
- Network access from the machine running the script to the Shelly device(s) on port 80 (or the configured `--port`).

---

## CLI usage

```
python sync_shelly_certs.py --hosts <ip1>[,<ip2>,...] [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--hosts` | *(required)* | Comma-separated Shelly IPs or hostnames |
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

### Cron (every 12 hours, real run only if certs changed)

```cron
0 */12 * * * python /config/scripts/sync_shelly_certs.py \
  --hosts 192.168.1.50,192.168.1.51 \
  --cert-file /ssl/fullchain.pem \
  --key-file /ssl/privkey.pem >> /var/log/shelly_cert_sync.log 2>&1
```

### Home Assistant `shell_command` + automation

Add to `configuration.yaml`:

```yaml
shell_command:
  sync_shelly_certs: >
    python /config/scripts/sync_shelly_certs.py
    --hosts 192.168.1.50,192.168.1.51
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
- Firmware behaviour (accepted chunk size, CA format, `ssl_ca` config key) may vary between models and firmware versions. Test against a single device before deploying to many.
- Plain HTTP is used for the initial upload. If the device is already in SSL-only mode and you need to re-upload, temporarily disable SSL-only mode via the Shelly web UI first.

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
