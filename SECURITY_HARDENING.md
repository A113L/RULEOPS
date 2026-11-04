# RULEOPS Web Security Hardening

This build adds server-side resource controls and browser security headers. These controls reduce risk on a trusted LAN; they do not make the built-in HTTP server suitable for direct public-internet exposure. Use a VPN or a TLS reverse proxy and restrict firewall access.

## Built-in limits

Defaults can be overridden with environment variables before starting `start_gui.sh` / `start_gui.bat`:

| Variable | Default | Purpose |
|---|---:|---|
| `RULEOPS_MAX_CONNECTIONS` | `16` | Maximum concurrent HTTP handler threads; excess clients receive HTTP 503. |
| `RULEOPS_HEADER_TIMEOUT_SECONDS` | `15` | Absolute time allowed to complete request headers. |
| `RULEOPS_REQUEST_IDLE_TIMEOUT_SECONDS` | `10` | Idle read timeout for small request bodies and ordinary requests. |
| `RULEOPS_UPLOAD_IDLE_TIMEOUT_SECONDS` | `8` | Maximum idle period while streaming an upload. |
| `RULEOPS_UPLOAD_MIN_RATE_BYTES_PER_SECOND` | `8192` | Minimum sustained upload throughput after the grace period. |
| `RULEOPS_UPLOAD_RATE_GRACE_SECONDS` | `30` | Initial upload-rate grace period. |
| `RULEOPS_UPLOAD_RATE_CHECK_INTERVAL_SECONDS` | `15` | Interval for subsequent upload-rate checks. |
| `RULEOPS_MAX_UPLOAD_FILE_BYTES` | `20 GiB` | Maximum size of one uploaded file. |
| `RULEOPS_MAX_UPLOAD_TOTAL_BYTES` | `40 GiB` | Aggregate size of temporary uploads across all tools. |
| `RULEOPS_MAX_DATA_STORAGE_BYTES` | `200 GiB` | Aggregate `runs/` data quota, including temporary uploads and run outputs. |
| `RULEOPS_MIN_FREE_DISK_BYTES` | `1 GiB` | Free-space reserve; uploads/jobs are rejected or stopped before the reserve is consumed. |

Example for a machine with more storage and a trusted LAN:

```bash
export RULEOPS_MAX_CONNECTIONS=24
export RULEOPS_MAX_UPLOAD_FILE_BYTES=$((30 * 1024 * 1024 * 1024))
export RULEOPS_MAX_UPLOAD_TOTAL_BYTES=$((60 * 1024 * 1024 * 1024))
export RULEOPS_MAX_DATA_STORAGE_BYTES=$((300 * 1024 * 1024 * 1024))
export RULEOPS_MIN_FREE_DISK_BYTES=$((2 * 1024 * 1024 * 1024))
./start_gui.sh
```

Do not raise quotas without checking available disk space. The upload path reserves declared bytes before receiving the body, checks free disk space, enforces a per-file and aggregate quota, applies idle and sustained-rate limits, and removes incomplete uploads on failure.

## Connection and Slowloris protection

- The threaded HTTP server admits at most `RULEOPS_MAX_CONNECTIONS` clients at once.
- Excess connections are rejected with HTTP 503 and `Retry-After: 5`.
- Request headers have an absolute deadline, not only an idle timeout.
- Small JSON bodies have a total read deadline.
- Uploads have an idle timeout, a minimum sustained data rate, and a size-dependent maximum transfer duration.
- The server rejects `Transfer-Encoding` request bodies and duplicate `Content-Length` headers; uploads require one valid `Content-Length`.

## Storage protection

- Uploads are limited per file and globally across RULEST, Rule Ranker, and Concentrator.
- Aggregate application data under `runs/` is checked before uploads and job starts.
- During a run, a storage watchdog stops the child process if the aggregate data quota is exceeded or the configured free-disk reserve is breached.
- Temporary uploads and run outputs remain under `runs/`; `auth.json` is outside that tree and is not removed by cleanup.

## Browser security policy

The server sends a restrictive Content Security Policy and defense-in-depth headers on all normal responses, redirects, and errors. The login page's inline CSS and JavaScript were moved into same-origin static files. Script execution is restricted to same-origin resources. `style-src-attr 'unsafe-inline'` is narrowly retained because the existing UI uses dynamic inline width styles for live upload/phase progress bars; no inline scripts are permitted.

Other headers include `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy`. The Server header no longer discloses the Python version.

## Durable login throttling

Failed-login counters and lockout levels are stored in `security.sqlite3` beside the application, with owner-only file permissions on POSIX systems. The first lockout is five minutes; repeated lockouts use progressive backoff up to one hour. A successful login clears that client's failure record. The database and its WAL/SHM files are excluded by `.gitignore`; do not commit them.

## Operational notes

- Preserve `auth.json`, `security.sqlite3`, and `runs/` during upgrades. `security.sqlite3` preserves failed-login throttles across server restarts.
- `security.sqlite3` contains client IP metadata; keep it private and back it up only if you need to retain throttling state.
- The built-in server still uses plain HTTP. Do not port-forward port 8765. For remote access, use a private VPN or a TLS reverse proxy that is the only route to the application.
- No rate limiter or concurrency limit can guarantee availability against an attacker who can saturate the host network or operating system resources.
