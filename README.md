# RULEOPS — Hashcat Rule Toolchain

RULEOPS is a unified, dark Cleanlooks-inspired workbench for three complementary Hashcat ruleset tools: RULEST, Rule Ranker and Concentrator. RULEST generates rulesets; Rule Ranker scores candidate rules, optimizes existing rulesets with CELF, and analyzes ranking CSV files. All three tools share one authenticated UI, LAN server, live log, job monitor, output/download area and global run-storage manager.

## Requirements

- Python 3.9 or newer
- Dependencies from `requirements.txt` (`numpy`, `pyopencl`, `tqdm`, `msgpack`)
- A working OpenCL runtime and compatible GPU driver for GPU acceleration in RULEST, Ranker ranking, and Ranker CELF optimization (the CSV analysis workflow is CPU-only)

## Install and start

### Windows

1. Extract this ZIP.
2. Open the project folder.
3. Install dependencies once:

   ```bat
   python -m pip install -r requirements.txt
   ```

4. Double-click `start_gui.bat`.
5. The terminal displays the local URL and any detected LAN URL, for example `http://192.168.1.25:8765`.

### Linux / macOS

```bash
python3 -m pip install -r requirements.txt
chmod +x start_gui.sh
./start_gui.sh
```

The terminal prints the local URL and discovered private IPv4 LAN address(es).

On the first visit, open the local URL on the computer running RULEOPS and create your application password (minimum 12 characters). The first person to complete this one-time setup becomes the administrator. Once the password is set, other devices can sign in using the same password.

## Open from another device on the same network

1. Start the server on the computer running RULEOPS.
2. Keep that computer and the other device connected to the same trusted Wi-Fi/LAN.
3. Read the `LAN` address printed in the server terminal, such as `http://192.168.1.25:8765`.
4. Open that exact address in the other device's browser.

Do not use `127.0.0.1` from the other device; that address points back to the device itself. If Windows Firewall asks, allow Python on **Private networks** only. If the LAN address is unreachable, check that the computer and client are on the same subnet and that the firewall allows inbound TCP port `8765`.

## Password authentication and network security

The entire Control Center is password-protected, including its APIs, file uploads, run controls, GPU diagnostics, logs and downloads.

- On the first visit, create an application password (minimum 12 characters). There is no default password.
- The password is stored as a salted PBKDF2-HMAC-SHA256 verifier in `auth.json`; the plain-text password is never written to disk.
- Sign-in is rate-limited by client address. Five incorrect attempts trigger a five-minute lockout; repeated lockouts use progressive backoff up to one hour. Throttle state is persisted in `security.sqlite3` and survives server restarts.
- Sessions use HttpOnly, SameSite=Strict cookies, expire after 12 hours, and are cleared when the server restarts.
- The web server limits concurrent connections, enforces request/header timeouts, rejects slow uploads, and applies per-file, aggregate-upload and total application-data quotas.
- A Content Security Policy restricts scripts to same-origin assets; login CSS and JavaScript are served as separate static files. Additional browser security headers are applied globally.
- Use **Change password** in the top bar to update the password; other active sessions are revoked.
- Use **Log out** in the top bar to end the current browser session.
- Keep `auth.json` private and include it in your backups. Preserve `security.sqlite3` as well if you want failed-login throttling to survive an application upgrade. Both are ignored by Git.
- To reset the password manually, stop the server and remove `auth.json`; the next visit will show the first-time password setup screen. Complete first-time setup locally before exposing a fresh installation to the LAN.

The server binds to `0.0.0.0` by default so devices on the local network can connect. **Important:** this built-in server uses plain HTTP, so a password does not encrypt traffic on the network. Use it only on a trusted LAN, or place it behind a trusted VPN/TLS reverse proxy/SSH tunnel. Do not port-forward port `8765` or expose it directly to the public internet.

### Web resource limits and hardening

Default server limits are 16 concurrent connections, 20 GiB per upload, 40 GiB aggregate temporary uploads, 200 GiB total data under `runs/`, and a 1 GiB free-disk reserve. Uploads also have an 8-second idle timeout and a sustained minimum throughput check after a 30-second grace period. During engine execution, a watchdog stops the process if the data quota or free-space reserve is breached.

For larger trusted-LAN workloads, limits can be adjusted with environment variables such as `RULEOPS_MAX_CONNECTIONS`, `RULEOPS_MAX_UPLOAD_FILE_BYTES`, `RULEOPS_MAX_UPLOAD_TOTAL_BYTES`, `RULEOPS_MAX_DATA_STORAGE_BYTES`, and `RULEOPS_MIN_FREE_DISK_BYTES`. See [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md) for the full list and examples. Increase quotas only after checking free disk capacity.

## CELF selection performance

The exact-batched CELF path now reuses the per-candidate target-ID bitmap produced during exact scoring. After the greedy heap identifies a winner, the application reads only that winner's bitmap row to obtain its exact covered target IDs. This removes the redundant full base-word/GPU scoring pass that was previously launched once per selected rule solely to record hit slots. A mismatch between the exact gain and the decoded bitmap still triggers the safe batched-exact fallback path; the selected-rule coverage is not inferred from approximate bounds.

The CELF GPU profile reports `winner bitmap fetches`, transferred bitmap size and fetch time so the optimization can be evaluated on the actual GPU/driver combination. It also separates upper-bound, exact-count and winner-recording calls (including singleton counts), so a generic `singleton` total is no longer mistaken for one particular scoring mode.

The experimental work-group-local gain reduction was rolled back after its throughput did not improve reliably on the target workload. CELF is back on the previous one-dimensional word/candidate dispatch with per-hit global gain atomics; exact target deduplication still uses the per-candidate bitmap. This avoids the extra work-group barriers and local atomic operations. Benchmark this baseline against the experimental kernel on the actual GPU before considering another reduction strategy.

Small groups of exact challengers left over by successive upper-bound batches are coalesced before exact rescoring. The default minimum group size is `4`; the batch is still capped by the preallocated GPU workspace, and any remaining candidates are flushed when no more admissible heap bounds can win. Set `RULEST_CELF_EXACT_MICROBATCH=1` to disable this coalescing, or raise it cautiously to trade a few more upper-bound checks for fewer exact GPU launches. The greedy comparison, exact gains, winner bitmap validation and selected-rule ordering are unchanged.

Performance gains depend on the target count, base-word size, GPU and OpenCL implementation; benchmark with the same input set before and after updating. No hardware speedup is claimed without a run on the target GPU.

For this PC only, start with:

```bash
python app.py --host 127.0.0.1 --port 8765
```

To use another port:

```bash
python app.py --host 0.0.0.0 --port 9000
```

On Windows, the launch script respects `RULEST_HOST` if you want to override the default, e.g. set `RULEST_HOST=127.0.0.1` before launching.

## Repeatable runs (RNG seed)

The **RNG seed** field in Engine configuration is optional. Enter an integer from `0` to `4294967295` to pass it to the engine as `--seed`. Reusing the same seed with the same BASE/TARGET files and all other settings fixes the engine's Python and NumPy random generators and Python hash ordering, making randomized steps repeatable. Leaving the field blank preserves the default behaviour, which uses a different random sequence between runs.

For the strongest repeatability, use the same RULEST version, Python/NumPy versions, OpenCL device and driver, uploaded files, and every other run option. Rare differences can still arise from floating-point reduction order in GPU/OpenCL operations; a fixed seed cannot control nondeterminism inside a GPU driver or hardware scheduler.

## Using the interface

1. Upload BASE and TARGET wordlists in **Input files**. A custom seed-rules file is optional.
2. Configure engine, optional **RNG seed**, Stage 0, genetic algorithm, rule selection and diagnostic settings. Use **Enable Stage 0** and **Enable Genetic** to turn the optional stages on or off.
3. Click **Launch engine**. The phase card follows actual engine output; the live log is saved to `runs/<run-id>/engine.log`.
4. Use **Pause**, **Resume**, or **Save & stop** to control a running job at safe engine checkpoints.
5. During CELF selection, the live log emits a periodic non-TTY heartbeat with selected-rule count, measured `rules/s` (recent and average), target coverage, remaining heap size, rescoring counters, batch size and elapsed time—even when profiling is disabled. The default web heartbeat interval is 0.5 seconds; set `RULEST_CELF_LOG_INTERVAL` to a larger value to reduce log volume.
6. The sidebar **LOCAL ENGINE** badge switches to **RUNNING** while any RULEST, Rule Ranker or Concentrator job is active; it also displays PAUSED, STOPPING, COMPLETE, STOPPED or ERROR as appropriate.
7. Use the log wrap/expand controls and download generated outputs when the run ends.
8. Uploaded BASE, TARGET and optional seed files are temporary server-side copies. They are automatically deleted when a run completes, fails or is stopped. Leftover uploads from an unexpected server shutdown are removed the next time the server starts. Generated outputs and `engine.log` are preserved.

## Rule Ranker workflows

Monitor cards use a muted section label above a separately spaced title and readable status detail. The Rule Ranker mode selector offers **Adaptive MAB** and **Legacy exhaustive** at the top of the ranking workspace.

Use the persistent **RULEOPS sidebar** to open any of the three programs: expand **RULEST** for Run workspace, Engine tuning and GPU diagnostics, or select **Rule Ranker** and **Concentrator** directly. All three programs use the same application password, LAN address, live log, output area and single-job controller. Only one engine job can run at a time, which avoids unintended competition for GPU memory and compute.

Rule Ranker provides three workflows:

1. **Rank rules (GPU):** upload a base wordlist, cracked-password list and candidate Hashcat `.rule` file. At the top of the Rule Ranker page, choose **Adaptive MAB** for multi-pass bandit screening or **Legacy exhaustive** to evaluate the full candidate set with the original ranking strategy. The two large mode buttons are shown before the shared uploads and remember your last selection for the browser session. MAB-only tuning controls are disabled automatically in Legacy mode. The main output is a ranked CSV.
2. **Optimize ruleset (GPU coverage + CELF):** upload the base wordlist and cracked-password list, then select exactly one source: an existing `.rule` file or a ranking CSV. Configure the candidate limit, selection budget(s), GPU batch sizes, length limits and cost alpha. The output is a reduced coverage-focused `.rule` file. Uploading a `.rule` source automatically replaces a previously uploaded CSV source, and vice versa.
3. **Analyze CSV (CPU):** upload a ranking CSV to create a summary, clean rules file and/or scored CSV. This workflow does not require GPU acceleration.

All Ranker workflows stream their output into the shared **Live activity** panel and place generated files in the shared downloads list. Ranker supports cancellation (partial files already written are preserved); safe-checkpoint Pause/Resume is available only for the RULEST engine. Uploaded input files are temporary server-side copies and are removed after the job completes, fails or is cancelled. Re-upload wordlists and cracked-password lists before a subsequent Ranker workflow. Generated output files remain in `runs/<run-id>/`.

The Ranker command-line package is also available directly through `run_ranker.py`; its original CLI options remain available. See [`RANKER_README.md`](RANKER_README.md) for standalone CLI examples.

## GPU diagnostics

The panel checks OpenCL and reports the Python interpreter, PyOpenCL status, platforms and devices. If PyOpenCL is missing, install it into the same interpreter used by the app:

```bash
python -m pip install --upgrade pyopencl
```

Installing PyOpenCL does not install the GPU manufacturer's OpenCL driver/runtime. If no OpenCL platform or GPU appears, install or repair the official graphics driver and the manufacturer's OpenCL runtime, then restart and check again.

### Clear logs from the web interface

Open **Live activity** and click **Clear log history**. After confirmation, the Control Center clears the visible log history and truncates the current run's saved `engine.log`. New engine messages continue to stream normally. Generated ruleset files are not deleted. Other browser sessions connected to the same server also reset their displayed history automatically.


## Concentrator integration

The web Control Center includes the original `concentrator.py` processor as a third tool beside RULEST Engine and Rule Ranker. It exposes the source CLI's four processing workflows:

- **Extract** — frequency-ranked extraction or statistical (Markov-weighted) extraction.
- **Combinatorial** — valid token-chain generation with target and length bounds.
- **Markov** — Kneser–Ney training and best-first rule generation.
- **Process & clean** — minimum-occurrence, top-N, functional-minimization, inverse and Hashcat cleanup filters in the source-defined order.

All three tools share one authenticated web server, LAN listener, live log, output browser and upload-cleanup lifecycle. Only one job can use the engine at a time. Concentrator uses its original CLI through a non-interactive web mode; high-memory actions that need explicit approval are controlled by the **Confirm high-memory operations** switch. The standalone interactive CLI remains available by running `python concentrator.py` directly.

## Sidebar navigation and run storage

The sidebar is the primary application navigator. Select **RULEST** to expand its workspace, engine tuning and GPU diagnostics pages. Select **Rule Ranker** or **Concentrator** to open those tools. **Live activity** remains available as a shared monitor across all three programs. Under **System → Run storage**, review the number of saved run folders, files and disk usage. **Delete all run folders** removes saved RULEST, Ranker and Concentrator run directories after an explicit confirmation. It is blocked while a job is active or an upload is in progress. The cleanup deliberately preserves `runs/uploads/`, `auth.json`, application files and configuration; generated outputs, logs and partial results in run folders are permanently deleted. On narrow screens, the sidebar becomes a compact horizontal tool bar; the RULEST submenu opens as a dropdown.

## Offline licensing (DEMO / PROFESSIONAL / ENTERPRISE)

RULEOPS includes an offline Ed25519 license verifier.

**Without a valid `license.lic`:**
- Each module (RULEST, Rule Ranker, Concentrator) allows **3 full runs** independently.
- After the third full run of a module, that module enters **DEMO LIMITED**.
- In DEMO LIMITED, advanced CELF features are strongly restricted (no greedy/advanced CELF; tight candidate/budget caps). A basic demonstration path remains available.
- Counters are stored in `license_usage.sqlite3`, survive restarts and re-logins, and are independent per module.

**With a signed PROFESSIONAL or ENTERPRISE `license.lic`:** all modules and CELF features are fully unlocked.

Install the issuer's `licensing/public_key.pem` and the customer's signed `license.lic` in the RULEOPS installation root (or use the administrator **Install license** API). The private signing key must NEVER be copied to a customer installation.

**Roles:** the first password created during setup is the **administrator** (full access + license management). The administrator can optionally set a separate regular **user** password with module access but without license administration.

Install the added dependency with `python3 -m pip install -r requirements.txt`.
