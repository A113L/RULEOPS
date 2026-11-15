# Run RULEOPS with systemd (Linux)

This guide installs RULEOPS as a system-wide systemd service. The service starts at boot, runs under the normal Linux account that owns the project, writes logs to the system journal, and restarts after an unexpected failure.

The repository contains the matching unit template at [`ruleops.service`](../ruleops.service). It has three placeholders that must be rendered for the local machine before it is installed. Do not copy the unrendered template directly into `/etc/systemd/system/`.

## 1. Requirements

- A Linux distribution using systemd (for example Ubuntu or Debian).
- A working Python 3 installation and a project-local virtual environment at `.venv/`.
- The RULEOPS Python dependencies installed from `requirements.txt`.
- A compatible OpenCL driver/runtime for GPU features. The systemd service uses the same Linux account as the interactive setup, so that account must be able to access the GPU device and OpenCL runtime.

On Ubuntu/Debian, the following packages provide the common Python and OpenCL build/runtime interfaces:

```bash
sudo apt update
sudo apt install -y \
  python3 python3-venv python3-dev build-essential \
  ocl-icd-libopencl1 ocl-icd-opencl-dev opencl-headers clinfo
```

These packages do not replace the GPU manufacturer's driver or OpenCL implementation. Install the correct driver/runtime for the machine's GPU separately.

## 2. Prepare the project environment

Run these commands as the normal Linux account that should own and run RULEOPS. Do not create the virtual environment or run the service as root.

```bash
cd ~/BUCKET/RULEOPS
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -r requirements.txt
```

Check the Python dependencies:

```bash
.venv/bin/python -c "import numpy, pyopencl, tqdm, msgpack; print('RULEOPS dependencies OK')"
```

Check that the same account can see an OpenCL platform and device:

```bash
clinfo -l
.venv/bin/python -c "import pyopencl as cl; print([(p.name, [d.name for d in p.get_devices()]) for p in cl.get_platforms()])"
```

The second command should list the available OpenCL platform(s) and device(s). If it fails, fix the driver/runtime or device permissions before relying on GPU-backed RULEOPS operations.

Before installing systemd, verify that RULEOPS starts manually:

```bash
.venv/bin/python app.py --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`, verify the login/setup page, then stop the foreground process with `Ctrl+C`. Make sure port `8765` is not already occupied before starting the service:

```bash
ss -ltnp | grep ':8765' || true
```

## 3. Render and install `ruleops.service`

From the RULEOPS project root, still as the intended service account:

```bash
cd ~/BUCKET/RULEOPS

APP_DIR="$(pwd -P)"
SERVICE_USER="$(id -un)"
SERVICE_GROUP="$(id -gn)"

# Escape characters that have special meaning in sed replacements and
# escape '%' for systemd unit-file specifier parsing.
escape_replacement() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g' -e 's/%/%%/g'
}

sed \
  -e "s|@RULEOPS_USER@|$(escape_replacement "$SERVICE_USER")|g" \
  -e "s|@RULEOPS_GROUP@|$(escape_replacement "$SERVICE_GROUP")|g" \
  -e "s|@RULEOPS_DIR@|$(escape_replacement "$APP_DIR")|g" \
  ruleops.service | sudo tee /etc/systemd/system/ruleops.service >/dev/null

sudo chmod 0644 /etc/systemd/system/ruleops.service
```

This generates a machine-specific service using the current absolute project path, user and primary group. The project remains in its current location; it does not need to be moved to `/opt`.

Validate the installed unit and enable it:

```bash
sudo systemd-analyze verify /etc/systemd/system/ruleops.service
sudo systemctl daemon-reload
sudo systemctl enable --now ruleops.service
```

Check that it started:

```bash
sudo systemctl status ruleops.service
```

The expected state is `Active: active (running)`.

## 4. Network access and first-time password setup

The unit follows RULEOPS's normal LAN-accessible startup configuration and binds to `0.0.0.0:8765`. On the first visit, create the application password (minimum 12 characters). The first person to complete this setup becomes the administrator. Complete this setup promptly and only on a trusted network.

Open the service from the server itself at:

```text
http://127.0.0.1:8765
```

To find the server's LAN address:

```bash
hostname -I
```

Then open `http://SERVER_LAN_IP:8765` from another device on the same trusted network.

**Network security:** RULEOPS's built-in server uses HTTP, not HTTPS. A password does not encrypt network traffic. Restrict access to a trusted LAN, VPN, or a properly configured TLS reverse proxy. Do not port-forward port `8765` or expose this development server directly to the public internet. Configure the host firewall to allow TCP `8765` only from the trusted client subnet. For example, replace the subnet below with the actual LAN subnet before running it:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8765 proto tcp
```

To make RULEOPS listen only on the local machine, change `--host 0.0.0.0` to `--host 127.0.0.1` in the repository's `ruleops.service`, repeat the render/install commands in section 3, then run `sudo systemctl daemon-reload` and `sudo systemctl restart ruleops`.

## 5. Service management

```bash
sudo systemctl start ruleops       # Start
sudo systemctl stop ruleops        # Stop
sudo systemctl restart ruleops     # Restart
sudo systemctl status ruleops      # Status
sudo systemctl enable ruleops      # Start automatically at boot
sudo systemctl disable ruleops     # Disable automatic startup
```

Follow live logs:

```bash
sudo journalctl -u ruleops.service -f
```

Show the latest 100 log lines:

```bash
sudo journalctl -u ruleops.service -n 100 --no-pager
```

The unit uses `KillSignal=SIGINT` and `KillMode=mixed` intentionally. RULEOPS handles Ctrl+C by asking an active engine job to stop, waiting for its shutdown path, closing the HTTP server and cleaning temporary uploads. `TimeoutStopSec=45` gives that shutdown path time to complete before systemd forcefully terminates any remaining processes.

## 6. Updating RULEOPS

After pulling a new version of the repository, update the virtual environment and restart the service:

```bash
cd ~/BUCKET/RULEOPS
git pull --ff-only
.venv/bin/python -m pip install -r requirements.txt
sudo systemctl restart ruleops.service
sudo systemctl status ruleops.service
```

If the project directory is moved, re-render and reinstall the unit using section 3 so `WorkingDirectory` and `ExecStart` point to the new absolute path.

## 7. Troubleshooting

### The service fails immediately

Inspect its status and logs:

```bash
sudo systemctl status ruleops.service --no-pager
sudo journalctl -u ruleops.service -n 150 --no-pager
```

Confirm that the path in `WorkingDirectory` exists and that `ExecStart` points to the project's `.venv/bin/python` and `app.py`.

### Port 8765 is already in use

```bash
sudo ss -ltnp | grep ':8765'
```

Stop the other process or change the port in `ruleops.service`, then render/install the unit again and reload systemd.

### The web interface works but GPU operations cannot find OpenCL

Run `clinfo -l` and the PyOpenCL test in section 2 as the same Linux account configured in `User=`. If the interactive account can see the GPU but the service cannot, check the device permissions and the account's supplementary groups (commonly `render` and/or `video`, depending on the driver). After changing group membership, start a new login session and restart the service.

### RULEOPS cannot write run outputs or its security files

The service runs as the account shown in `User=`. That account needs write permission to the project directory and its `runs/` directory, because `auth.json`, `security.sqlite3`, uploaded inputs and generated run files are stored there. Inspect ownership and permissions rather than running RULEOPS as root or applying an indiscriminate recursive ownership change.

## 8. Persistent application data

The service does not move or reset RULEOPS data. By default, RULEOPS enforces a **10 GiB aggregate data quota** across run outputs, reusable library files and temporary uploads. This application quota is separate from physical filesystem capacity and can be overridden with `RULEOPS_MAX_DATA_STORAGE_BYTES` when the available disk space and retention policy justify it. Storage Intelligence displays both measurements separately.

To override the quota for this systemd service, create a service drop-in (replace the value only after checking free disk capacity):

```bash
sudo systemctl edit ruleops.service
```

Add, for example, the following under `[Service]` to set a different quota of 15 GiB:

```ini
[Service]
Environment=RULEOPS_MAX_DATA_STORAGE_BYTES=16106127360
```

Then apply the change:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ruleops.service
```

Keep these items when updating the code:

- `auth.json` — application password verifier.
- `security.sqlite3` — persistent login-throttling state.
- `runs/` — uploads, reusable library files and generated run outputs.

Back them up according to your normal data-retention policy. Do not commit credentials, the security database or run data to Git.
