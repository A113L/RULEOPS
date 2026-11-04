#!/usr/bin/env python3
"""RULEOPS: unified local web interface for RULEST, Rule Ranker and Concentrator."""
from __future__ import annotations

import json
import os
import codecs
import re
import sys
import time
import uuid
import shutil
import signal
import threading
import subprocess
import urllib.parse
import ipaddress
import socket
import math
import secrets
import hashlib
import hmac
import base64
import sqlite3
from contextlib import contextmanager
from http.cookies import SimpleCookie
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gpu_diagnostics import collect_gpu_diagnostics
from licensing.core import (
    DEMO_LIMIT,
    apply_celf_limits,
    can_start_full_run,
    celf_restrictions,
    is_fully_licensed,
    license_summary,
    module_mode,
    record_module_run,
)

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DATA = ROOT / "runs"
UPLOADS = DATA / "uploads"
AUTH_FILE = ROOT / "auth.json"
DATA.mkdir(exist_ok=True)
UPLOADS.mkdir(exist_ok=True)

# Passwords are never stored in clear text. Sessions live in memory, so a server
# restart automatically signs out every browser.
PASSWORD_ITERATIONS = 600_000
SESSION_TTL_SECONDS = 12 * 60 * 60
PASSWORD_MIN_LENGTH = 12
LOGIN_WINDOW_SECONDS = 5 * 60
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 5 * 60
SESSIONS = {}       # token -> {csrf, expires}
LOGIN_FAILURES = {}  # Deprecated in-memory compatibility mirror; SQLite is authoritative.
SECURITY_DB = ROOT / "security.sqlite3"
LOGIN_MAX_LOCK_SECONDS = 60 * 60

LOCK = threading.RLock()
STATE = {
    "status": "idle", "tool": "rulest", "paused": False, "pause_requested": False, "job_id": None, "started_at": None, "finished_at": None,
    "pid": None, "stage": "Waiting for a run", "stage_detail": "Start a run to see the active processing phase.",
    "stage_started_at": None, "progress": None,
    "exit_code": None, "logs": [], "log_seq": 0, "log_generation": 0, "outputs": [],
    "error": None, "control_file": None, "run_dir": None,
}
UPLOADS_META = {
    "base": None, "target": None, "seed": None,
    "ranker_wordlist": None, "ranker_cracked": None, "ranker_rules": None,
    "ranker_source_csv": None, "ranker_source_rules": None, "ranker_analysis_csv": None,
    "concentrator_files": [],
}
RANKER_UPLOAD_FIELDS = {
    "ranker_wordlist", "ranker_cracked", "ranker_rules",
    "ranker_source_csv", "ranker_source_rules", "ranker_analysis_csv",
}
CONCENTRATOR_UPLOAD_FIELDS = {"concentrator_files"}
MAX_CONCENTRATOR_FILES = 32
MAX_CONCENTRATOR_TOTAL_BYTES = 40 * 1024 * 1024 * 1024
UPLOADS_ACTIVE = set()
UPLOAD_RESERVATIONS = {}  # field -> declared bytes, reserved before reading body
PROCESS = None
RUN_THREAD = None


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    """Read a bounded positive integer setting without crashing on bad env values."""
    try:
        value = int(os.environ.get(name, str(default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


# Defaults intentionally support large password wordlists while placing aggregate
# bounds around the server's temporary and persistent data directories.
MAX_UPLOAD_BYTES = _env_int("RULEOPS_MAX_UPLOAD_FILE_BYTES", 20 * 1024**3)
MAX_TOTAL_UPLOAD_BYTES = _env_int("RULEOPS_MAX_UPLOAD_TOTAL_BYTES", 40 * 1024**3)
MAX_DATA_STORAGE_BYTES = _env_int("RULEOPS_MAX_DATA_STORAGE_BYTES", 200 * 1024**3)
MIN_FREE_DISK_BYTES = _env_int("RULEOPS_MIN_FREE_DISK_BYTES", 1 * 1024**3, minimum=0)
MAX_CONCURRENT_CONNECTIONS = min(64, _env_int("RULEOPS_MAX_CONNECTIONS", 16, minimum=2))
HEADER_TIMEOUT_SECONDS = _env_int("RULEOPS_HEADER_TIMEOUT_SECONDS", 15)
REQUEST_IDLE_TIMEOUT_SECONDS = _env_int("RULEOPS_REQUEST_IDLE_TIMEOUT_SECONDS", 10)
UPLOAD_IDLE_TIMEOUT_SECONDS = _env_int("RULEOPS_UPLOAD_IDLE_TIMEOUT_SECONDS", 8)
UPLOAD_MIN_RATE_BYTES_PER_SECOND = _env_int("RULEOPS_UPLOAD_MIN_RATE_BYTES_PER_SECOND", 8 * 1024)
UPLOAD_RATE_GRACE_SECONDS = _env_int("RULEOPS_UPLOAD_RATE_GRACE_SECONDS", 30)
UPLOAD_RATE_CHECK_INTERVAL_SECONDS = _env_int("RULEOPS_UPLOAD_RATE_CHECK_INTERVAL_SECONDS", 15)
UPLOAD_CHUNK_BYTES = 64 * 1024
STORAGE_WATCH_INTERVAL_SECONDS = 5

BOOL_OPTIONS = {
    "bloom_no_shard": "--bloom-no-shard",
    "allow_reject_rules": "--allow-reject-rules",
    "no_builtin_seeds": "--no-builtin-seeds",
    "token_strip": "--token-strip",
    "genetic": "--genetic",
    "exact_recovery": "--exact-recovery",
    "debug": "--debug",
    "profile": "--profile",
}
VALUE_OPTIONS = {
    "device": "--device", "max_depth": "--max-depth", "target_hours": "--target-hours",
    "max_chains": "--max-chains", "bloom_mb": "--bloom-mb",
    "token_strip_min_stem": "--token-strip-min-stem",
    "token_strip_max_prefix": "--token-strip-max-prefix",
    "token_strip_max_suffix": "--token-strip-max-suffix",
    "token_strip_min_leet_amb": "--token-strip-min-leet-amb",
    "token_strip_workers": "--token-strip-workers",
    "token_strip_chunk_size": "--token-strip-chunk-size",
    "token_strip_bloom_mb": "--token-strip-bloom-mb",
    "genetic_generations": "--genetic-generations", "genetic_pop": "--genetic-pop",
    "genetic_elite": "--genetic-elite", "select_mode": "--select-mode",
    "select_budget": "--select-budget", "select_budgets": "--select-budgets",
    "select_cost_alpha": "--select-cost-alpha",
}


def auth_configured() -> bool:
    return AUTH_FILE.is_file()


def _derive_password_hash(password: str, salt: bytes, iterations: int = PASSWORD_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def make_password_record(password: str) -> dict:
    salt = secrets.token_bytes(32)
    digest = _derive_password_hash(password, salt)
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": PASSWORD_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(digest).decode("ascii"),
        "created_at": int(time.time()),
    }


def save_password_record(record: dict):
    """Atomically persist the password verifier with owner-only file permissions."""
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = AUTH_FILE.with_name(AUTH_FILE.name + ".tmp")
    payload = json.dumps(record, indent=2) + "\n"
    # Create the temporary verifier with owner-only permissions from the outset.
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass  # Windows ACLs govern access there; the file still stores only a hash.
    temporary.replace(AUTH_FILE)
    try:
        os.chmod(AUTH_FILE, 0o600)
    except OSError:
        pass


def load_password_record() -> dict:
    """Load auth.json. Supports legacy flat admin record and role-based {admin,user}."""
    try:
        record = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError("No application password has been configured yet.")
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"The authentication file is invalid: {exc}") from exc
    # Legacy flat format -> treat as admin
    if record.get("algorithm") == "pbkdf2_sha256" and "admin" not in record:
        return {"admin": record, "user": None, "version": 1}
    if "admin" in record and isinstance(record["admin"], dict):
        if record["admin"].get("algorithm") != "pbkdf2_sha256":
            raise ValueError("Unsupported password hash algorithm in auth.json.")
        return record
    raise ValueError("Unsupported auth.json structure.")


def _verify_against_record(password: str, record: dict) -> bool:
    if not isinstance(record, dict):
        return False
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["password_hash"], validate=True)
        iterations = int(record["iterations"])
        if iterations < 100_000 or iterations > 2_000_000 or len(salt) < 16 or len(expected) != 32:
            return False
        actual = _derive_password_hash(password, salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, KeyError, TypeError, base64.binascii.Error):
        return False


def verify_password(password: str) -> bool:
    """True if password matches admin or user."""
    return verify_password_role(password) is not None


def verify_password_role(password: str):
    """Return 'admin' or 'user' if password matches, else None."""
    if not isinstance(password, str) or len(password) > 1024 or not auth_configured():
        return None
    try:
        store = load_password_record()
    except ValueError:
        return None
    admin_rec = store.get("admin") if isinstance(store, dict) else None
    if _verify_against_record(password, admin_rec):
        return "admin"
    user_rec = store.get("user") if isinstance(store, dict) else None
    if user_rec and _verify_against_record(password, user_rec):
        return "user"
    return None


def save_admin_password(password: str):
    """Create or replace the administrator password (first-time setup or admin change)."""
    store = {"admin": make_password_record(password), "user": None, "version": 1}
    if auth_configured():
        try:
            existing = load_password_record()
            store["user"] = existing.get("user")
        except ValueError:
            pass
    save_password_record(store)


def save_user_password(password: str | None):
    """Admin sets or clears the regular user password."""
    store = load_password_record()
    if password is None or password == "":
        store["user"] = None
    else:
        store["user"] = make_password_record(password)
    store["version"] = 1
    save_password_record(store)


def _cookie_token(handler) -> str | None:
    try:
        cookie = SimpleCookie()
        cookie.load(handler.headers.get("Cookie", ""))
        morsel = cookie.get("rulest_session")
        return morsel.value if morsel else None
    except Exception:
        return None


def get_session(handler):
    token = _cookie_token(handler)
    if not token:
        return None
    now = time.time()
    with LOCK:
        for key in [key for key, value in SESSIONS.items() if value.get("expires", 0) <= now]:
            SESSIONS.pop(key, None)
        session = SESSIONS.get(token)
        if session and session.get("expires", 0) > now:
            return token, session
    return None


def create_session(handler, role: str = "admin"):
    """Create an authenticated session. role is 'admin' or 'user'."""
    if role not in ("admin", "user"):
        role = "user"
    token = secrets.token_urlsafe(36)
    csrf_token = secrets.token_urlsafe(32)
    with LOCK:
        SESSIONS[token] = {
            "csrf": csrf_token,
            "expires": time.time() + SESSION_TTL_SECONDS,
            "role": role,
        }
    # Queue the cookie until send_response() has emitted the HTTP status line.
    handler._auth_set_cookie = (
        f"rulest_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECONDS}"
    )
    return csrf_token


def session_role(session) -> str:
    """Return role from a get_session() result tuple (token, data).

    Missing role defaults to admin for backward compatibility with sessions
    created before role support and with single-password installations.
    """
    if not session:
        return "user"
    role = session[1].get("role")
    if role in ("admin", "user"):
        return role
    return "admin"


def require_admin(handler, api: bool = True) -> bool:
    session = get_session(handler)
    if not session:
        if api:
            handler.send_json({"error": "Authentication required. Please sign in again.", "auth_required": True}, 401)
        return False
    if session_role(session) != "admin":
        handler.send_json({"error": "Administrator privileges required.", "admin_required": True}, 403)
        return False
    return True


def clear_session_cookie(handler):
    handler.send_header(
        "Set-Cookie",
        "rulest_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
    )


def request_ip(handler) -> str:
    try:
        return str(handler.client_address[0])
    except Exception:
        return "unknown"


def _security_db_connection():
    """Open the owner-only SQLite database used for durable login throttling."""
    path = Path(SECURITY_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(descriptor)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    connection = sqlite3.connect(str(path), timeout=3.0)
    connection.execute("PRAGMA busy_timeout = 3000")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS login_throttle (
            client_ip TEXT PRIMARY KEY,
            failures INTEGER NOT NULL DEFAULT 0,
            window_started REAL NOT NULL,
            locked_until REAL NOT NULL DEFAULT 0,
            lock_level INTEGER NOT NULL DEFAULT 0,
            updated_at REAL NOT NULL
        )
    """)
    return connection


@contextmanager
def security_db_session():
    connection = _security_db_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def login_lock_remaining(client_ip: str) -> int:
    """Return durable lock time for an IP; expired windows reset, lock history remains."""
    now = time.time()
    with LOCK:
        try:
            with security_db_session() as connection:
                row = connection.execute(
                    "SELECT failures, window_started, locked_until FROM login_throttle WHERE client_ip = ?",
                    (client_ip,),
                ).fetchone()
                if not row:
                    return 0
                failures, window_started, locked_until = row
                if locked_until > now:
                    return max(1, int(locked_until - now + 0.999))
                if locked_until:
                    connection.execute(
                        "UPDATE login_throttle SET failures = 0, window_started = ?, locked_until = 0, updated_at = ? WHERE client_ip = ?",
                        (now, now, client_ip),
                    )
                    return 0
                if now - window_started > LOGIN_WINDOW_SECONDS:
                    connection.execute(
                        "UPDATE login_throttle SET failures = 0, window_started = ?, updated_at = ? WHERE client_ip = ?",
                        (now, now, client_ip),
                    )
                return 0
        except sqlite3.Error:
            # Fail closed briefly if the durable limiter cannot be read.
            return LOGIN_LOCK_SECONDS


def record_login_failure(client_ip: str):
    now = time.time()
    with LOCK:
        try:
            with security_db_session() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT failures, window_started, locked_until, lock_level FROM login_throttle WHERE client_ip = ?",
                    (client_ip,),
                ).fetchone()
                if row:
                    failures, window_started, locked_until, lock_level = row
                    if locked_until > now:
                        connection.commit()
                        return
                    if locked_until or now - window_started > LOGIN_WINDOW_SECONDS:
                        failures = 0
                        window_started = now
                else:
                    failures, window_started, locked_until, lock_level = 0, now, 0, 0
                failures += 1
                new_locked_until = 0
                if failures >= LOGIN_MAX_FAILURES:
                    lock_level = min(int(lock_level) + 1, 5)
                    delay = min(LOGIN_LOCK_SECONDS * (2 ** (lock_level - 1)), LOGIN_MAX_LOCK_SECONDS)
                    new_locked_until = now + delay
                connection.execute("DELETE FROM login_throttle WHERE updated_at < ?", (now - 90 * 24 * 60 * 60,))
                connection.execute(
                    """INSERT INTO login_throttle
                       (client_ip, failures, window_started, locked_until, lock_level, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(client_ip) DO UPDATE SET
                         failures=excluded.failures,
                         window_started=excluded.window_started,
                         locked_until=excluded.locked_until,
                         lock_level=excluded.lock_level,
                         updated_at=excluded.updated_at""",
                    (client_ip, failures, window_started, new_locked_until, lock_level, now),
                )
                connection.commit()
                LOGIN_FAILURES[client_ip] = {
                    "count": failures, "first": window_started,
                    "locked_until": new_locked_until, "lock_level": lock_level,
                }
        except sqlite3.Error:
            # Keep a process-local fallback if SQLite is temporarily unavailable.
            item = LOGIN_FAILURES.setdefault(client_ip, {"count": 0, "first": now, "locked_until": 0})
            if now - item.get("first", now) > LOGIN_WINDOW_SECONDS:
                item.update(count=0, first=now, locked_until=0)
            item["count"] += 1
            if item["count"] >= LOGIN_MAX_FAILURES:
                item["locked_until"] = now + LOGIN_LOCK_SECONDS


def reset_login_failures(client_ip: str):
    with LOCK:
        LOGIN_FAILURES.pop(client_ip, None)
        try:
            with security_db_session() as connection:
                connection.execute("DELETE FROM login_throttle WHERE client_ip = ?", (client_ip,))
        except sqlite3.Error:
            pass


def safe_name(value: str, fallback="output.txt") -> str:
    value = Path(str(value or fallback)).name
    value = re.sub(r"[^A-Za-z0-9._ -]+", "_", value).strip(" .")
    return value or fallback


def cleanup_uploaded_files(log_message: bool = True):
    """Delete server-side copies of uploaded inputs and clear their metadata.

    Run output files live under runs/<run-id>/ and are deliberately untouched.
    The caller must only invoke this when no upload request is in progress.
    """
    removed = []
    with LOCK:
        if UPLOADS_ACTIVE:
            return removed
        for field in UPLOADS_META:
            UPLOADS_META[field] = [] if field == "concentrator_files" else None
        try:
            for candidate in UPLOADS.iterdir():
                # Uploaded files are always direct children of runs/uploads.
                # Unlink symlinks themselves; never follow them.
                if candidate.is_file() or candidate.is_symlink():
                    try:
                        candidate.unlink()
                        removed.append(candidate.name)
                    except OSError:
                        pass
        except FileNotFoundError:
            UPLOADS.mkdir(parents=True, exist_ok=True)
    if removed and log_message:
        add_log(f"[WEB] Deleted {len(removed)} temporary uploaded input file(s).")
    return removed


def cleanup_stale_uploaded_files():
    """Remove upload leftovers from a previous unclean server shutdown."""
    return cleanup_uploaded_files(log_message=False)


def _iter_run_directories():
    """Yield direct child run directories, never following symlinks or uploads/."""
    if not DATA.exists():
        return
    try:
        entries = sorted(DATA.iterdir(), key=lambda item: item.name.lower())
    except OSError:
        return
    for entry in entries:
        if entry.name == UPLOADS.name:
            continue
        try:
            if entry.is_symlink():
                # A symlink is not a run directory. Do not traverse or delete it.
                continue
            if entry.is_dir():
                yield entry
        except OSError:
            continue


def _directory_usage(path: Path) -> tuple[int, int]:
    """Return (regular file count, bytes) without following symlinks."""
    file_count = 0
    total_bytes = 0
    for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(root) / name).is_symlink()]
        for name in files:
            candidate = Path(root) / name
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                stat = candidate.lstat()
                file_count += 1
                total_bytes += stat.st_size
            except OSError:
                continue
    return file_count, total_bytes


def data_storage_usage_bytes() -> int:
    """Return total regular-file bytes under runs/, excluding symlink targets."""
    return _directory_usage(DATA)[1]


def storage_preflight(additional_bytes: int = 0) -> tuple[bool, str, int]:
    """Check aggregate app-data quota and preserve a minimum free-disk reserve."""
    try:
        used = data_storage_usage_bytes()
        free = shutil.disk_usage(DATA).free
    except OSError as exc:
        return False, f"Storage status could not be checked: {exc}", 0
    if used + max(0, additional_bytes) > MAX_DATA_STORAGE_BYTES:
        return False, (
            f"RULEOPS storage quota would be exceeded ({used + additional_bytes:,} / "
            f"{MAX_DATA_STORAGE_BYTES:,} bytes). Clear old run folders or increase "
            "RULEOPS_MAX_DATA_STORAGE_BYTES."
        ), used
    if free - max(0, additional_bytes) < MIN_FREE_DISK_BYTES:
        return False, (
            f"Insufficient free disk space. RULEOPS reserves {MIN_FREE_DISK_BYTES:,} bytes "
            "for the operating system and active jobs."
        ), used
    return True, "", used


def run_storage_summary() -> dict:
    """Summarize persisted run folders; uploads/ is excluded by design."""
    with LOCK:
        directories = list(_iter_run_directories())
        file_count = 0
        total_bytes = 0
        for directory in directories:
            count, size = _directory_usage(directory)
            file_count += count
            total_bytes += size
        return {
            "run_directories": len(directories),
            "files": file_count,
            "bytes": total_bytes,
            "active": STATE.get("status") in ("running", "stopping"),
            "uploads_preserved": True,
        }


def clear_run_directories() -> dict:
    """Delete all persisted run directories, preserving uploads/ and app config.

    This operation is rejected while any engine job or upload is active. It only
    removes direct, non-symlink directories under DATA and never follows links.
    """
    with LOCK:
        if STATE.get("status") in ("running", "stopping"):
            raise RuntimeError("Run folders cannot be deleted while a job is running or stopping.")
        if UPLOADS_ACTIVE:
            raise RuntimeError("Wait for active uploads to finish before deleting run folders.")

        current_run_dir = Path(STATE["run_dir"]) if STATE.get("run_dir") else None
        removed = 0
        failures = []
        for directory in list(_iter_run_directories()):
            try:
                shutil.rmtree(directory)
                removed += 1
            except OSError as exc:
                failures.append(f"{directory.name}: {exc}")

        # Drop references to deleted outputs so the UI cannot offer dead links.
        if current_run_dir is not None:
            try:
                if current_run_dir.parent.resolve() == DATA.resolve() and not current_run_dir.exists():
                    STATE["run_dir"] = None
                    STATE["outputs"] = []
            except OSError:
                STATE["run_dir"] = None
                STATE["outputs"] = []

        result = run_storage_summary_unlocked()
        result.update({"deleted_directories": removed, "failures": failures})

    add_log(f"[WEB] Run storage cleanup removed {removed} run director{'y' if removed == 1 else 'ies'}.")
    return result


def run_storage_summary_unlocked() -> dict:
    """Internal summary helper for callers already holding LOCK (RLock-safe)."""
    directories = list(_iter_run_directories())
    file_count = 0
    total_bytes = 0
    for directory in directories:
        count, size = _directory_usage(directory)
        file_count += count
        total_bytes += size
    return {
        "run_directories": len(directories),
        "files": file_count,
        "bytes": total_bytes,
        "active": STATE.get("status") in ("running", "stopping"),
        "uploads_preserved": True,
    }


ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\)|[@-Z\\-_])"
)
PROGRESS_PERCENT_RE = re.compile(r"(?<!\d)(\d{1,3})%\s*\|")
PROGRESS_COUNT_RE = re.compile(r"\|\s*([\d,]+)\s*/\s*([\d,]+)\s*\[")


def engine_badge_for_status(status: str, paused: bool = False) -> dict:
    """Return the sidebar engine badge state from the authoritative job state."""
    if status == "stopping":
        return {"label": "STOPPING", "state": "stopping"}
    if status == "running" and paused:
        return {"label": "PAUSED", "state": "paused"}
    if status == "running":
        return {"label": "RUNNING", "state": "running"}
    if status == "completed":
        return {"label": "COMPLETE", "state": "complete"}
    if status == "stopped":
        return {"label": "STOPPED", "state": "stopped"}
    if status == "failed":
        return {"label": "ERROR", "state": "error"}
    if status == "offline":
        return {"label": "OFFLINE", "state": "offline"}
    return {"label": "READY", "state": "ready"}


def clean_terminal_text(line: str) -> str:
    """Remove terminal control sequences without dropping printable log text."""
    clean = ANSI_ESCAPE_RE.sub("", str(line))
    clean = clean.replace("\x08", "")
    clean = "".join(ch for ch in clean if ch in "\t" or ord(ch) >= 32)
    return clean.strip()


def detect_active_stage(line: str):
    """Return a phase only for real activity markers, never startup option summaries."""
    text = clean_terminal_text(line)
    upper = text.upper()
    # CLI prints a configuration overview near startup. Those lines say
    # `STAGE N : enabled/disabled` and must not masquerade as active phases.
    if re.search(r"\bSTAGE\s*[0-3S]\s*:\s*(?:ENABLED|DISABLED)\b", upper):
        return None

    # Section headings are emitted exactly when a phase starts. Progress bars
    # also contain the stage name and a percentage marker.
    if "DONE" in upper and "RULEST FINISHED" in upper:
        return "Completed"
    if "POST-PROCESSING" in upper or "[MINIMIZE]" in upper or "[MIN]" in upper or "MINIMIZING" in upper:
        return "Minimization"
    if "SELECTION — CELF" in upper or "SELECTION - CELF" in upper or "[CELF]" in upper or "[SELECT]" in upper:
        return "Rule Selection · CELF"
    if "BLOOM FILTER" in upper or "BUILDING BLOOM" in upper:
        return "GPU Setup · Bloom Filter"
    if re.search(r"\bSTAGE\s*0\b", upper) or "[S0]" in upper:
        if "STAGE 0" in upper or "[S0]" in upper:
            return "Stage 0 · Token Strip"
    if re.search(r"\bSTAGE\s*S\b", upper) or "[SEED]" in upper:
        return "Stage S · Built-in Seeds"
    if re.search(r"\bSTAGE\s*1\b", upper) or "[S1]" in upper:
        return "Stage 1 · Single-rule GPU sweep"
    if re.search(r"\bSTAGE\s*2\b", upper) or "[S2]" in upper:
        return "Stage 2 · Rule-chain search"
    if re.search(r"\bSTAGE\s*3\b", upper) or "[S3]" in upper:
        return "Stage 3 · Genetic Algorithm"
    if "[OUT]" in upper:
        return "Writing output"
    if "CONCENTRATOR" in upper and "PROCESSING MODE" in upper:
        return "Concentrator · Processing"
    if "RULE EXTRACTION AND VALIDATION" in upper or "EXTRACTED" in upper:
        return "Concentrator · Rule extraction"
    if "COMBINATORIAL RULE GENERATION" in upper or "GENERATED" in upper and "COMBINATORIAL" in upper:
        return "Concentrator · Combinatorial generation"
    if "MARKOV RULE GENERATION" in upper or "BUILDING KN-SMOOTHED" in upper:
        return "Concentrator · Markov generation"
    if "PROCESSING MODE" in upper and "RULE MINIMIZATION" in upper:
        return "Concentrator · Ruleset processing"
    if "FUNCTIONAL MINIMIZATION" in upper or "SIG (SQLITE)" in upper:
        return "Concentrator · Functional minimization"
    if "HASHCAT CLEANUP" in upper or "HASHCAT RULE CLEANUP" in upper:
        return "Concentrator · Hashcat validation"
    if "PARALLEL RULE FILE ANALYSIS" in upper or "ANALYSIS OF" in upper:
        return "Concentrator · Input analysis"
    if "GPU" in upper and "OPENCL" in upper:
        return "Concentrator · GPU initialization"
    if "[GPU]" in upper and any(word in upper for word in ("INITIAL", "COMPILE", "DEVICE", "CONTEXT")):
        return "GPU Setup · Device initialization"
    return None


def clear_log_history():
    """Clear the current browser log buffer and truncate the persisted engine log.

    A generation counter lets every connected browser discard stale entries,
    including entries that were already rendered before another client cleared
    the log. Sequence numbers remain monotonic within a run.
    """
    with LOCK:
        run_dir = STATE.get("run_dir")
        log_path = Path(run_dir) / "engine.log" if run_dir else None
        if log_path is not None:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text("", encoding="utf-8")
            except OSError as exc:
                raise RuntimeError(f"Could not clear the saved engine log: {exc}") from exc

        STATE["logs"] = []
        STATE["log_generation"] = int(STATE.get("log_generation", 0)) + 1
        for output in STATE.get("outputs", []):
            if output.get("name") == "engine.log":
                output["size"] = 0
        return {
            "log_seq": int(STATE.get("log_seq", 0)),
            "log_generation": STATE["log_generation"],
        }


def add_log(line: str):
    clean = clean_terminal_text(line)
    if not clean:
        return
    with LOCK:
        STATE["log_seq"] += 1
        event_time = time.time()
        STATE["logs"].append({"id": STATE["log_seq"], "text": clean, "time": event_time})
        if len(STATE["logs"]) > 5000:
            STATE["logs"] = STATE["logs"][-4000:]
        run_dir = STATE.get("run_dir")
        if run_dir:
            try:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event_time))
                with (Path(run_dir) / "engine.log").open("a", encoding="utf-8") as log_file:
                    log_file.write(f"[{stamp}] {clean}\n")
            except OSError:
                pass


def update_stage(line: str):
    clean = clean_terminal_text(line)
    if not clean:
        return
    stage = detect_active_stage(clean)
    with LOCK:
        active_tool = STATE.get("tool", "rulest")
    if active_tool == "ranker" and stage is None:
        upper = clean.upper()
        if "CELF" in upper or "GREEDY" in upper or "POST-PROCESS" in upper:
            stage = "Rule Ranker · CELF optimization"
        elif "ANALYSIS" in upper or "EXTRACTING" in upper or "SUMMARY" in upper:
            stage = "Rule Ranker · CSV analysis"
        elif "RANKER" in upper or "MAB" in upper or "TRIAL" in upper or "%" in upper:
            stage = "Rule Ranker · GPU scoring"
        else:
            stage = "Rule Ranker"
    elif active_tool == "concentrator" and stage is None:
        upper = clean.upper()
        if "MARKOV" in upper:
            stage = "Concentrator · Markov generation"
        elif "COMBO" in upper or "COMBINATORIAL" in upper:
            stage = "Concentrator · Combinatorial generation"
        elif "EXTRACTION" in upper or "EXTRACT" in upper:
            stage = "Concentrator · Rule extraction"
        elif "MINIMIZ" in upper or "FILTER" in upper or "CLEANUP" in upper:
            stage = "Concentrator · Ruleset processing"
        elif "GPU" in upper or "OPENCL" in upper:
            stage = "Concentrator · GPU setup"
        else:
            stage = "Concentrator · Processing"
    pct_match = PROGRESS_PERCENT_RE.search(clean)
    count_match = PROGRESS_COUNT_RE.search(clean)
    progress = None
    if pct_match:
        progress = min(100, int(pct_match.group(1)))
    elif count_match:
        total = int(count_match.group(2).replace(",", ""))
        done = int(count_match.group(1).replace(",", ""))
        if total > 0:
            progress = min(100, round(done * 100 / total))

    with LOCK:
        if "RESUMED" in clean.upper():
            STATE["paused"] = False
            STATE["pause_requested"] = False
        elif "PAUSED" in clean.upper():
            STATE["paused"] = True
            STATE["pause_requested"] = False
        if stage:
            if stage != STATE["stage"]:
                STATE["progress"] = None
                STATE["stage_started_at"] = time.time()
            STATE["stage"] = stage
            if stage == "Completed":
                STATE["progress"] = 100
                STATE["stage_detail"] = "All processing phases completed successfully."
            else:
                # Keep the most recent meaningful engine message as the live
                # sub-step, while retaining the complete line in the log.
                STATE["stage_detail"] = clean[:320]
        elif clean and STATE.get("status") in ("running", "stopping"):
            # Show current work details from the same phase without allowing
            # the startup configuration list to change the active phase.
            if STATE.get("stage") not in ("Waiting for a run", "Starting engine"):
                STATE["stage_detail"] = clean[:320]
        if progress is not None:
            STATE["progress"] = progress


def build_command(options: dict, run_dir: Path):
    base = UPLOADS_META.get("base")
    target = UPLOADS_META.get("target")
    if not base or not target:
        raise ValueError("Upload both BASE and TARGET wordlists before starting a run.")
    output_name = safe_name(options.get("output_name", "rulest_output.txt"))
    if output_name.lower() == "control.txt":
        raise ValueError("The output filename 'control.txt' is reserved for run controls.")
    output_path = run_dir / output_name
    cmd = [sys.executable, "-u", str(ROOT / "run_rulest.py"), str(base["path"]), str(target["path"]), "--output", str(output_path)]
    for key, flag in BOOL_OPTIONS.items():
        if options.get(key):
            cmd.append(flag)
    for key, flag in VALUE_OPTIONS.items():
        value = options.get(key)
        if value is None or value == "":
            continue
        cmd.extend([flag, str(value)])
    # The engine's --seed option fixes Python/NumPy RNG state and pins
    # PYTHONHASHSEED via its early re-exec path. Keep it optional so existing
    # clients retain the engine's default non-deterministic behaviour.
    rng_seed_raw = options.get("rng_seed")
    if rng_seed_raw not in (None, ""):
        if isinstance(rng_seed_raw, bool):
            raise ValueError("RNG seed must be an integer from 0 to 4294967295.")
        rng_seed_text = str(rng_seed_raw).strip()
        if not re.fullmatch(r"[0-9]{1,10}", rng_seed_text):
            raise ValueError("RNG seed must be an integer from 0 to 4294967295.")
        rng_seed = int(rng_seed_text)
        if rng_seed > 0xFFFFFFFF:
            raise ValueError("RNG seed must be between 0 and 4294967295.")
        cmd.extend(["--seed", str(rng_seed)])
    seed = UPLOADS_META.get("seed")
    if seed:
        cmd.extend(["--seed-rules", str(seed["path"])])
    for depth in range(2, 11):
        value = options.get(f"depth{depth}_chains")
        if value not in (None, ""):
            cmd.extend([f"--depth{depth}-chains", str(value)])
    return cmd, output_name


def _uploaded_path(field: str, label: str) -> Path:
    item = UPLOADS_META.get(field)
    if not item or not Path(item["path"]).is_file():
        raise ValueError(f"Upload the {label} file first.")
    return Path(item["path"])


def _int_option(options: dict, key: str, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    raw = options.get(key, default)
    if raw in (None, ""):
        return default
    if isinstance(raw, bool):
        raise ValueError(f"{key.replace('_', ' ')} must be an integer.")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{key.replace('_', ' ')} must be an integer.")
    if value < minimum or (maximum is not None and value > maximum):
        range_text = f"{minimum}–{maximum}" if maximum is not None else f">= {minimum}"
        raise ValueError(f"{key.replace('_', ' ')} must be {range_text}.")
    return value


def _float_option(options: dict, key: str, default: float, minimum: float = 0.0, maximum: float | None = None) -> float:
    raw = options.get(key, default)
    if raw in (None, ""):
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{key.replace('_', ' ')} must be a number.")
    if not math.isfinite(value) or not (value >= minimum) or (maximum is not None and value > maximum):
        range_text = f"{minimum}–{maximum}" if maximum is not None else f">= {minimum}"
        raise ValueError(f"{key.replace('_', ' ')} must be {range_text}.")
    return value


def build_ranker_command(mode: str, options: dict, run_dir: Path):
    """Build a validated command for the bundled Rule Ranker dispatcher."""
    if mode not in {"rank", "optimize", "analyze"}:
        raise ValueError("Unsupported Rule Ranker workflow.")
    cmd = [sys.executable, "-u", str(ROOT / "run_ranker.py")]

    if mode == "rank":
        wordlist = _uploaded_path("ranker_wordlist", "base wordlist")
        rules = _uploaded_path("ranker_rules", "candidate rules")
        cracked = _uploaded_path("ranker_cracked", "cracked-password list")
        output_name = safe_name(options.get("output_name", "ranker_output.csv"), "ranker_output.csv")
        if output_name.lower() in {"control.txt", "engine.log"}:
            raise ValueError("This output filename is reserved.")
        output_path = run_dir / output_name
        cmd += ["rank", "--wordlist", str(wordlist), "--rules", str(rules), "--cracked", str(cracked), "--output", str(output_path)]
        cmd += ["--topk", str(_int_option(options, "topk", 1000, 0))]

        for key, flag in (("batch_size", "--batch-size"), ("global_bits", "--global-bits"), ("cracked_bits", "--cracked-bits")):
            raw = options.get(key)
            if raw not in (None, ""):
                cmd += [flag, str(_int_option(options, key, 1, 1))]
        preset = options.get("preset") or "recommend"
        if preset not in {"low_memory", "medium_memory", "high_memory", "recommend"}:
            raise ValueError("Select a valid GPU memory preset.")
        cmd += ["--preset", preset]
        if options.get("legacy"):
            # Legacy is a separate exhaustive strategy; do not send MAB-only
            # tuning flags or validate hidden MAB controls in this mode.
            cmd.append("--legacy")
        else:
            cmd += ["--mab-exploration", str(_float_option(options, "mab_exploration", 2.0, 0.0))]
            cmd += ["--mab-final-trials", str(_int_option(options, "mab_final_trials", 50, 1))]
            cmd += ["--mab-screening-trials", str(_int_option(options, "mab_screening_trials", 5, 1))]
            cmd += ["--mab-sample-words", str(_int_option(options, "mab_sample_words", 8192, 1))]
            if not options.get("mab_zero_eliminate", True):
                cmd.append("--mab-no-zero-eliminate")
        device = options.get("device")
        if device not in (None, ""):
            cmd += ["--device", str(_int_option(options, "device", 0, 0))]
        return cmd, output_name

    if mode == "optimize":
        wordlist = _uploaded_path("ranker_wordlist", "base wordlist")
        cracked = _uploaded_path("ranker_cracked", "cracked-password list")
        source_csv = UPLOADS_META.get("ranker_source_csv")
        source_rules = UPLOADS_META.get("ranker_source_rules")
        if bool(source_csv) == bool(source_rules):
            raise ValueError("Upload exactly one optimization source: a ranking CSV or a plain .rule file.")
        source_type = options.get("source_type", "rules")
        if source_type not in {"rules", "csv"}:
            raise ValueError("Choose either a plain .rule file or a ranking CSV as the optimization source.")
        if source_type == "csv" and not source_csv:
            raise ValueError("The selected source is a ranking CSV, but no ranking CSV is uploaded.")
        if source_type == "rules" and not source_rules:
            raise ValueError("The selected source is a plain .rule file, but no ruleset file is uploaded.")
        output_name = safe_name(options.get("output_name", "ranker_optimized.rule"), "ranker_optimized.rule")
        if output_name.lower() in {"control.txt", "engine.log"}:
            raise ValueError("This output filename is reserved.")
        output_path = run_dir / output_name
        cmd.append("postprocess")
        if source_csv:
            cmd += ["--ranking-csv", str(source_csv["path"])]
        else:
            cmd += ["--rules-file", str(source_rules["path"])]
        cmd += ["--wordlist", str(wordlist), "--cracked", str(cracked), "--output", str(output_path)]
        cmd += ["--candidates", str(_int_option(options, "candidates", 20000, 1))]
        for key, flag in (("budget", "--budget"), ("rule_batch_size", "--rule-batch-size"),
                          ("words_batch_size", "--words-batch-size"), ("max_word_len", "--max-word-len"),
                          ("max_rule_len", "--max-rule-len"), ("max_output_len", "--max-output-len")):
            raw = options.get(key)
            if raw not in (None, ""):
                minimum = 1 if key in {"budget", "rule_batch_size", "words_batch_size", "max_word_len", "max_rule_len", "max_output_len"} else 0
                cmd += [flag, str(_int_option(options, key, 1, minimum))]
        budgets = str(options.get("budgets", "") or "").strip()
        if budgets:
            parts = [part.strip() for part in budgets.split(",")]
            if any(not re.fullmatch(r"[0-9]+", part) or int(part) <= 0 for part in parts):
                raise ValueError("Budget sweep must contain positive integers separated by commas.")
            if len(set(parts)) != len(parts):
                raise ValueError("Budget sweep values must be unique.")
            cmd += ["--budgets", ",".join(parts)]
        if options.get("auto_max_output_len"):
            cmd.append("--auto-max-output-len")
        if options.get("print_output_len_estimate"):
            cmd.append("--print-output-len-estimate")
        if options.get("device") not in (None, ""):
            cmd += ["--device", str(_int_option(options, "device", 0, 0))]
        cmd += ["--cost-alpha", str(_float_option(options, "cost_alpha", 0.0, 0.0))]
        cmd += ["--strategy", "recompute-gpu"]
        return cmd, output_name

    # mode == analyze: CPU-friendly ranking CSV analysis / extraction.
    source = _uploaded_path("ranker_analysis_csv", "ranking CSV")
    output_name = safe_name(options.get("summary_name", "rule_analysis_summary.txt"), "rule_analysis_summary.txt")
    rules_name = safe_name(options.get("rules_output_name", "clean_rules.rule"), "clean_rules.rule")
    scores_name = safe_name(options.get("scores_output_name", "rules_with_scores.csv"), "rules_with_scores.csv")
    cmd += ["handler", "--input", str(source)]
    if not options.get("rules_only") and not options.get("no_stats"):
        cmd += ["--output", str(run_dir / output_name)]
    if options.get("write_rules", True):
        cmd += ["--rules-output", str(run_dir / rules_name)]
    if options.get("write_scores"):
        cmd += ["--scores-output", str(run_dir / scores_name)]
    if options.get("top") not in (None, ""):
        cmd += ["--top", str(_int_option(options, "top", 1, 1))]
    cmd += ["--console-top", str(_int_option(options, "console_top", 20, 0))]
    cmd += ["--chunk-size", str(_int_option(options, "chunk_size", 10000, 1))]
    for key, flag in (("no_console", "--no-console"), ("parallel", "--parallel"),
                      ("no_progress", "--no-progress"), ("rules_only", "--rules-only"),
                      ("no_stats", "--no-stats")):
        if options.get(key):
            cmd.append(flag)
    return cmd, output_name


def build_concentrator_command(mode: str, options: dict, run_dir: Path):
    """Build a non-interactive command for the bundled Concentrator v3.5 tool."""
    if mode not in {"extract", "combo", "markov", "process"}:
        raise ValueError("Choose a valid Concentrator workflow.")
    uploaded = UPLOADS_META.get("concentrator_files") or []
    if not uploaded:
        raise ValueError("Upload at least one Hashcat rules file for Concentrator.")
    paths = []
    for item in uploaded:
        path = Path(item["path"])
        if not path.is_file():
            raise ValueError(f"Concentrator input file is missing: {item.get('name', path.name)}")
        paths.append(path)
    if len(paths) > MAX_CONCENTRATOR_FILES:
        raise ValueError(f"Concentrator accepts at most {MAX_CONCENTRATOR_FILES} input files.")

    output_base_name = safe_name(options.get("output_base_name", "concentrator_output"), "concentrator_output")
    if output_base_name.lower() in {"control", "control.txt", "engine.log", "auth.json"}:
        raise ValueError("This output base name is reserved.")
    output_base = run_dir / output_base_name
    max_length = _int_option(options, "max_length", 31, 1, 255)
    output_format = options.get("output_format", "line")
    if output_format not in {"line", "expanded"}:
        raise ValueError("Choose a valid Concentrator output format.")
    cmd = [sys.executable, "-u", str(ROOT / "concentrator.py"), *[str(path) for path in paths],
           "-ob", str(output_base), "-f", output_format, "-m", str(max_length)]
    cmd.append("--in-memory" if options.get("in_memory") else "-d")
    if options.get("no_gpu"):
        cmd.append("--no-gpu")
    # Concentrator's --yes is a global non-interactive consent switch. Add it
    # for every workflow, not just -p, so Markov / combo memory checks never
    # fall back to an input() prompt in the web worker.
    if options.get("confirm_large_memory"):
        cmd.append("-y")

    if mode == "extract":
        cmd += ["-e", "-t", str(_int_option(options, "top_rules", 10000, 1))]
        if options.get("statistical_sort"):
            cmd.append("-s")
        output_name = f"{output_base_name}_extracted.rule"
    elif mode == "combo":
        minimum = _int_option(options, "combo_min_len", 1, 1, 31)
        maximum = _int_option(options, "combo_max_len", 3, 1, 31)
        if minimum > maximum:
            raise ValueError("Combinatorial minimum length must not exceed maximum length.")
        cmd += ["-g", "-n", str(_int_option(options, "combo_target", 100000, 1)),
                "-l", str(minimum), str(maximum)]
        output_name = f"{output_base_name}_combo.rule"
    elif mode == "markov":
        minimum = _int_option(options, "markov_min_len", 1, 1, 31)
        maximum = _int_option(options, "markov_max_len", 3, 1, 31)
        if minimum > maximum:
            raise ValueError("Markov minimum length must not exceed maximum length.")
        cmd += ["-gm", "-gt", str(_int_option(options, "generate_target", 10000, 1)),
                "-ml", str(minimum), str(maximum)]
        output_name = f"{output_base_name}_markov.rule"
    else:
        cmd.append("-p")
        min_occ = options.get("filter_min_occ")
        max_rules = options.get("filter_max_rules")
        inverse = options.get("filter_inverse")
        if min_occ not in (None, ""):
            cmd += ["--filter-min-occ", str(_int_option(options, "filter_min_occ", 1, 1))]
        if max_rules not in (None, ""):
            cmd += ["--filter-max-rules", str(_int_option(options, "filter_max_rules", 1, 1))]
        if options.get("filter_func_redundancy"):
            cmd.append("--filter-func-redundancy")
        if inverse not in (None, ""):
            cmd += ["--filter-inverse", str(_int_option(options, "filter_inverse", 1, 1))]
        cleanup_mode = options.get("filter_hashcat_cleanup")
        if cleanup_mode not in (None, "", "none", "cpu", "gpu"):
            raise ValueError("Hashcat cleanup must be None, CPU or GPU.")
        if cleanup_mode in {"cpu", "gpu"}:
            cmd += ["--filter-hashcat-cleanup", cleanup_mode]
        output_name = f"{output_base_name}_processed.rule"
    return cmd, output_name


def run_worker(cmd, run_id, run_dir, control_file=None, tool="rulest", storage_baseline_bytes=None):
    global PROCESS, RUN_THREAD
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # Give progress renderers a wide virtual terminal so they do not discard
    # useful counters/postfix fields before the GUI can wrap the full line.
    env["COLUMNS"] = "200"
    env["LINES"] = "40"
    if tool == "concentrator":
        env["CONCENTRATOR_WEB_MODE"] = "1"
        env["CONCENTRATOR_WEB_AUTO_CONFIRM"] = "1" if "-y" in cmd else "0"
    else:
        env.pop("CONCENTRATOR_WEB_MODE", None)
        env.pop("CONCENTRATOR_WEB_AUTO_CONFIRM", None)
    if control_file is not None:
        env["RULEST_CONTROL_FILE"] = str(control_file)
    else:
        env.pop("RULEST_CONTROL_FILE", None)
    creationflags = 0
    popen_kwargs = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True
    start = time.time()
    proc = None
    code = None
    error = None
    outputs = []
    storage_guard = {"error": None}
    storage_stop = threading.Event()
    storage_thread = None
    if storage_baseline_bytes is None:
        storage_baseline_bytes = max(0, data_storage_usage_bytes() - _directory_usage(run_dir)[1])
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=0, creationflags=creationflags, **popen_kwargs,
        )
        with LOCK:
            PROCESS = proc
            STATE["pid"] = proc.pid

        def storage_watchdog():
            while not storage_stop.wait(STORAGE_WATCH_INTERVAL_SECONDS):
                try:
                    run_bytes = _directory_usage(run_dir)[1]
                    total_bytes = int(storage_baseline_bytes) + run_bytes
                    free_bytes = shutil.disk_usage(DATA).free
                    reason = None
                    if total_bytes > MAX_DATA_STORAGE_BYTES:
                        reason = (
                            f"RULEOPS data quota exceeded: {total_bytes:,} / "
                            f"{MAX_DATA_STORAGE_BYTES:,} bytes."
                        )
                    elif free_bytes < MIN_FREE_DISK_BYTES:
                        reason = (
                            f"Free disk space fell below the configured reserve "
                            f"({free_bytes:,} < {MIN_FREE_DISK_BYTES:,} bytes)."
                        )
                    if reason:
                        storage_guard["error"] = reason
                        add_log(f"[SECURITY] {reason} Stopping the active process to protect storage.")
                        try:
                            if os.name == "nt":
                                proc.terminate()
                            else:
                                os.killpg(proc.pid, signal.SIGTERM)
                        except (OSError, ProcessLookupError):
                            pass
                        return
                except OSError as exc:
                    storage_guard["error"] = f"Storage watchdog could not inspect disk usage: {exc}"
                    add_log(f"[SECURITY] {storage_guard['error']} Stopping the active process.")
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                    return

        storage_thread = threading.Thread(target=storage_watchdog, name="ruleops-storage-watchdog", daemon=True)
        storage_thread.start()
        pending = ""
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        # rulest progress bars redraw in place using a bare carriage return
        # (no trailing newline) and can redraw several times per second for
        # the entire duration of a long stage (e.g. CELF greedy selection,
        # which can run for hours). Emitting one persisted log entry per
        # redraw used to flood STATE["logs"] and, more importantly, the
        # browser's log DOM (one new element appended per entry, never
        # trimmed), which eventually made the web UI tab unresponsive even
        # though the underlying engine process kept running and finished
        # normally. Bare-CR frames are therefore throttled before being
        # persisted/broadcast; real newline-terminated lines are never
        # throttled. Stage detection still runs on every frame (cheap, no
        # I/O) so the UI's "current stage" stays responsive.
        last_progress_emit = 0.0
        PROGRESS_LOG_MIN_INTERVAL = 2.0
        while True:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            decoded = decoder.decode(chunk)
            pending += decoded
            tokens = re.split(r"(\r\n|\n|\r)", pending)
            pending = tokens.pop() if tokens else ""
            for i in range(0, len(tokens) - 1, 2):
                line, sep = tokens[i], tokens[i + 1]
                update_stage(line)
                if sep == "\r":
                    now = time.time()
                    if now - last_progress_emit < PROGRESS_LOG_MIN_INTERVAL:
                        continue
                    last_progress_emit = now
                add_log(line)
        pending += decoder.decode(b"", final=True)
        if pending.strip():
            add_log(pending)
            update_stage(pending)
        code = proc.wait()
        if storage_guard["error"]:
            error = storage_guard["error"]
        add_log(f"[WEB] Process finished with exit code {code} in {time.time() - start:.1f}s.")
    except Exception as exc:
        error = str(exc)
        add_log(f"[WEB ERROR] {exc}")
    finally:
        storage_stop.set()
        if storage_thread is not None and storage_thread.is_alive():
            storage_thread.join(timeout=STORAGE_WATCH_INTERVAL_SECONDS + 1)
        # Keep status as running/stopping until cleanup finishes so a new upload
        # cannot race with deletion of the previous run's inputs.
        with LOCK:
            was_stopped = STATE.get("status") == "stopping"
        cleanup_uploaded_files(log_message=True)
        if error is None:
            for item in sorted(run_dir.iterdir()):
                if item.is_file() and item.name != "control.txt":
                    outputs.append({"name": item.name, "size": item.stat().st_size})
        with LOCK:
            PROCESS = None
            RUN_THREAD = None
            STATE["pid"] = None
            STATE["paused"] = False
            STATE["pause_requested"] = False
            STATE["finished_at"] = time.time()
            STATE["outputs"] = outputs
            if error is not None:
                STATE["status"] = "failed"
                STATE["error"] = error
                STATE["stage"] = "Process error"
                STATE["stage_detail"] = error[:320]
                STATE["exit_code"] = code
            elif was_stopped:
                STATE["status"] = "stopped"
                STATE["stage"] = "Stopped"
                STATE["stage_detail"] = "Run stopped. Partial results, if any, were preserved."
                STATE["exit_code"] = code
            else:
                STATE["status"] = "completed" if code == 0 else "failed"
                STATE["exit_code"] = code
                STATE["stage"] = "Completed" if code == 0 else "Process exited with an error"
                STATE["stage_detail"] = (
                    "Run completed successfully." if code == 0
                    else f"Engine process exited with code {code}. Check the log for the failure details."
                )
                STATE["progress"] = 100 if code == 0 else STATE.get("progress")


class RulestHTTPServer(ThreadingHTTPServer):
    """Bounded threaded HTTP server with explicit admission control."""
    daemon_threads = False
    block_on_close = True
    request_queue_size = 32
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self._connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)
        self._active_requests = set()
        self._active_requests_lock = threading.Lock()
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            response = (
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Connection: close\r\n"
                b"Retry-After: 5\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-Length: 32\r\n\r\n"
                b"RULEOPS connection limit reached"
            )
            try:
                request.settimeout(0.5)
                request.sendall(response)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        with self._active_requests_lock:
            self._active_requests.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._active_requests_lock:
                self._active_requests.discard(request)
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_requests_lock:
                self._active_requests.discard(request)
            self._connection_slots.release()

    def server_close(self):
        # Interrupt in-flight HTTP requests/uploads before waiting for handler
        # threads; partial uploads are removed by their normal exception path.
        with self._active_requests_lock:
            active = list(self._active_requests)
        for request in active:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "RULEOPS"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def version_string(self):
        return "RULEOPS"

    def setup(self):
        super().setup()
        self.connection.settimeout(REQUEST_IDLE_TIMEOUT_SECONDS)
        self._header_timer = threading.Timer(HEADER_TIMEOUT_SECONDS, self._abort_slow_headers)
        self._header_timer.daemon = True
        self._header_timer.start()

    def _abort_slow_headers(self):
        try:
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            timer = getattr(self, "_header_timer", None)
            if timer is not None:
                timer.cancel()

    def end_headers(self):
        # Centralized defense-in-depth headers apply to success, redirects and errors.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
        )
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def log_message(self, fmt, *args):
        # Keep the terminal clean; application activity is in the browser log.
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        queued_cookie = getattr(self, "_auth_set_cookie", None)
        if queued_cookie:
            self.send_header("Set-Cookie", queued_cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Login/setup endpoints and the branded favicon are intentionally public.
        if path == "/api/auth/me":
            self.handle_auth_me()
            return
        if path == "/favicon.svg":
            self.serve_static("favicon.svg", "image/svg+xml; charset=utf-8")
            return
        if path == "/login.css":
            self.serve_static("login.css", "text/css; charset=utf-8")
            return
        if path == "/login.js":
            self.serve_static("login.js", "text/javascript; charset=utf-8")
            return
        if path in ("/", "/index.html", "/login"):
            if get_session(self):
                if path == "/login":
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                else:
                    self.serve_static("index.html", "text/html; charset=utf-8")
            else:
                self.serve_static("login.html", "text/html; charset=utf-8")
            return

        if not self.require_authenticated(api=path.startswith("/api/")):
            return

        if path == "/app.js":
            self.serve_static("app.js", "text/javascript; charset=utf-8")
        elif path == "/styles.css":
            self.serve_static("styles.css", "text/css; charset=utf-8")
        elif path == "/api/devices":
            try:
                diagnostics = collect_gpu_diagnostics()
                devices = [
                    {"index": str(item["index"]), "name": item["name"], "type": item["type"],
                     "vendor": item["vendor"], "platform": item["platform"]}
                    for item in diagnostics["devices"]
                ]
                self.send_json({
                    "ok": diagnostics["gpu_count"] > 0,
                    "devices": devices,
                    "gpu_devices": [item for item in devices if item["type"] == "GPU"],
                    "message": diagnostics["summary"],
                    "diagnostics": diagnostics,
                })
            except Exception as exc:
                self.send_json({
                    "ok": False, "devices": [], "gpu_devices": [],
                    "message": f"GPU diagnostics failed: {type(exc).__name__}: {exc}",
                }, 500)
        elif path == "/api/run-storage/summary":
            self.send_json({"ok": True, **run_storage_summary()})
        elif path == "/api/license":
            self.send_json({"ok": True, "license": license_summary(), "demo_limit": DEMO_LIMIT})
        elif path == "/api/status":
            qs = urllib.parse.parse_qs(parsed.query)
            try:
                since = int(qs.get("since", ["0"])[0])
            except ValueError:
                since = 0
            try:
                client_generation = int(qs.get("generation", ["-1"])[0])
            except ValueError:
                client_generation = -1
            with LOCK:
                elapsed = None
                if STATE["started_at"]:
                    end = STATE["finished_at"] or time.time()
                    elapsed = max(0, end - STATE["started_at"])
                data = {k: v for k, v in STATE.items() if k not in ("logs", "control_file", "run_dir")}
                data["engine_badge"] = engine_badge_for_status(STATE.get("status", "idle"), STATE.get("paused", False))
                data["license"] = license_summary()
                _sess = get_session(self)
                data["role"] = session_role(_sess) if _sess else None
                data["is_admin"] = data["role"] == "admin"
                data["elapsed"] = elapsed
                data["stage_elapsed"] = max(0, time.time() - STATE["stage_started_at"]) if STATE.get("stage_started_at") else None
                current_generation = int(STATE.get("log_generation", 0))
                data["log_generation"] = current_generation
                data["logs"] = (
                    list(STATE["logs"]) if client_generation != current_generation
                    else [entry for entry in STATE["logs"] if entry["id"] > since]
                )
                data["uploads"] = {
                    k: ([{"name": item["name"], "size": item["size"]} for item in v] if isinstance(v, list)
                        else ({"name": v["name"], "size": v["size"]} if v else None))
                    for k, v in UPLOADS_META.items()
                }
            self.send_json(data)
        elif path.startswith("/api/download/"):
            name = safe_name(urllib.parse.unquote(path.rsplit("/", 1)[-1]))
            with LOCK:
                run_dir = Path(STATE["run_dir"]) if STATE.get("run_dir") else None
                allowed = {x["name"] for x in STATE.get("outputs", [])}
            target = run_dir / name if run_dir else None
            if not target or name not in allowed or not target.is_file():
                self.send_error(404, "Output not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(target.stat().st_size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            with target.open("rb") as f:
                shutil.copyfileobj(f, self.wfile)
        else:
            self.send_error(404)

    def serve_static(self, filename, content_type):
        path = WEB / filename
        if not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store" if filename == "index.html" else "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        content_lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(content_lengths) > 1:
            self.close_connection = True
            self.send_json({"error": "Transfer-Encoding and duplicate Content-Length headers are not supported."}, 400)
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/auth/setup":
            self.handle_auth_setup()
            return
        if parsed.path == "/api/auth/login":
            self.handle_auth_login()
            return
        if not self.require_authenticated(api=True, csrf=True):
            return
        if parsed.path in ("/api/run", "/api/ranker/run", "/api/concentrator/run"):
            # Per-module DEMO counters (independent, durable). Full license bypasses limits.
            path_to_module = {
                "/api/run": "RULEST",
                "/api/ranker/run": "RULE_RANKER",
                "/api/concentrator/run": "CONCENTRATOR",
            }
            module = path_to_module[parsed.path]
            try:
                gate = can_start_full_run(module)
                # Record a full DEMO consumption only while still in DEMO (not LIMITED, not licensed).
                if gate.get("mode") == "DEMO" and not is_fully_licensed():
                    status = record_module_run(module, tool_path=parsed.path)
                    # Attach status for handlers / logs via request attribute
                    self._demo_run_status = status
                else:
                    self._demo_run_status = {
                        "module": module,
                        "mode": gate.get("mode"),
                        "used": gate.get("used", 0),
                        "remaining": gate.get("remaining", -1),
                        "recorded": False,
                    }
            except Exception as exc:
                self.send_json({
                    "error": f"License usage store unavailable; operation blocked safely. ({type(exc).__name__})",
                    "license_required": True,
                }, 503)
                return
        if parsed.path == "/api/auth/logout":
            self.handle_auth_logout()
        elif parsed.path == "/api/auth/change-password":
            self.handle_auth_change_password()
        elif parsed.path == "/api/auth/set-user-password":
            self.handle_auth_set_user_password()
        elif parsed.path == "/api/license/install":
            self.handle_license_install()
        elif parsed.path.startswith("/api/upload/"):
            self.handle_upload(parsed, ranker=False)
        elif parsed.path.startswith("/api/ranker/upload/"):
            self.handle_upload(parsed, ranker=True)
        elif parsed.path.startswith("/api/concentrator/upload/"):
            self.handle_upload(parsed, concentrator=True)
        elif parsed.path == "/api/run":
            self.handle_run()
        elif parsed.path == "/api/ranker/run":
            self.handle_ranker_run()
        elif parsed.path == "/api/ranker/cancel":
            self.handle_ranker_cancel()
        elif parsed.path == "/api/concentrator/run":
            self.handle_concentrator_run()
        elif parsed.path == "/api/concentrator/cancel":
            self.handle_concentrator_cancel()
        elif parsed.path == "/api/control":
            self.handle_control()
        elif parsed.path == "/api/logs/clear":
            self.handle_clear_logs()
        elif parsed.path == "/api/run-storage/clear":
            self.handle_clear_run_directories()
        else:
            self.send_error(404)

    def require_authenticated(self, api=False, csrf=False):
        session = get_session(self)
        if not session:
            if api:
                self.send_json({"error": "Authentication required. Please sign in again.", "auth_required": True}, 401)
            else:
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            return False
        if csrf:
            supplied = self.headers.get("X-CSRF-Token", "")
            if not supplied or not hmac.compare_digest(supplied, session[1].get("csrf", "")):
                self.send_json({"error": "Invalid or missing request security token. Refresh the page and try again."}, 403)
                return False
        return True

    def _declared_content_length(self, maximum: int, allow_empty: bool = False):
        values = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding requests are not supported.")
        if len(values) != 1 or not str(values[0]).strip().isdigit():
            raise ValueError("A single valid Content-Length header is required.")
        length = int(values[0])
        if (length == 0 and not allow_empty) or length > maximum:
            raise OverflowError("Request body is empty or exceeds the allowed size.")
        return length

    def _read_exact_body(self, length: int, total_timeout: float):
        deadline = time.monotonic() + total_timeout
        chunks = []
        remaining = length
        while remaining:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("Request body exceeded its total time limit.")
            self.connection.settimeout(min(REQUEST_IDLE_TIMEOUT_SECONDS, left))
            chunk = self.rfile.read1(min(UPLOAD_CHUNK_BYTES, remaining))
            if not chunk:
                raise ConnectionError("Request body ended before Content-Length bytes arrived.")
            chunks.append(chunk)
            remaining -= len(chunk)
        self.connection.settimeout(REQUEST_IDLE_TIMEOUT_SECONDS)
        return b"".join(chunks)

    def read_json_body(self, maximum=1024 * 1024):
        self._body_read_failed = False
        try:
            length = self._declared_content_length(maximum)
            body = self._read_exact_body(length, total_timeout=20.0)
            return json.loads(body.decode("utf-8"))
        except OverflowError:
            self._body_read_failed = True
            self.send_json({"error": "Request body is empty or too large."}, 413)
        except (ValueError, TimeoutError, ConnectionError, OSError, json.JSONDecodeError, UnicodeDecodeError):
            self._body_read_failed = True
            self.close_connection = True
            self.send_json({"error": "Invalid or incomplete request body."}, 400)
        return None

    def read_upload_to_file(self, destination: Path, length: int, reservation_key: str | None = None):
        """Stream an upload with idle, absolute-progress and minimum-rate limits."""
        start = time.monotonic()
        rate_window_start = start
        rate_window_bytes = 0
        received = 0
        deadline = start + max(
            300.0,
            (length / float(UPLOAD_MIN_RATE_BYTES_PER_SECOND)) * 1.5 + 120.0,
        )
        with destination.open("xb") as output:
            while received < length:
                now = time.monotonic()
                if now >= deadline:
                    raise TimeoutError("Upload exceeded its maximum transfer duration.")
                self.connection.settimeout(min(UPLOAD_IDLE_TIMEOUT_SECONDS, max(0.5, deadline - now)))
                chunk = self.rfile.read1(min(UPLOAD_CHUNK_BYTES, length - received))
                if not chunk:
                    raise ConnectionError("Upload ended before all bytes arrived.")
                output.write(chunk)
                received += len(chunk)
                if reservation_key is not None:
                    with LOCK:
                        if reservation_key in UPLOAD_RESERVATIONS:
                            UPLOAD_RESERVATIONS[reservation_key] = max(0, length - received)
                rate_window_bytes += len(chunk)
                now = time.monotonic()
                elapsed = now - rate_window_start
                if (now - start >= UPLOAD_RATE_GRACE_SECONDS
                        and elapsed >= UPLOAD_RATE_CHECK_INTERVAL_SECONDS):
                    rate = rate_window_bytes / max(elapsed, 0.001)
                    if rate < UPLOAD_MIN_RATE_BYTES_PER_SECOND:
                        raise TimeoutError(
                            f"Upload rate {rate:.0f} B/s stayed below the configured minimum "
                            f"{UPLOAD_MIN_RATE_BYTES_PER_SECOND} B/s."
                        )
                    rate_window_start = now
                    rate_window_bytes = 0
        self.connection.settimeout(REQUEST_IDLE_TIMEOUT_SECONDS)

    def handle_auth_me(self):
        session = get_session(self)
        role = session_role(session) if session else None
        self.send_json({
            "authenticated": bool(session),
            "setup_required": not auth_configured(),
            "role": role,
            "is_admin": role == "admin",
            "csrf_token": session[1]["csrf"] if session else None,
            "session_expires_in": max(0, int(session[1]["expires"] - time.time())) if session else 0,
            "license": license_summary(),
        })

    def handle_auth_setup(self):
        if auth_configured():
            self.send_json({"error": "An application password is already configured. Sign in instead."}, 409)
            return
        data = self.read_json_body(16 * 1024)
        if self._body_read_failed:
            return
        password = data.get("password") if isinstance(data, dict) else None
        if not isinstance(password, str) or len(password) < PASSWORD_MIN_LENGTH or len(password) > 1024:
            self.send_json({"error": f"Choose a password with at least {PASSWORD_MIN_LENGTH} characters."}, 400)
            return
        with LOCK:
            if auth_configured():
                self.send_json({"error": "An application password was configured by another session. Sign in instead."}, 409)
                return
            try:
                save_admin_password(password)
            except OSError as exc:
                self.send_json({"error": f"Could not save auth.json: {exc}"}, 500)
                return
        csrf = create_session(self, role="admin")
        self.send_json({
            "ok": True,
            "csrf_token": csrf,
            "role": "admin",
            "message": "Administrator password configured. You are signed in as admin.",
        })

    def handle_auth_login(self):
        client_ip = request_ip(self)
        remaining = login_lock_remaining(client_ip)
        if remaining:
            self.send_json({"error": f"Too many failed attempts. Try again in {remaining} seconds."}, 429)
            return
        if not auth_configured():
            self.send_json({"error": "Create an application password before signing in."}, 409)
            return
        data = self.read_json_body(16 * 1024)
        if self._body_read_failed:
            return
        password = data.get("password") if isinstance(data, dict) else None
        if not isinstance(password, str) or len(password) > 1024:
            record_login_failure(client_ip)
            self.send_json({"error": "Incorrect password."}, 401)
            return
        role = verify_password_role(password)
        if not role:
            record_login_failure(client_ip)
            self.send_json({"error": "Incorrect password."}, 401)
            return
        reset_login_failures(client_ip)
        csrf = create_session(self, role=role)
        self.send_json({
            "ok": True,
            "csrf_token": csrf,
            "role": role,
            "is_admin": role == "admin",
            "message": f"Signed in successfully as {role}.",
            "license": license_summary(),
        })

    def handle_auth_logout(self):
        token = _cookie_token(self)
        with LOCK:
            if token:
                SESSIONS.pop(token, None)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        clear_session_cookie(self)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def handle_auth_change_password(self):
        client_ip = request_ip(self)
        remaining = login_lock_remaining(client_ip)
        if remaining:
            self.send_json({"error": f"Too many failed attempts. Try again in {remaining} seconds."}, 429)
            return
        data = self.read_json_body(16 * 1024)
        if self._body_read_failed:
            return
        if not isinstance(data, dict):
            self.send_json({"error": "Invalid password-change request."}, 400)
            return
        current = data.get("current_password")
        new_password = data.get("new_password")
        role = verify_password_role(current) if isinstance(current, str) else None
        if not role:
            record_login_failure(request_ip(self))
            self.send_json({"error": "Current password is incorrect."}, 401)
            return
        if not isinstance(new_password, str) or len(new_password) < PASSWORD_MIN_LENGTH or len(new_password) > 1024:
            self.send_json({"error": f"New password must contain at least {PASSWORD_MIN_LENGTH} characters."}, 400)
            return
        try:
            if role == "admin":
                save_admin_password(new_password)
            else:
                save_user_password(new_password)
        except (OSError, ValueError) as exc:
            self.send_json({"error": f"Could not update auth.json: {exc}"}, 500)
            return
        # Revoke every session and issue a fresh one to this browser.
        with LOCK:
            SESSIONS.clear()
        reset_login_failures(client_ip)
        csrf = create_session(self, role=role)
        self.send_json({
            "ok": True,
            "csrf_token": csrf,
            "role": role,
            "message": "Password changed. Other sessions have been signed out.",
        })

    def handle_auth_set_user_password(self):
        """Administrator sets or clears the regular user password."""
        if not require_admin(self, api=True):
            return
        data = self.read_json_body(16 * 1024)
        if self._body_read_failed:
            return
        password = data.get("password") if isinstance(data, dict) else None
        if password is not None and password != "":
            if not isinstance(password, str) or len(password) < PASSWORD_MIN_LENGTH or len(password) > 1024:
                self.send_json({"error": f"User password must be at least {PASSWORD_MIN_LENGTH} characters."}, 400)
                return
        try:
            save_user_password(password if password else None)
        except (OSError, ValueError) as exc:
            self.send_json({"error": f"Could not update user password: {exc}"}, 500)
            return
        self.send_json({
            "ok": True,
            "user_enabled": bool(password),
            "message": "User password updated." if password else "User password removed.",
        })

    def handle_license_install(self):
        """Administrator installs a signed license.lic payload (JSON envelope)."""
        if not require_admin(self, api=True):
            return
        data = self.read_json_body(256 * 1024)
        if self._body_read_failed:
            return
        if not isinstance(data, dict):
            self.send_json({"error": "Expected JSON license envelope with payload and signature."}, 400)
            return
        if "payload" not in data or "signature" not in data:
            self.send_json({"error": "License file must contain payload and signature fields."}, 400)
            return
        try:
            target = ROOT / "license.lic"
            temporary = target.with_name("license.lic.tmp")
            payload = json.dumps(data, indent=2) + "\n"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        except OSError as exc:
            self.send_json({"error": f"Could not write license.lic: {exc}"}, 500)
            return
        summary = license_summary()
        if not summary.get("valid"):
            self.send_json({
                "ok": False,
                "error": summary.get("reason") or "License installed but failed verification.",
                "license": summary,
            }, 400)
            return
        self.send_json({
            "ok": True,
            "message": "License installed. All modules restored to full capability.",
            "license": summary,
        })

    def handle_clear_logs(self):
        try:
            result = clear_log_history()
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, 500)
            return
        self.send_json({"ok": True, **result})

    def handle_clear_run_directories(self):
        try:
            result = clear_run_directories()
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, 409)
            return
        if result.get("failures"):
            self.send_json({"ok": False, **result}, 207)
            return
        self.send_json({"ok": True, **result})

    def handle_upload(self, parsed, ranker=False, concentrator=False):
        field = parsed.path.rsplit("/", 1)[-1]
        allowed_fields = (CONCENTRATOR_UPLOAD_FIELDS if concentrator else
                          RANKER_UPLOAD_FIELDS if ranker else {"base", "target", "seed"})
        if field not in allowed_fields:
            self.send_error(404)
            return
        query_params = urllib.parse.parse_qs(parsed.query)
        requested_filename = safe_name(query_params.get("filename", [f"{field}.txt"])[0], f"{field}.txt")
        if concentrator and field == "concentrator_files":
            extension = Path(requested_filename).suffix.lower()
            if extension not in {".rule", ".rules", ".hr", ".hashcat", ".txt", ".lst"}:
                self.send_json({"error": "Concentrator accepts .rule, .rules, .hr, .hashcat, .txt and .lst files."}, 415)
                return
        try:
            length = self._declared_content_length(MAX_UPLOAD_BYTES)
        except OverflowError:
            self.send_json({"error": f"Upload is empty or exceeds the per-file limit ({MAX_UPLOAD_BYTES:,} bytes)."}, 413)
            return
        except ValueError as exc:
            self.close_connection = True
            self.send_json({"error": str(exc)}, 400)
            return

        # Reserve quota before accepting any body bytes, preventing concurrent
        # clients from each passing an independent disk-space check.
        with LOCK:
            if STATE["status"] in ("running", "stopping"):
                self.send_json({"error": "Files cannot be replaced while a run is active."}, 409)
                return
            if field in UPLOADS_ACTIVE:
                self.send_json({"error": f"A {field.upper()} upload is already in progress."}, 409)
                return
            current_meta = UPLOADS_META.get(field)
            replaceable = int(current_meta.get("size", 0)) if isinstance(current_meta, dict) else 0
            exclusive_source = {
                "ranker_source_csv": "ranker_source_rules",
                "ranker_source_rules": "ranker_source_csv",
            }.get(field)
            if exclusive_source:
                other = UPLOADS_META.get(exclusive_source)
                if isinstance(other, dict):
                    replaceable += int(other.get("size", 0))
            try:
                upload_bytes = _directory_usage(UPLOADS)[1]
                data_bytes = data_storage_usage_bytes()
                free_bytes = shutil.disk_usage(UPLOADS).free
            except OSError as exc:
                self.send_json({"error": f"Storage check failed: {exc}"}, 507)
                return
            reserved_bytes = sum(int(value) for value in UPLOAD_RESERVATIONS.values())
            if upload_bytes + reserved_bytes - replaceable + length > MAX_TOTAL_UPLOAD_BYTES:
                self.send_json({
                    "error": f"Combined temporary uploads would exceed the {MAX_TOTAL_UPLOAD_BYTES:,}-byte quota. "
                             "Remove unused uploaded inputs or increase RULEOPS_MAX_UPLOAD_TOTAL_BYTES."
                }, 413)
                return
            if data_bytes + reserved_bytes - replaceable + length > MAX_DATA_STORAGE_BYTES:
                self.send_json({
                    "error": f"RULEOPS data quota ({MAX_DATA_STORAGE_BYTES:,} bytes) would be exceeded. "
                             "Clear old run folders or increase RULEOPS_MAX_DATA_STORAGE_BYTES."
                }, 507)
                return
            if free_bytes - length < MIN_FREE_DISK_BYTES:
                self.send_json({
                    "error": f"Upload would violate the {MIN_FREE_DISK_BYTES:,}-byte free-disk reserve."
                }, 507)
                return
            if concentrator and field == "concentrator_files":
                current_files = UPLOADS_META.get(field) or []
                current_total = sum(int(item.get("size", 0)) for item in current_files)
                if len(current_files) >= MAX_CONCENTRATOR_FILES:
                    self.send_json({"error": f"Concentrator accepts at most {MAX_CONCENTRATOR_FILES} input files."}, 413)
                    return
                if current_total + length > MAX_CONCENTRATOR_TOTAL_BYTES:
                    self.send_json({"error": "Combined Concentrator uploads exceed the 40 GiB limit."}, 413)
                    return
            UPLOADS_ACTIVE.add(field)
            UPLOAD_RESERVATIONS[field] = length

        filename = requested_filename
        stored = UPLOADS / f"{uuid.uuid4().hex}_{filename}"
        try:
            try:
                self.read_upload_to_file(stored, length, reservation_key=field)
            except (TimeoutError, ConnectionError, OSError):
                self.close_connection = True
                raise

            meta = {"path": stored, "name": filename, "size": length}
            replaced = []
            with LOCK:
                if concentrator and field == "concentrator_files":
                    current = UPLOADS_META.get(field) or []
                    # Re-check aggregate/count after the body arrives in case another
                    # workflow changed metadata while this request was streaming.
                    current_total = sum(int(item.get("size", 0)) for item in current)
                    if len(current) >= MAX_CONCENTRATOR_FILES or current_total + length > MAX_CONCENTRATOR_TOTAL_BYTES:
                        raise ValueError("Concentrator upload count or aggregate size limit was reached.")
                    current.append(meta)
                    UPLOADS_META[field] = current
                else:
                    old = UPLOADS_META.get(field)
                    UPLOADS_META[field] = meta
                    replaced.append(old)
                if exclusive_source:
                    replaced.append(UPLOADS_META.get(exclusive_source))
                    UPLOADS_META[exclusive_source] = None
                UPLOADS_ACTIVE.discard(field)
                UPLOAD_RESERVATIONS.pop(field, None)
            for previous in replaced:
                if previous and Path(previous["path"]).exists():
                    try:
                        Path(previous["path"]).unlink()
                    except OSError:
                        pass
            self.send_json({"ok": True, "field": field, "name": filename, "size": length})
        except Exception as exc:
            with LOCK:
                UPLOADS_ACTIVE.discard(field)
                UPLOAD_RESERVATIONS.pop(field, None)
            try:
                stored.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                response_status = 408 if isinstance(exc, TimeoutError) else 400
                self.send_json({"error": f"Upload failed: {exc}"}, response_status)
            except OSError:
                self.close_connection = True

    def handle_run(self):
        global PROCESS, RUN_THREAD
        options = self.read_json_body(1024 * 1024)
        if not isinstance(options, dict):
            return
        # Enforce DEMO / DEMO LIMITED CELF caps for RULEST selection stage.
        options = apply_celf_limits(options, module="RULEST")
        if options.get("_license_mode") == "DEMO_LIMITED":
            # Force frequency selection when advanced CELF is locked.
            if str(options.get("select_mode", "")).lower() in {"greedy", "celf"}:
                options["select_mode"] = "frequency"
        with LOCK:
            storage_ok, storage_message, storage_baseline_bytes = storage_preflight()
            if not storage_ok:
                self.send_json({"error": storage_message}, 507)
                return
            if STATE["status"] in ("running", "stopping"):
                self.send_json({"error": "A run is already in progress."}, 409)
                return
            if UPLOADS_ACTIVE:
                self.send_json({"error": "Wait for the active file upload to finish before starting."}, 409)
                return
            if not UPLOADS_META["base"] or not UPLOADS_META["target"]:
                self.send_json({"error": "Upload both BASE and TARGET wordlists first."}, 400)
                return
            run_id = uuid.uuid4().hex[:10]
            run_dir = DATA / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            control_file = run_dir / "control.txt"
            control_file.write_text("", encoding="ascii")
            try:
                cmd, output_name = build_command(options, run_dir)
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
                return
            STATE.update({
                "status": "running", "tool": "rulest", "paused": False, "pause_requested": False, "job_id": run_id, "started_at": time.time(), "finished_at": None,
                "pid": None, "stage": "Starting engine", "stage_detail": "Launching the engine process…",
                "stage_started_at": time.time(), "progress": None, "exit_code": None,
                "logs": [], "log_seq": 0,
                "log_generation": int(STATE.get("log_generation", 0)) + 1,
                "outputs": [], "error": None,
                "control_file": str(control_file), "run_dir": str(run_dir),
            })
            add_log("[WEB] Starting rulest engine…")
            if options.get("_celf_message"):
                add_log(f"[LICENSE] {options.get('_celf_message')}")
            add_log("[WEB] Uploaded files are mounted as BASE / TARGET inputs.")
            add_log("[WEB] " + " ".join(cmd[2:]))
        thread = threading.Thread(target=run_worker, args=(cmd, run_id, run_dir, control_file, "rulest", storage_baseline_bytes), daemon=True)
        with LOCK:
            RUN_THREAD = thread
        thread.start()
        self.send_json({"ok": True, "job_id": run_id, "output": output_name, "tool": "rulest"})

    def handle_ranker_run(self):
        global RUN_THREAD
        data = self.read_json_body(1024 * 1024)
        if not isinstance(data, dict):
            self.send_json({"error": "Invalid Rule Ranker configuration."}, 400)
            return
        mode = data.get("mode")
        options = data.get("options") if isinstance(data.get("options"), dict) else {}
        # Enforce DEMO / DEMO LIMITED CELF caps (strong limits after 3 full runs).
        options = apply_celf_limits(options, module="RULE_RANKER")
        if options.get("_license_mode") == "DEMO_LIMITED":
            add_log(f"[LICENSE] {options.get('_celf_message')}")
        with LOCK:
            storage_ok, storage_message, storage_baseline_bytes = storage_preflight()
            if not storage_ok:
                self.send_json({"error": storage_message}, 507)
                return
            if STATE["status"] in ("running", "stopping"):
                self.send_json({"error": "Another RULEST or Ranker job is already running."}, 409)
                return
            if UPLOADS_ACTIVE:
                self.send_json({"error": "Wait for all active file uploads to finish before starting."}, 409)
                return
            run_id = uuid.uuid4().hex[:10]
            run_dir = DATA / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            try:
                cmd, output_name = build_ranker_command(str(mode), options, run_dir)
            except Exception as exc:
                shutil.rmtree(run_dir, ignore_errors=True)
                self.send_json({"error": str(exc)}, 400)
                return
            STATE.update({
                "status": "running", "tool": "ranker", "paused": False, "pause_requested": False,
                "job_id": run_id, "started_at": time.time(), "finished_at": None, "pid": None,
                "stage": "Rule Ranker · Starting", "stage_detail": f"Launching {mode} workflow…",
                "stage_started_at": time.time(), "progress": None, "exit_code": None,
                "logs": [], "log_seq": 0,
                "log_generation": int(STATE.get("log_generation", 0)) + 1,
                "outputs": [], "error": None, "control_file": None, "run_dir": str(run_dir),
            })
            add_log(f"[WEB] Starting Rule Ranker workflow: {mode}.")
            add_log("[WEB] Uploaded files are temporary and will be removed when the job finishes.")
            add_log("[WEB] " + " ".join(cmd[3:]))
        thread = threading.Thread(target=run_worker, args=(cmd, run_id, run_dir, None, "ranker", storage_baseline_bytes), daemon=True)
        with LOCK:
            RUN_THREAD = thread
        thread.start()
        self.send_json({"ok": True, "job_id": run_id, "output": output_name, "tool": "ranker", "mode": mode})

    def handle_concentrator_run(self):
        global RUN_THREAD
        data = self.read_json_body(1024 * 1024)
        if not isinstance(data, dict):
            self.send_json({"error": "Invalid Concentrator configuration."}, 400)
            return
        mode = str(data.get("mode", ""))
        options = data.get("options") if isinstance(data.get("options"), dict) else {}
        with LOCK:
            storage_ok, storage_message, storage_baseline_bytes = storage_preflight()
            if not storage_ok:
                self.send_json({"error": storage_message}, 507)
                return
            if STATE["status"] in ("running", "stopping"):
                self.send_json({"error": "Another RULEST, Ranker or Concentrator job is already running."}, 409)
                return
            if UPLOADS_ACTIVE:
                self.send_json({"error": "Wait for all active file uploads to finish before starting."}, 409)
                return
            run_id = uuid.uuid4().hex[:10]
            run_dir = DATA / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            try:
                cmd, output_name = build_concentrator_command(mode, options, run_dir)
            except Exception as exc:
                shutil.rmtree(run_dir, ignore_errors=True)
                self.send_json({"error": str(exc)}, 400)
                return
            STATE.update({
                "status": "running", "tool": "concentrator", "paused": False, "pause_requested": False,
                "job_id": run_id, "started_at": time.time(), "finished_at": None, "pid": None,
                "stage": f"Concentrator · {mode.title()}", "stage_detail": "Launching Concentrator workflow…",
                "stage_started_at": time.time(), "progress": None, "exit_code": None,
                "logs": [], "log_seq": 0,
                "log_generation": int(STATE.get("log_generation", 0)) + 1,
                "outputs": [], "error": None, "control_file": None, "run_dir": str(run_dir),
            })
            add_log(f"[WEB] Starting Concentrator workflow: {mode}.")
            add_log("[WEB] Uploaded rule files are temporary and will be removed when the job finishes.")
            add_log("[WEB] " + " ".join(cmd[3:]))
        thread = threading.Thread(target=run_worker, args=(cmd, run_id, run_dir, None, "concentrator", storage_baseline_bytes), daemon=True)
        with LOCK:
            RUN_THREAD = thread
        thread.start()
        self.send_json({"ok": True, "job_id": run_id, "output": output_name, "tool": "concentrator", "mode": mode})

    def handle_concentrator_cancel(self):
        with LOCK:
            if STATE["status"] not in ("running", "stopping") or STATE.get("tool") != "concentrator":
                self.send_json({"error": "There is no active Concentrator job to cancel."}, 409)
                return
            proc = PROCESS
            STATE["status"] = "stopping"
        add_log("[WEB] Cancellation requested for Concentrator. Temporary input files will be cleaned after exit.")
        if proc is not None and proc.poll() is None:
            try:
                if os.name == "nt":
                    proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
                else:
                    os.killpg(proc.pid, signal.SIGINT)
            except Exception:
                try:
                    proc.terminate()
                except OSError:
                    pass
        self.send_json({"ok": True, "action": "cancel"})

    def handle_ranker_cancel(self):
        with LOCK:
            if STATE["status"] not in ("running", "stopping") or STATE.get("tool") != "ranker":
                self.send_json({"error": "There is no active Rule Ranker job to cancel."}, 409)
                return
            proc = PROCESS
            STATE["status"] = "stopping"
        add_log("[WEB] Cancellation requested for Rule Ranker. The process will be interrupted.")
        if proc is not None and proc.poll() is None:
            try:
                if os.name == "nt":
                    proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
                else:
                    os.killpg(proc.pid, signal.SIGINT)
            except Exception:
                try:
                    proc.terminate()
                except OSError:
                    pass
        self.send_json({"ok": True, "action": "cancel"})

    def handle_control(self):
        data = self.read_json_body(16 * 1024)
        if not isinstance(data, dict):
            return
        action = data.get("action")
        command = {"pause": "p", "resume": "r", "stop": "q"}.get(action)
        if command is None:
            self.send_json({"error": "Unsupported control action."}, 400)
            return
        with LOCK:
            if STATE["status"] not in ("running", "stopping") or STATE.get("tool") != "rulest" or not STATE.get("control_file"):
                self.send_json({"error": "There is no active RULEST engine run to control."}, 409)
                return
            path = Path(STATE["control_file"])
            with path.open("a", encoding="ascii") as f:
                f.write(command + "\n")
            if action == "pause":
                STATE["pause_requested"] = True
            elif action == "resume":
                STATE["pause_requested"] = False
            elif action == "stop":
                STATE["status"] = "stopping"
                STATE["pause_requested"] = False
        labels = {"pause": "Pause requested", "resume": "Resume requested", "stop": "Partial-save exit requested"}
        add_log(f"[WEB] {labels[action]}.")
        self.send_json({"ok": True, "action": action})


def stop_active_run_for_shutdown(timeout: float = 15.0):
    """Ask an active engine to stop, then force-stop it if the server exits."""
    global PROCESS, RUN_THREAD
    with LOCK:
        proc = PROCESS
        worker = RUN_THREAD
        active = STATE.get("status") in ("running", "stopping")
        control_file = STATE.get("control_file")
        if active and control_file:
            try:
                with Path(control_file).open("a", encoding="ascii") as stream:
                    stream.write("q\n")
                STATE["status"] = "stopping"
                STATE["pause_requested"] = False
            except OSError:
                pass
        elif active and proc is not None and proc.poll() is None:
            try:
                if os.name == "nt":
                    proc.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
                else:
                    os.killpg(proc.pid, signal.SIGINT)
                STATE["status"] = "stopping"
            except OSError:
                pass
    if active:
        tool_name = str(STATE.get("tool") or "engine").upper()
        add_log(f"[WEB] Web server is shutting down; stopping the active {tool_name} job.")
    if proc is not None and proc.poll() is None:
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=8,
                    )
                else:
                    os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=5)
            except Exception:
                try:
                    if os.name == "nt":
                        proc.kill()
                    else:
                        os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
    if worker is not None and worker.is_alive():
        worker.join(timeout=10)
    # If no worker is running (for example after a previous crash), clean up
    # any remaining temporary files. Never delete inputs while the child lives.
    if worker is None or not worker.is_alive():
        cleanup_uploaded_files(log_message=False)


def discover_lan_ipv4_addresses():
    """Discover private IPv4 addresses suitable for opening the UI on a LAN."""
    found = set()
    probe = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 80))
        found.add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        if probe is not None:
            probe.close()

    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM):
            found.add(item[4][0])
    except OSError:
        pass

    private = []
    for address in found:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 4 and parsed.is_private and not parsed.is_loopback and not parsed.is_link_local:
            private.append(str(parsed))
    return sorted(set(private))


def build_access_urls(host, port, lan_addresses=None):
    """Return browser URLs corresponding to the server bind address."""
    if host in ("0.0.0.0", ""):
        addresses = ["127.0.0.1"]
        addresses.extend(discover_lan_ipv4_addresses() if lan_addresses is None else lan_addresses)
        return [f"http://{address}:{port}" for address in dict.fromkeys(addresses)]
    return [f"http://{host}:{port}"]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Rulest web frontend (LAN-accessible)")
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="Interface to bind (default: 0.0.0.0 for local-network access; use 127.0.0.1 for this PC only)",
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    cleanup_stale_uploaded_files()
    server = RulestHTTPServer((args.host, args.port), Handler)
    actual_port = server.server_address[1]
    print()
    print("  RULEOPS v2.4.8  /  HASHCAT RULE TOOLCHAIN")
    print(f"  Listening on: {args.host}:{actual_port}")
    print(f"  Connection limit: {MAX_CONCURRENT_CONNECTIONS} concurrent clients")
    print(f"  Upload limits: {MAX_UPLOAD_BYTES / 1024**3:.1f} GiB/file, {MAX_TOTAL_UPLOAD_BYTES / 1024**3:.1f} GiB total")
    print(f"  Data quota: {MAX_DATA_STORAGE_BYTES / 1024**3:.1f} GiB; free-space reserve: {MIN_FREE_DISK_BYTES / 1024**3:.1f} GiB")
    print(f"  Login throttling: persistent SQLite database ({SECURITY_DB.name})")
    for url in build_access_urls(args.host, actual_port):
        label = "This PC" if "127.0.0.1" in url else "LAN"
        print(f"  {label}: {url}")
    if args.host in ("0.0.0.0", ""):
        print()
        print("  NETWORK ACCESS / SECURITY")
        print("  A password is required before the panel or API can be used.")
        print("  First visit: create the application password in your browser.")
        print("  Complete first-time setup promptly; the first person to set it becomes admin.")
        print("  HTTP traffic is not encrypted; use a trusted LAN or a VPN/TLS tunnel.")
        print("  Never port-forward this development server to the public internet.")
        print("  For this PC only, start with: python app.py --host 127.0.0.1")
        print("  On Windows, allow Python through the firewall on Private networks only.")
    print()
    print("  Press Ctrl+C to stop the web interface.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("Stopping web interface...")
    finally:
        stop_active_run_for_shutdown()
        server.server_close()
        cleanup_uploaded_files(log_message=False)


if __name__ == "__main__":
    main()
