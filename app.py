#!/usr/bin/env python3
"""RULEOPS: unified local web interface for RULEST, Rule Ranker and Concentrator."""
from __future__ import annotations

import json
import heapq
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
import stat as stat_module
import zipfile
from contextlib import contextmanager
from http.cookies import SimpleCookie
from pathlib import Path, PurePosixPath
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gpu_diagnostics import collect_gpu_diagnostics
ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DATA = ROOT / "runs"
UPLOADS = DATA / "uploads"
RUN_DATASET_MANIFEST = ".ruleops-run.json"
AUTH_FILE = ROOT / "auth.json"


def ensure_runtime_directories() -> None:
    """Create the persistent runtime storage tree inside the project directory."""
    DATA.mkdir(parents=True, exist_ok=True)
    UPLOADS.mkdir(parents=True, exist_ok=True)


# The runs/ tree is intentionally gitignored and therefore absent from clean
# checkouts/archives. Recreate it whenever the application process starts.
ensure_runtime_directories()

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
RUN_STORAGE_MAINTENANCE_LOCK = threading.Lock()
STATE = {
    "status": "idle", "tool": "rulest", "paused": False, "pause_requested": False, "job_id": None, "started_at": None, "finished_at": None,
    "pid": None, "stage": "Waiting for a run", "stage_detail": "Start a run to see the active processing phase.",
    "stage_started_at": None, "progress": None,
    "progress_completed": None, "progress_total": None, "progress_rate": None,
    "progress_rules": None,
    "exit_code": None, "logs": [], "log_seq": 0, "log_generation": 0, "outputs": [],
    "error": None, "control_file": None, "run_dir": None,
}
UPLOADS_META = {
    "base": None, "target": None, "seed": None,
    "ranker_wordlist": None, "ranker_cracked": None, "ranker_rules": None,
    "ranker_source_csv": None, "ranker_source_rules": None, "ranker_analysis_csv": None,
    "concentrator_files": [],
    "rulestripper_base": None, "rulestripper_target": None,
    "minimizer_rules": None, "minimizer_probe": None,
}
RANKER_UPLOAD_FIELDS = {
    "ranker_wordlist", "ranker_cracked", "ranker_rules",
    "ranker_source_csv", "ranker_source_rules", "ranker_analysis_csv",
}
CONCENTRATOR_UPLOAD_FIELDS = {"concentrator_files"}
UTILITY_UPLOAD_FIELDS = {"rulestripper_base", "rulestripper_target", "minimizer_rules", "minimizer_probe"}
# Wordlists and rule files are retained in a reusable library. CSV uploads remain
# temporary because they are workflow-specific and can be re-created cheaply.
LIBRARY_FIELD_CATEGORIES = {
    "base": "wordlists", "target": "wordlists",
    "ranker_wordlist": "wordlists", "ranker_cracked": "wordlists",
    "seed": "rules", "ranker_rules": "rules",
    "ranker_source_rules": "rules", "concentrator_files": "rules",
    "rulestripper_base": "wordlists", "rulestripper_target": "wordlists",
    "minimizer_rules": "rules", "minimizer_probe": "wordlists",
}
LIBRARY_ASSET_ID_RE = re.compile(r"^[a-f0-9]{32}_[A-Za-z0-9._ -]{1,180}$")
MAX_CONCENTRATOR_FILES = 32
MAX_CONCENTRATOR_TOTAL_BYTES = 40 * 1024 * 1024 * 1024
UPLOADS_ACTIVE = set()
UPLOAD_RESERVATIONS = {}  # field -> declared bytes, reserved before reading body
PROCESS = None
RUN_THREAD = None
# Storage Intelligence history is intentionally session-scoped: it records scans and
# cleanup actions since this server process started, without creating another data file.
_STORAGE_INTELLIGENCE_STATE = {
    "last_run_scan": None,
    "last_library_scan": None,
    "activity": [],
}


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
MAX_DATA_STORAGE_BYTES = _env_int("RULEOPS_MAX_DATA_STORAGE_BYTES", 10 * 1024**3)
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
    "topn_seeds": "--topn-seeds",
    "topn_complementary": "--topn-complementary",
    "token_strip": "--token-strip",
    "genetic": "--genetic",
    "exact_recovery": "--exact-recovery",
    "debug": "--debug",
    "profile": "--profile",
}
VALUE_OPTIONS = {
    "device": "--device", "max_depth": "--max-depth", "target_hours": "--target-hours",
    "max_chains": "--max-chains", "bloom_mb": "--bloom-mb",
    "topn_n": "--topn-n", "topn_max_seeds": "--topn-max-seeds",
    "topn_inject_cap": "--topn-inject-cap",
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


def library_category_dir(category: str) -> Path:
    """Return a non-symlink persistent folder for a validated asset category."""
    if category not in {"wordlists", "rules"}:
        raise ValueError("Unsupported library category.")
    library_root = DATA / "library"
    folder = library_root / category
    # Do not let a pre-created symlink redirect uploads or library browsing outside
    # RULEOPS data storage.
    if library_root.is_symlink() or folder.is_symlink():
        raise ValueError("The reusable input library path must not be a symbolic link.")
    return folder


def _safe_library_filename(name: str) -> bool:
    """Accept generated asset IDs and safe legacy names, never path components."""
    return (
        isinstance(name, str)
        and 1 <= len(name) <= 220
        and name not in {".", ".."}
        and Path(name).name == name
        and "\\" not in name
        and bool(re.fullmatch(r"[A-Za-z0-9._ -]{1,220}", name))
    )


# NumPy and JSON files in the input library are treated as internal/metadata
# artifacts, never as selectable wordlists or rule files. Ranker's fingerprint
# cache names vary with source names and max_len, so filter by final extension
# instead of depending on one exact cache filename pattern.
LIBRARY_NON_INPUT_EXTENSIONS = {".npy", ".json"}


def _is_library_derived_cache(name: str) -> bool:
    """Return True for Ranker caches and other non-input NumPy/JSON artifacts."""
    return Path(str(name)).suffix.lower() in LIBRARY_NON_INPUT_EXTENSIONS


def _library_asset_display_name(asset_id: str) -> str:
    """Recover the user-facing filename from a generated ID or legacy filename."""
    if LIBRARY_ASSET_ID_RE.fullmatch(str(asset_id)):
        return str(asset_id).split("_", 1)[1]
    return str(asset_id)


def _library_digest_index_path() -> Path:
    """Return the private digest-index path outside selectable asset folders."""
    root = DATA / "library"
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise ValueError("The reusable input library path must not be a symbolic link.")
    index_path = root / ".asset_hashes.sqlite3"
    if index_path.is_symlink():
        raise ValueError("The reusable input digest index must not be a symbolic link.")
    if index_path.exists() and not index_path.is_file():
        raise ValueError("The reusable input digest index must be a regular file.")
    return index_path


def _sha256_file(path: Path) -> str:
    """Hash a file incrementally so duplicate detection never loads it into RAM."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _library_asset_sha256(category: str, path: Path, metadata=None, known_digest: str | None = None) -> str:
    """Get a cached content digest, invalidating it whenever size/mtime changes."""
    if category not in {"wordlists", "rules"}:
        raise ValueError("Unsupported library category.")
    metadata = metadata or os.stat(str(path), follow_symlinks=False)
    size = int(metadata.st_size)
    mtime_ns = int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)))
    ctime_ns = int(getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)))
    inode = int(getattr(metadata, "st_ino", 0))
    index_path = _library_digest_index_path()
    with sqlite3.connect(str(index_path), timeout=15) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS asset_digests (
                   category TEXT NOT NULL,
                   asset_id TEXT NOT NULL,
                   size INTEGER NOT NULL,
                   mtime_ns INTEGER NOT NULL,
                   ctime_ns INTEGER NOT NULL,
                   inode INTEGER NOT NULL,
                   sha256 TEXT NOT NULL,
                   PRIMARY KEY(category, asset_id)
               )"""
        )
        row = connection.execute(
            "SELECT size, mtime_ns, ctime_ns, inode, sha256 FROM asset_digests WHERE category=? AND asset_id=?",
            (category, path.name),
        ).fetchone()
        if (row and int(row[0]) == size and int(row[1]) == mtime_ns
                and int(row[2]) == ctime_ns and int(row[3]) == inode):
            return str(row[4])
        digest = known_digest or _sha256_file(path)
        connection.execute(
            """INSERT INTO asset_digests(category, asset_id, size, mtime_ns, ctime_ns, inode, sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(category, asset_id) DO UPDATE SET
                   size=excluded.size, mtime_ns=excluded.mtime_ns,
                   ctime_ns=excluded.ctime_ns, inode=excluded.inode, sha256=excluded.sha256""",
            (category, path.name, size, mtime_ns, ctime_ns, inode, digest),
        )
        return digest


def _find_duplicate_library_asset(category: str, display_name: str, size: int, digest: str):
    """Find byte-identical assets with the same visible filename and size.

    Matching by digest avoids hiding two different wordlists that happen to have
    the same name and size. Hashes for old assets are cached in SQLite, so each
    existing large file is read at most once unless it changes.
    """
    folder = library_category_dir(category)
    try:
        entries = sorted(folder.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    for item in entries:
        try:
            if not _safe_library_filename(item.name) or _is_library_derived_cache(item.name):
                continue
            if _library_asset_display_name(item.name).casefold() != display_name.casefold():
                continue
            metadata = os.lstat(str(item))
            if not stat_module.S_ISREG(metadata.st_mode) or int(metadata.st_size) != int(size):
                continue
            if _library_asset_sha256(category, item, metadata) == digest:
                return item
        except (OSError, ValueError, sqlite3.Error):
            continue
    return None


def list_library_assets() -> dict:
    """List reusable files and collapse byte-identical duplicate uploads.

    The content index is consulted only for groups sharing the same visible name
    and size. Large unique wordlists therefore incur no extra disk reads during
    menu refresh. Different content is always kept selectable and labelled with
    a short ID suffix so same-name variants remain distinguishable.
    """
    result = {"wordlists": [], "rules": []}
    for category in result:
        folder = library_category_dir(category)
        try:
            entries = list(folder.iterdir())
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            continue

        groups = {}
        for item in entries:
            try:
                if not _safe_library_filename(item.name) or _is_library_derived_cache(item.name):
                    continue
                # os.lstat is Python 3.8-compatible and never follows symlinks.
                metadata = os.lstat(str(item))
                if not stat_module.S_ISREG(metadata.st_mode):
                    continue
                display_name = _library_asset_display_name(item.name)
                record = {
                    "id": item.name, "name": display_name, "size": metadata.st_size,
                    "modified": int(metadata.st_mtime),
                }
                key = (display_name.casefold(), int(metadata.st_size))
                groups.setdefault(key, []).append((item, metadata, record))
            except OSError:
                continue

        for group in groups.values():
            # No comparison is needed unless entries would look duplicated in UI.
            candidates = sorted(group, key=lambda row: (row[2]["modified"], row[2]["id"]))
            unique = []
            seen_digests = set()
            if len(candidates) == 1:
                unique.append(candidates[0][2])
            else:
                for item, metadata, record in candidates:
                    try:
                        digest = _library_asset_sha256(category, item, metadata)
                    except (OSError, ValueError, sqlite3.Error):
                        # If hashing fails, don't hide a potentially distinct file.
                        unique.append(record)
                        continue
                    if digest not in seen_digests:
                        seen_digests.add(digest)
                        unique.append(record)
            if len(unique) > 1:
                for index, record in enumerate(unique, start=1):
                    short_id = record["id"][:8]
                    record["label"] = f"{record['name']} · variant {index} ({short_id})"
            result[category].extend(unique)
        result[category].sort(key=lambda entry: (entry["name"].casefold(), entry["id"]))
    return result


def search_library_assets(query: str, limit: int = 300) -> dict:
    """Search reusable-library and run/work-folder files by filename.

    The query is compared only with each file's basename. Full absolute paths
    are returned as display metadata so same-named files can be distinguished.
    Run-folder traversal never follows symlinks and deliberately excludes the
    uploads/ and library/ roots.
    """
    query = str(query or "").strip()
    if not query or len(query) > 180:
        raise ValueError("Enter a filename search between 1 and 180 characters.")
    needle = query.casefold()
    results = []
    for category in ("wordlists", "rules"):
        folder = library_category_dir(category)
        try:
            root = folder.resolve(strict=True)
            entries = sorted(folder.iterdir(), key=lambda item: item.name.casefold())
        except FileNotFoundError:
            continue
        except OSError:
            continue
        for item in entries:
            try:
                if not _safe_library_filename(item.name) or _is_library_derived_cache(item.name):
                    continue
                metadata = os.lstat(str(item))
                if not stat_module.S_ISREG(metadata.st_mode):
                    continue
                display_name = _library_asset_display_name(item.name)
                # Search is intentionally filename-only. The full path is output
                # metadata, not part of the match expression.
                if needle not in display_name.casefold():
                    continue
                resolved = item.resolve(strict=True)
                if resolved.parent != root:
                    continue
                results.append({
                    "id": item.name,
                    "source": "library",
                    "category": category,
                    "name": display_name,
                    "path": str(resolved),
                    "size": int(metadata.st_size),
                    "modified": int(metadata.st_mtime),
                })
            except (OSError, ValueError):
                continue

    for run_directory in _iter_run_directories():
        try:
            run_root = run_directory.resolve(strict=True)
            data_root = DATA.resolve(strict=True)
            if run_root.parent != data_root or run_directory.is_symlink():
                continue
        except (OSError, ValueError):
            continue

        def raise_walk_error(error):
            raise error

        try:
            for current_root, directory_names, file_names in os.walk(
                run_root, topdown=True, followlinks=False, onerror=raise_walk_error
            ):
                current_path = Path(current_root)
                directory_names[:] = sorted(
                    name for name in directory_names
                    if not (current_path / name).is_symlink()
                )
                for filename in sorted(file_names, key=str.casefold):
                    if filename == RUN_DATASET_MANIFEST or needle not in filename.casefold():
                        continue
                    candidate = current_path / filename
                    try:
                        metadata = candidate.lstat()
                        if not stat_module.S_ISREG(metadata.st_mode):
                            continue
                        resolved = candidate.resolve(strict=True)
                        if os.path.commonpath((str(run_root), str(resolved))) != str(run_root):
                            continue
                        relative_path = candidate.relative_to(run_root).as_posix()
                        results.append({
                            "id": relative_path,
                            "source": "run",
                            "category": "work folder",
                            "run_id": run_directory.name,
                            "relative_path": relative_path,
                            "name": filename,
                            "path": str(resolved),
                            "size": int(metadata.st_size),
                            "modified": int(metadata.st_mtime),
                        })
                    except (OSError, ValueError):
                        continue
        except OSError:
            # A run folder may be concurrently removed or have permissions
            # changed. Other folders remain searchable.
            continue

    results.sort(key=lambda row: (row["name"].casefold(), row["source"], row["category"], row["id"]))
    total = len(results)
    return {"query": query, "results": results[:limit], "total": total, "truncated": total > limit}


def open_run_folder_file(run_id: str, relative_path: str):
    """Open a regular file inside one direct runs/ child without following symlinks.

    Returns (file_descriptor, stat_result, absolute_path). The descriptor is
    opened with O_NOFOLLOW and, on platforms with dir_fd support, each path
    component is traversed relative to an already-open directory descriptor.
    """
    run_id = str(run_id or "")
    relative_path = str(relative_path or "")
    if (
        not run_id or "\x00" in run_id
        or run_id in {".", "..", "uploads", "library"}
        or "/" in run_id or "\\" in run_id
    ):
        raise ValueError("Invalid work-folder identifier.")
    relative = PurePosixPath(relative_path)
    if (
        not relative_path or relative.is_absolute() or "\\" in relative_path
        or "\x00" in relative_path or ":" in relative_path
        or relative.as_posix() != relative_path
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("Invalid work-folder file path.")

    directory = DATA / run_id
    try:
        directory_metadata = directory.lstat()
        if not stat_module.S_ISDIR(directory_metadata.st_mode):
            raise ValueError("Work folder was not found.")
        run_root = directory.resolve(strict=True)
        data_root = DATA.resolve(strict=True)
        if run_root.parent != data_root:
            raise ValueError("Work folder is outside RULEOPS run storage.")
    except (OSError, RuntimeError) as exc:
        raise ValueError("Work folder was not found.") from exc

    parts = list(relative.parts)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory_flag = flags | getattr(os, "O_DIRECTORY", 0)
    descriptor = None
    opened_directories = []
    try:
        if os.open in getattr(os, "supports_dir_fd", set()):
            current_fd = os.open(str(run_root), directory_flag)
            opened_directories.append(current_fd)
            for component in parts[:-1]:
                current_fd = os.open(component, directory_flag, dir_fd=current_fd)
                opened_directories.append(current_fd)
            descriptor = os.open(parts[-1], flags, dir_fd=current_fd)
            candidate = run_root.joinpath(*parts)
        else:
            candidate = run_root.joinpath(*parts)
            cursor = run_root
            for component in parts[:-1]:
                cursor = cursor / component
                if cursor.is_symlink() or not cursor.is_dir():
                    raise ValueError("Work-folder path contains an unsafe directory.")
            if candidate.is_symlink():
                raise ValueError("Symbolic-link files cannot be downloaded.")
            descriptor = os.open(str(candidate), flags)

        metadata = os.fstat(descriptor)
        if not stat_module.S_ISREG(metadata.st_mode):
            raise ValueError("Requested work-folder item is not a regular file.")
        resolved = candidate.resolve(strict=True)
        if os.path.commonpath((str(run_root), str(resolved))) != str(run_root):
            raise ValueError("Requested file is outside its work folder.")
        return descriptor, metadata, resolved
    except (OSError, RuntimeError) as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise ValueError("Work-folder file was not found or is not safe to access.") from exc
    finally:
        for opened_fd in reversed(opened_directories):
            try:
                os.close(opened_fd)
            except OSError:
                pass


class _HTTPZipSink:
    """Minimal non-seekable ZIP destination that streams to an HTTP/1.0 socket."""
    def __init__(self, stream):
        self.stream = stream

    def write(self, payload):
        self.stream.write(payload)
        return len(payload)

    def flush(self):
        self.stream.flush()


def _library_file_signature(metadata) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
        int(getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000))),
        int(metadata.st_mode),
    )


def _duplicate_record_key(record: dict) -> tuple[str, ...]:
    """Return a stable, source-aware key for a library or work-folder file."""
    if record.get("source") == "run":
        return ("run", str(record["run_id"]), str(record["relative_path"]))
    return ("library", str(record["category"]), str(record["id"]))


def _hash_work_duplicate_record(record: dict) -> str:
    """Hash a work-folder file through the no-follow descriptor helper."""
    descriptor, metadata, resolved = open_run_folder_file(record["run_id"], record["relative_path"])
    try:
        if _library_file_signature(metadata) != record["_signature"]:
            raise RuntimeError("Work-folder file changed during duplicate scanning.")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after_fd = os.fstat(stream.fileno())
        after_path = resolved.lstat()
        if (_library_file_signature(after_fd) != record["_signature"]
                or _library_file_signature(after_path) != record["_signature"]):
            raise RuntimeError("Work-folder file changed during duplicate scanning.")
        return digest.hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _duplicate_groups_for_records(records: list[dict]) -> tuple[dict, dict, list[dict]]:
    """Group files by visible filename and by confirmed identical content.

    Library assets retain the existing same-category checksum matching across
    different names. Work-folder files are hashed only when their filename
    collides with another scanned file, keeping large run archives practical.
    """
    name_groups: dict[str, list[int]] = {}
    content_groups: dict[tuple, list[int]] = {}

    for index, record in enumerate(records):
        name_groups.setdefault(record["name"].casefold(), []).append(index)
        if record.get("source") == "library" and record.get("sha256"):
            key = ("library", record["category"], record["sha256"])
            content_groups.setdefault(key, []).append(index)

    # For name-collision candidates, checksum equality distinguishes exact
    # redundant copies from same-name files that merely need human review.
    for visible_name, indices in name_groups.items():
        if len(indices) < 2:
            continue
        for index in indices:
            record = records[index]
            if record.get("source") == "run" and not record.get("sha256"):
                try:
                    record["sha256"] = _hash_work_duplicate_record(record)
                except (OSError, ValueError, RuntimeError):
                    record["deletable"] = False
                    record["protected_reason"] = "Could not verify file contents; rescan before deleting."
        for index in indices:
            digest = records[index].get("sha256")
            if digest:
                key = ("same-name-content", visible_name, digest)
                content_groups.setdefault(key, []).append(index)

    parent = list(range(len(records)))
    rank = [0] * len(records)

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left, right):
        a, b = find(left), find(right)
        if a == b:
            return
        if rank[a] < rank[b]:
            a, b = b, a
        parent[b] = a
        if rank[a] == rank[b]:
            rank[a] += 1

    for mapping in (name_groups, content_groups):
        for indices in mapping.values():
            if len(indices) > 1:
                for other in indices[1:]:
                    union(indices[0], other)

    grouped = {}
    for index in range(len(records)):
        grouped.setdefault(find(index), []).append(index)
    return name_groups, content_groups, [indices for indices in grouped.values() if len(indices) > 1]


def _scan_library_duplicate_records() -> tuple[list[dict], list[dict]]:
    """Scan reusable library and saved work folders for name/content duplicates."""
    records = []
    active_library_assets = _active_library_assets()

    # Reusable library files: hash/cache every eligible asset, as before.
    for category in ("wordlists", "rules"):
        folder = library_category_dir(category)
        try:
            library_root = folder.resolve(strict=True)
            entries = sorted(folder.iterdir(), key=lambda item: item.name.casefold())
        except FileNotFoundError:
            continue
        except OSError:
            continue
        for item in entries:
            try:
                if not _safe_library_filename(item.name) or _is_library_derived_cache(item.name):
                    continue
                metadata = os.lstat(str(item))
                if not stat_module.S_ISREG(metadata.st_mode):
                    continue
                resolved = item.resolve(strict=True)
                if resolved.parent != library_root:
                    continue
                digest = _library_asset_sha256(category, item, metadata)
                is_active = (category, item.name) in active_library_assets
                records.append({
                    "source": "library",
                    "id": item.name,
                    "category": category,
                    "name": _library_asset_display_name(item.name),
                    "path": str(resolved),
                    "size": int(metadata.st_size),
                    "modified": int(metadata.st_mtime),
                    "sha256": digest,
                    "deletable": not is_active,
                    "protected_reason": "Currently mounted in a tool input." if is_active else "",
                    "_signature": _library_file_signature(metadata),
                })
            except (OSError, ValueError, sqlite3.Error):
                # An unreadable or changing file must never become a deletion candidate.
                continue

    # Completed work folders: include nested regular files, never follow links.
    current_run_root = None
    if STATE.get("run_dir"):
        try:
            current_run_root = Path(STATE["run_dir"]).resolve(strict=True)
        except (OSError, RuntimeError):
            current_run_root = None

    for run_directory in _iter_run_directories():
        try:
            run_root = run_directory.resolve(strict=True)
            if run_root.parent != DATA.resolve(strict=True) or run_directory.is_symlink():
                continue
        except (OSError, RuntimeError):
            continue
        is_current_run = current_run_root is not None and run_root == current_run_root

        def raise_walk_error(error):
            raise error

        try:
            for current_root, directory_names, file_names in os.walk(
                run_root, topdown=True, followlinks=False, onerror=raise_walk_error
            ):
                current_path = Path(current_root)
                safe_directories = []
                for name in sorted(directory_names, key=str.casefold):
                    child = current_path / name
                    try:
                        child_stat = child.lstat()
                        if stat_module.S_ISDIR(child_stat.st_mode) and not stat_module.S_ISLNK(child_stat.st_mode):
                            safe_directories.append(name)
                    except OSError:
                        continue
                directory_names[:] = safe_directories

                for filename in sorted(file_names, key=str.casefold):
                    if filename == RUN_DATASET_MANIFEST:
                        continue
                    candidate = current_path / filename
                    try:
                        relative_path = candidate.relative_to(run_root).as_posix()
                        descriptor, metadata, resolved = open_run_folder_file(run_directory.name, relative_path)
                        os.close(descriptor)
                        if not stat_module.S_ISREG(metadata.st_mode):
                            continue
                        records.append({
                            "source": "run",
                            "id": relative_path,
                            "category": "work folder",
                            "run_id": run_directory.name,
                            "relative_path": relative_path,
                            "name": filename,
                            "path": str(resolved),
                            "size": int(metadata.st_size),
                            "modified": int(metadata.st_mtime),
                            "sha256": None,
                            "deletable": not is_current_run,
                            "protected_reason": "This is the currently selected run folder." if is_current_run else "",
                            "_signature": _library_file_signature(metadata),
                        })
                    except (OSError, ValueError, RuntimeError):
                        continue
        except OSError:
            # A work folder may be concurrently removed or have permissions changed.
            continue

    records.sort(key=lambda row: (row["name"].casefold(), row["source"], row["path"]))
    name_groups, content_groups, grouped_indices = _duplicate_groups_for_records(records)

    # Suggest removal only for confirmed byte-identical copies. Prefer a protected
    # current/active file as the retained representative, otherwise keep newest.
    suggested_delete = set()
    for indices in content_groups.values():
        unique_indices = sorted(set(indices))
        if len(unique_indices) < 2:
            continue
        keeper = min(
            unique_indices,
            key=lambda i: (
                bool(records[i].get("deletable", True)),
                -int(records[i]["modified"]),
                records[i]["path"].casefold(),
            ),
        )
        suggested_delete.update(
            i for i in unique_indices if i != keeper and records[i].get("deletable", True)
        )

    groups = []
    for indices in grouped_indices:
        reasons = set()
        member_set = set(indices)
        if any(len(bucket) > 1 and not member_set.isdisjoint(bucket) for bucket in name_groups.values()):
            reasons.add("same filename")
        if any(len(bucket) > 1 and not member_set.isdisjoint(bucket) for bucket in content_groups.values()):
            reasons.add("identical content")
        members = []
        for index in sorted(indices, key=lambda i: (records[i]["name"].casefold(), records[i]["path"].casefold())):
            record = dict(records[index])
            record["suggest_delete"] = index in suggested_delete
            record["match"] = (
                "identical content" if record.get("sha256") and any(
                    len(bucket) > 1 and index in bucket for bucket in content_groups.values()
                )
                else "same filename; contents differ" if record.get("sha256")
                else "same filename; contents unverified"
            )
            members.append(record)
        categories = sorted({records[index]["category"] for index in indices})
        sources = sorted({records[index]["source"] for index in indices})
        groups.append({
            "category": categories[0] if len(categories) == 1 else "library and work folders",
            "sources": sources,
            "reasons": sorted(reasons),
            "files": members,
        })

    groups.sort(key=lambda group: (group["category"], group["files"][0]["name"].casefold()))
    return records, groups


def _record_storage_activity(action: str, detail: str = "", bytes_reclaimed: int = 0) -> None:
    """Record a compact, in-memory storage event for the Intelligence panel."""
    event = {
        "action": str(action)[:80],
        "detail": str(detail)[:220],
        "bytes_reclaimed": max(0, int(bytes_reclaimed or 0)),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with LOCK:
        activity = _STORAGE_INTELLIGENCE_STATE.setdefault("activity", [])
        activity.insert(0, event)
        del activity[8:]


def _set_storage_scan_snapshot(key: str, snapshot: dict) -> None:
    with LOCK:
        _STORAGE_INTELLIGENCE_STATE[key] = dict(snapshot)


def _invalidate_storage_scan_snapshots() -> None:
    """Mark scan-derived cleanup counts stale after any destructive operation."""
    with LOCK:
        _STORAGE_INTELLIGENCE_STATE["last_run_scan"] = None
        _STORAGE_INTELLIGENCE_STATE["last_library_scan"] = None


def scan_library_duplicates() -> dict:
    """Scan reusable library and completed work folders for duplicates."""
    with _run_storage_maintenance():
        records, groups = _scan_library_duplicate_records()
    safe_groups = []
    suggested = 0
    for group in groups:
        files = []
        for record in group["files"]:
            suggested += int(bool(record["suggest_delete"]))
            files.append({key: value for key, value in record.items() if key != "_signature"})
        safe_groups.append({**group, "files": files})
    suggested_bytes = sum(
        int(item.get("size", 0))
        for group in safe_groups for item in group["files"]
        if item.get("suggest_delete")
    )
    result = {
        "scanned_files": len(records),
        "scanned_library_files": sum(1 for item in records if item["source"] == "library"),
        "scanned_work_files": sum(1 for item in records if item["source"] == "run"),
        "duplicate_groups": safe_groups,
        "duplicate_group_count": len(safe_groups),
        "suggested_delete_count": suggested,
        "suggested_delete_bytes": suggested_bytes,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _set_storage_scan_snapshot("last_library_scan", {
        "scanned_at": result["scanned_at"],
        "duplicate_group_count": result["duplicate_group_count"],
        "same_name_review_groups": sum(1 for group in safe_groups if "same filename" in group.get("reasons", [])),
        "suggested_delete_count": suggested,
        "suggested_delete_bytes": suggested_bytes,
        "scanned_files": result["scanned_files"],
    })
    _record_storage_activity(
        "Library + work duplicate scan",
        f"Reviewed {len(records):,} files · {len(safe_groups):,} duplicate group(s)",
    )
    return result

def _active_library_assets() -> set[tuple[str, str]]:
    active = set()
    for value in UPLOADS_META.values():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, dict) or not item.get("library"):
                continue
            category = item.get("category")
            asset_id = item.get("asset_id")
            if category in {"wordlists", "rules"} and isinstance(asset_id, str):
                active.add((category, asset_id))
    return active


def _verify_duplicate_record(record: dict) -> tuple[Path, str]:
    """Reopen a scanned asset safely and verify its identity and content hash."""
    if record.get("source") == "run":
        descriptor, metadata, resolved = open_run_folder_file(record["run_id"], record["relative_path"])
        try:
            if _library_file_signature(metadata) != record["_signature"]:
                raise RuntimeError("A selected work-folder file changed after scanning. Run the scan again.")
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = None
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
                after_fd = os.fstat(stream.fileno())
            after_path = resolved.lstat()
            if (_library_file_signature(after_fd) != record["_signature"]
                    or _library_file_signature(after_path) != record["_signature"]):
                raise RuntimeError("A selected work-folder file changed after scanning. Run the scan again.")
            return resolved, digest.hexdigest()
        finally:
            if descriptor is not None:
                os.close(descriptor)

    path = resolve_library_asset(record["category"], record["id"])
    metadata = os.lstat(str(path))
    if _library_file_signature(metadata) != record["_signature"]:
        raise RuntimeError("A selected file changed after scanning. Run the duplicate scan again.")
    digest = _library_asset_sha256(record["category"], path, metadata)
    if digest != record["sha256"]:
        raise RuntimeError("A selected file checksum changed after scanning. Run the duplicate scan again.")
    return path, digest


def delete_selected_library_assets(items: list[dict]) -> dict:
    """Delete checked library/work files after a fresh duplicate scan and safety checks."""
    if not isinstance(items, list) or not items or len(items) > 300:
        raise ValueError("Select between 1 and 300 duplicate files to delete.")

    selected = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("The selected file list is invalid.")
        source = item.get("source", "library")
        if source == "library":
            category = item.get("category")
            asset_id = item.get("asset_id")
            if category not in {"wordlists", "rules"} or not _safe_library_filename(asset_id):
                raise ValueError("One of the selected library files is invalid.")
            key = ("library", category, asset_id)
        elif source == "run":
            run_id = item.get("run_id")
            relative_path = item.get("relative_path")
            # Reuse the no-follow resolver for strict identifier/path validation.
            descriptor, _metadata, _resolved = open_run_folder_file(run_id, relative_path)
            os.close(descriptor)
            key = ("run", str(run_id), str(relative_path))
        else:
            raise ValueError("One of the selected file sources is invalid.")
        selected.add(key)
    if len(selected) != len(items):
        raise ValueError("The selection contains duplicate file entries.")

    deleted = []
    failures = []
    with _run_storage_maintenance():
        records, duplicate_groups = _scan_library_duplicate_records()
        by_key = {_duplicate_record_key(record): record for record in records}
        duplicate_keys = {
            _duplicate_record_key(record)
            for group in duplicate_groups for record in group["files"]
        }
        if not selected.issubset(duplicate_keys):
            raise ValueError("Only files listed in the latest duplicate scan can be deleted.")
        missing = selected.difference(by_key)
        if missing:
            raise ValueError("One or more selected files no longer exist or could not be verified. Scan again.")
        protected = [by_key[key] for key in selected if not by_key[key].get("deletable", True)]
        if protected:
            raise RuntimeError(protected[0].get("protected_reason") or "One or more selected files are protected.")

        name_groups, content_groups, _grouped = _duplicate_groups_for_records(records)
        for name, indices in name_groups.items():
            keys = {_duplicate_record_key(records[index]) for index in indices}
            selected_in_group = selected.intersection(keys)
            if len(keys) > 1 and selected_in_group and len(selected_in_group) == len(keys):
                raise ValueError("At least one file with each duplicated filename must remain. Uncheck one copy and try again.")
        for content_key, indices in content_groups.items():
            keys = {_duplicate_record_key(records[index]) for index in indices}
            selected_in_group = selected.intersection(keys)
            if len(keys) > 1 and selected_in_group and len(selected_in_group) == len(keys):
                raise ValueError("At least one byte-identical copy must remain. Uncheck one copy and try again.")

        # Revalidate selected files and every survivor that protects a name/content group.
        verify_keys = set(selected)
        for mapping in (name_groups, content_groups):
            for indices in mapping.values():
                keys = {_duplicate_record_key(records[index]) for index in indices}
                if selected.intersection(keys):
                    verify_keys.update(keys - selected)

        verified_paths = {}
        verified_hashes = {}
        for key in verify_keys:
            record = by_key[key]
            path, digest = _verify_duplicate_record(record)
            if record.get("sha256") and digest != record["sha256"]:
                raise RuntimeError("A selected file checksum changed after scanning. Run the scan again.")
            verified_paths[key] = path
            verified_hashes[key] = digest

        selected_library = {
            (key[1], key[2]) for key in selected if key[0] == "library"
        }
        with LOCK:
            if STATE.get("status") in ("running", "stopping"):
                raise RuntimeError("Files cannot be deleted while a job is active.")
            if UPLOADS_ACTIVE or UPLOAD_RESERVATIONS:
                raise RuntimeError("Wait for active uploads to finish before deleting files.")
            in_use = selected_library.intersection(_active_library_assets())
            if in_use:
                raise RuntimeError("One or more selected library files are currently mounted in a tool input. Unselect them and try again.")
            current_run_dir = None
            if STATE.get("run_dir"):
                try:
                    current_run_dir = Path(STATE["run_dir"]).resolve()
                except OSError:
                    current_run_dir = None
            for key in sorted(selected):
                path = verified_paths[key]
                if key[0] == "run":
                    run_root = (DATA / key[1]).resolve(strict=True)
                    if current_run_dir is not None and run_root == current_run_dir:
                        raise RuntimeError("The currently selected run folder is protected from file deletion.")
                try:
                    path.unlink()
                except OSError as exc:
                    failures.append({"source": key[0], "id": key[-1], "error": type(exc).__name__})
                    continue
                record = by_key[key]
                deleted.append({
                    "source": key[0],
                    "category": record["category"],
                    "id": record["id"],
                    "run_id": record.get("run_id"),
                    "relative_path": record.get("relative_path"),
                    "name": record["name"],
                    "path": record["path"],
                })
                if key[0] == "library":
                    try:
                        index_path = _library_digest_index_path()
                        with sqlite3.connect(str(index_path), timeout=15) as connection:
                            connection.execute(
                                "DELETE FROM asset_digests WHERE category=? AND asset_id=?",
                                (key[1], key[2]),
                            )
                    except sqlite3.Error:
                        pass

    deleted_paths = {item.get("path") for item in deleted}
    deleted_bytes = sum(
        int(record.get("size", 0)) for record in (by_key.values() if "by_key" in locals() else [])
        if record.get("path") in deleted_paths
    )
    if deleted:
        _invalidate_storage_scan_snapshots()
    add_log(f"[WEB] Duplicate cleanup removed {len(deleted)} selected library/work file(s).")
    if deleted:
        _record_storage_activity(
            "Duplicate files removed",
            f"Deleted {len(deleted):,} selected library/work file(s)",
            deleted_bytes,
        )
    return {
        "ok": True, "deleted": deleted, "deleted_count": len(deleted),
        "requested_count": len(selected), "failures": failures,
    }

def resolve_library_asset(category: str, asset_id: str) -> Path:
    """Resolve a library ID/name to a regular file strictly inside its folder."""
    if (
        category not in {"wordlists", "rules"}
        or not _safe_library_filename(asset_id)
        or _is_library_derived_cache(asset_id)
    ):
        raise ValueError("The selected library item is invalid.")
    folder = library_category_dir(category)
    try:
        root = folder.resolve(strict=True)
        candidate = folder / asset_id
        if candidate.is_symlink() or candidate.parent.resolve(strict=True) != root or not candidate.is_file():
            raise ValueError("The selected library item no longer exists.")
        return candidate
    except FileNotFoundError as exc:
        raise ValueError("The selected library item no longer exists.") from exc


def upload_meta_for_library_asset(category: str, asset_id: str) -> dict:
    path = resolve_library_asset(category, asset_id)
    stat = path.stat()
    return {
        "path": path, "name": _library_asset_display_name(path.name), "size": stat.st_size,
        "library": True, "asset_id": path.name, "category": category,
        "sha256": _library_asset_sha256(category, path, stat),
        "file_signature": _library_file_signature(stat),
    }


def remove_temporary_upload(meta):
    """Remove only an upload-session file; never delete a reusable library asset."""
    if not isinstance(meta, dict) or meta.get("library"):
        return False
    raw_path = meta.get("path")
    if not raw_path:
        return False
    try:
        path = Path(raw_path)
        if path.is_symlink() or path.parent.resolve() != UPLOADS.resolve():
            return False
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


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
    """Yield run directories only, preserving uploads/, library/ and symlinks."""
    if not DATA.exists():
        return
    try:
        entries = sorted(DATA.iterdir(), key=lambda item: item.name.lower())
    except OSError:
        return
    for entry in entries:
        if entry.name in {UPLOADS.name, "library"}:
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
    if RUN_STORAGE_MAINTENANCE_LOCK.locked():
        return False, "Run storage is being scanned or cleaned up. Retry after the operation finishes.", 0
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
    """Summarize run folders; uploads/ and the reusable library are excluded."""
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
            "library_preserved": True,
        }


@contextmanager
def _run_storage_maintenance():
    """Serialize scans/deletes and prevent a new engine run during maintenance."""
    if not RUN_STORAGE_MAINTENANCE_LOCK.acquire(blocking=False):
        raise RuntimeError("Another run-storage scan or cleanup operation is already in progress.")
    try:
        with LOCK:
            _assert_run_storage_cleanup_idle()
        yield
    finally:
        RUN_STORAGE_MAINTENANCE_LOCK.release()


def _assert_run_storage_cleanup_idle() -> None:
    """Prevent storage scans/deletes from racing active engines or uploads."""
    if STATE.get("status") in ("running", "stopping"):
        raise RuntimeError("Run storage cannot be scanned or cleaned up while a job is running or stopping.")
    if UPLOADS_ACTIVE:
        raise RuntimeError("Wait for active uploads to finish before scanning or deleting run folders.")


def _run_input_metadata(tool: str, mode: str) -> list[dict]:
    """Return selected input slots in command-line order for run identity."""
    if tool == "rulest":
        fields = ["base", "target", "seed"]
    elif tool == "ranker" and mode == "rank":
        fields = ["ranker_wordlist", "ranker_rules", "ranker_cracked"]
    elif tool == "ranker" and mode == "optimize":
        source = "ranker_source_csv" if UPLOADS_META.get("ranker_source_csv") else "ranker_source_rules"
        fields = [source, "ranker_wordlist", "ranker_cracked"]
    elif tool == "ranker" and mode == "analyze":
        fields = ["ranker_analysis_csv"]
    elif tool == "concentrator":
        fields = ["concentrator_files"]
    elif tool == "rulestripper":
        fields = ["rulestripper_base", "rulestripper_target"]
    elif tool == "minimizer":
        fields = ["minimizer_rules", "minimizer_probe"]
    else:
        return []

    selected = []
    for field in fields:
        value = UPLOADS_META.get(field)
        if field == "concentrator_files":
            selected.extend(item for item in (value or []) if isinstance(item, dict))
        elif isinstance(value, dict):
            selected.append(value)
    return selected


def _stable_run_input_record(meta: dict, slot: int) -> dict:
    """Build a content identity for one selected dataset without loading it into RAM."""
    raw_path = meta.get("path")
    if not raw_path:
        raise ValueError("A selected run input has no file path.")
    path = Path(raw_path)
    before = os.lstat(str(path))
    if stat_module.S_ISLNK(before.st_mode) or not stat_module.S_ISREG(before.st_mode):
        raise ValueError("A selected run input is not a regular, non-symlink file.")
    before_signature = _library_file_signature(before)

    digest = meta.get("sha256")
    cached_signature = meta.get("file_signature")
    if not digest or tuple(cached_signature or ()) != before_signature:
        if meta.get("library") and meta.get("category") in {"wordlists", "rules"}:
            digest = _library_asset_sha256(str(meta["category"]), path, before)
        else:
            digest = _sha256_file(path)

    after = os.lstat(str(path))
    if _library_file_signature(after) != before_signature:
        raise ValueError("A selected run input changed while its dataset identity was being recorded.")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("A selected run input did not produce a valid SHA-256 checksum.")
    return {
        "slot": int(slot),
        "name": safe_name(meta.get("name") or path.name, "input"),
        "size": int(before.st_size),
        "sha256": digest,
    }


def _dataset_fingerprint(tool: str, mode: str, inputs: list[dict]) -> str:
    """Fingerprint the tool/workflow and ordered input contents, excluding run options."""
    identity = {
        "tool": str(tool),
        "mode": str(mode),
        "inputs": [
            {"slot": int(item["slot"]), "size": int(item["size"]), "sha256": str(item["sha256"])}
            for item in inputs
        ],
    }
    payload = json.dumps(identity, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _write_run_dataset_manifest(run_dir: Path, tool: str, mode: str) -> dict | None:
    """Persist run inputs at launch so future scans can find repeated dataset runs."""
    selected = _run_input_metadata(tool, mode)
    if not selected:
        return None
    try:
        inputs = [_stable_run_input_record(item, index + 1) for index, item in enumerate(selected)]
        manifest = {
            "schema_version": 1,
            "tool": str(tool),
            "mode": str(mode),
            "created_at": time.time(),
            "inputs": inputs,
        }
        manifest["dataset_fingerprint"] = _dataset_fingerprint(tool, mode, inputs)
        target = run_dir / RUN_DATASET_MANIFEST
        temporary = run_dir / (RUN_DATASET_MANIFEST + ".tmp")
        temporary.write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, target)
        return manifest
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        try:
            (run_dir / (RUN_DATASET_MANIFEST + ".tmp")).unlink(missing_ok=True)
        except OSError:
            pass
        return None


def _validated_run_dataset_manifest(manifest: object) -> dict | None:
    """Validate a manifest and recompute its fingerprint rather than trusting its field."""
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        return None
    tool = manifest.get("tool")
    mode = manifest.get("mode")
    inputs = manifest.get("inputs")
    if tool not in {"rulest", "ranker", "concentrator", "rulestripper", "minimizer"}:
        return None
    if not isinstance(mode, str) or not mode or len(mode) > 40:
        return None
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= MAX_CONCENTRATOR_FILES:
        return None
    normalized = []
    for expected_slot, item in enumerate(inputs, start=1):
        if not isinstance(item, dict):
            return None
        try:
            slot = int(item.get("slot"))
            size = int(item.get("size"))
            digest = str(item.get("sha256", ""))
            name = str(item.get("name", "input"))
        except (TypeError, ValueError):
            return None
        if slot != expected_slot or size < 0 or not re.fullmatch(r"[a-f0-9]{64}", digest):
            return None
        normalized.append({"slot": slot, "size": size, "sha256": digest, "name": name[:220]})
    fingerprint = _dataset_fingerprint(tool, mode, normalized)
    stored_fingerprint = manifest.get("dataset_fingerprint")
    if stored_fingerprint and not hmac.compare_digest(str(stored_fingerprint), fingerprint):
        return None
    return {
        "tool": tool,
        "mode": mode,
        "inputs": normalized,
        "dataset_fingerprint": fingerprint,
        "created_at": float(manifest.get("created_at") or 0),
        "source": "recorded",
    }


def _read_run_dataset_manifest(directory: Path) -> dict | None:
    """Read a small, regular manifest from a direct run folder without following links."""
    path = directory / RUN_DATASET_MANIFEST
    try:
        before = os.lstat(str(path))
        if stat_module.S_ISLNK(before.st_mode) or not stat_module.S_ISREG(before.st_mode) or before.st_size > 128 * 1024:
            return None
        with path.open("r", encoding="utf-8") as stream:
            raw = json.load(stream)
        after = os.lstat(str(path))
        if _library_file_signature(before) != _library_file_signature(after):
            return None
        return _validated_run_dataset_manifest(raw)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _legacy_run_dataset_manifest(directory: Path) -> dict | None:
    """Infer older run inputs from their saved web command log where all inputs remain available."""
    log_path = directory / "engine.log"
    try:
        info = os.lstat(str(log_path))
        if stat_module.S_ISLNK(info.st_mode) or not stat_module.S_ISREG(info.st_mode):
            return None
        with log_path.open("rb") as stream:
            if info.st_size > 4 * 1024 * 1024:
                stream.seek(-4 * 1024 * 1024, os.SEEK_END)
            log_text = stream.read().decode("utf-8", errors="replace")
    except OSError:
        return None

    tool = mode = None
    if "Starting rulest engine" in log_text or "run_rulest.py" in log_text:
        tool, mode = "rulest", "default"
    else:
        ranker_match = re.search(r"Starting Rule Ranker workflow:\s*([a-z]+)", log_text, re.IGNORECASE)
        concentrator_match = re.search(r"Starting Concentrator workflow:\s*([a-z]+)", log_text, re.IGNORECASE)
        if ranker_match:
            tool, mode = "ranker", ranker_match.group(1).lower()
        elif concentrator_match:
            tool, mode = "concentrator", concentrator_match.group(1).lower()
        elif "Starting Rulestripper" in log_text or "run_rulestripper.py" in log_text:
            tool, mode = "rulestripper", "extract"
        elif "Starting Rule Minimizer" in log_text or "minimizer.py" in log_text:
            tool, mode = "minimizer", "minimize"
    if not tool or not mode:
        return None

    command_lines = []
    for line in log_text.splitlines():
        marker = line.find("[WEB]")
        if marker < 0:
            continue
        payload = line[marker + len("[WEB]"):].strip()
        if tool == "rulest" and "run_rulest.py" in payload and "--output" in payload:
            command_lines.append(payload)
        elif tool == "ranker" and any(flag in payload for flag in ("--wordlist", "--ranking-csv", "--rules-file", "--input")):
            command_lines.append(payload)
        elif tool == "concentrator" and "-ob" in payload:
            command_lines.append(payload)
        elif tool == "rulestripper" and "run_rulestripper.py" in payload and "--output" in payload:
            command_lines.append(payload)
        elif tool == "minimizer" and "minimizer.py" in payload and "-o" in payload:
            command_lines.append(payload)
    if not command_lines:
        return None
    command = command_lines[-1]

    candidates = []
    for category in ("wordlists", "rules"):
        try:
            folder = library_category_dir(category)
            if folder.is_symlink() or not folder.is_dir():
                continue
            for candidate in folder.iterdir():
                if not _safe_library_filename(candidate.name) or _is_library_derived_cache(candidate.name):
                    continue
                metadata = os.lstat(str(candidate))
                if stat_module.S_ISREG(metadata.st_mode) and not stat_module.S_ISLNK(metadata.st_mode):
                    candidates.append({"path": candidate.resolve(strict=True), "name": _library_asset_display_name(candidate.name),
                                       "size": metadata.st_size, "library": True, "category": category})
        except OSError:
            continue
    try:
        for candidate in UPLOADS.iterdir():
            metadata = os.lstat(str(candidate))
            if stat_module.S_ISREG(metadata.st_mode) and not stat_module.S_ISLNK(metadata.st_mode):
                candidates.append({"path": candidate.resolve(strict=True), "name": candidate.name,
                                   "size": metadata.st_size, "library": False})
    except OSError:
        pass

    hits = []
    seen_paths = set()
    for candidate in candidates:
        path_text = str(candidate["path"])
        position = command.find(path_text)
        if position < 0 or path_text in seen_paths:
            continue
        seen_paths.add(path_text)
        candidate["_position"] = position
        hits.append(candidate)
    hits.sort(key=lambda item: (item["_position"], -len(str(item["path"]))))

    expected = {
        ("rulest", "default"): (2, 3),
        ("ranker", "rank"): (3, 3),
        ("ranker", "optimize"): (3, 3),
        ("ranker", "analyze"): (1, 1),
        ("rulestripper", "extract"): (2, 2),
        ("minimizer", "minimize"): (1, 2),
        ("concentrator", mode): (1, MAX_CONCENTRATOR_FILES),
    }.get((tool, mode))
    if expected is None or not expected[0] <= len(hits) <= expected[1]:
        return None

    inputs = []
    try:
        for index, meta in enumerate(hits, start=1):
            inputs.append(_stable_run_input_record(meta, index))
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return None
    return {
        "tool": tool,
        "mode": mode,
        "inputs": inputs,
        "dataset_fingerprint": _dataset_fingerprint(tool, mode, inputs),
        "created_at": 0.0,
        "source": "inferred from saved command log",
    }


def _run_directory_metadata(directory: Path) -> dict | None:
    """Inspect a run folder without hashing output data; reject links/special files."""
    try:
        if directory.is_symlink() or not directory.is_dir():
            return None
        directory_stat = directory.lstat()
    except OSError:
        return None

    file_count = 0
    total_bytes = 0
    latest_mtime_ns = int(getattr(directory_stat, "st_mtime_ns", directory_stat.st_mtime * 1_000_000_000))
    log_files = 0
    visible_files = []
    snapshot_records = []

    def raise_walk_error(error):
        raise error

    try:
        for root, dir_names, file_names in os.walk(directory, topdown=True, followlinks=False, onerror=raise_walk_error):
            root_path = Path(root)
            safe_dir_names = []
            for name in sorted(dir_names, key=str.casefold):
                child = root_path / name
                child_stat = child.lstat()
                if stat_module.S_ISLNK(child_stat.st_mode) or not stat_module.S_ISDIR(child_stat.st_mode):
                    return None
                safe_dir_names.append(name)
            dir_names[:] = safe_dir_names
            for name in sorted(file_names, key=str.casefold):
                child = root_path / name
                child_stat = child.lstat()
                if stat_module.S_ISLNK(child_stat.st_mode) or not stat_module.S_ISREG(child_stat.st_mode):
                    return None
                file_count += 1
                total_bytes += int(child_stat.st_size)
                child_mtime_ns = int(getattr(child_stat, "st_mtime_ns", child_stat.st_mtime * 1_000_000_000))
                latest_mtime_ns = max(latest_mtime_ns, child_mtime_ns)
                relative = child.relative_to(directory).as_posix()
                snapshot_records.append({
                    "path": relative,
                    "size": int(child_stat.st_size),
                    "mtime_ns": child_mtime_ns,
                    "mode": int(child_stat.st_mode),
                })
                if relative == RUN_DATASET_MANIFEST or name == "control.txt":
                    continue
                visible_files.append(relative)
                if Path(name).suffix.lower() == ".log":
                    log_files += 1
    except (OSError, ValueError):
        return None

    empty = not visible_files
    log_only = empty or log_files == len(visible_files)
    return {
        "files": len(visible_files),
        "physical_files": file_count,
        "bytes": total_bytes,
        "log_files": log_files,
        "empty": empty,
        "log_only": log_only,
        "has_non_log_outputs": bool(visible_files) and log_files < len(visible_files),
        "latest_mtime_ns": latest_mtime_ns,
        "snapshot_records": snapshot_records,
    }


def _is_direct_run_directory(directory: Path) -> bool:
    """Validate that a candidate is a direct, non-symlink child of DATA."""
    try:
        return not directory.is_symlink() and directory.is_dir() and directory.parent.resolve() == DATA.resolve()
    except OSError:
        return False


def _run_dataset_manifest_for_directory(directory: Path) -> dict | None:
    """Prefer a recorded fingerprint; infer older runs only from a saved web command."""
    return _read_run_dataset_manifest(directory) or _legacy_run_dataset_manifest(directory)


def _scan_run_storage_candidates_unlocked() -> dict:
    """Find empty/log-only folders and repeated runs of the same tool input datasets."""
    log_only = []
    grouped = {}
    skipped_unsafe = 0
    scanned = 0
    current_run_dir = None
    if STATE.get("run_dir"):
        try:
            current_run_dir = Path(STATE["run_dir"]).resolve()
        except OSError:
            current_run_dir = None

    for directory in _iter_run_directories():
        scanned += 1
        metadata = _run_directory_metadata(directory)
        if metadata is None:
            skipped_unsafe += 1
            continue

        if metadata["log_only"]:
            log_only.append({
                "name": directory.name,
                "files": metadata["files"],
                "log_files": metadata["log_files"],
                "bytes": metadata["bytes"],
                "empty": metadata["empty"],
                "snapshot_records": metadata["snapshot_records"],
            })

        # Log-only or empty attempts are handled by the separate cleanup action.
        if not metadata["has_non_log_outputs"]:
            continue

        manifest = _run_dataset_manifest_for_directory(directory)
        if manifest is None:
            continue
        fingerprint = manifest["dataset_fingerprint"]
        grouped.setdefault(fingerprint, []).append({
            "name": directory.name,
            "path": directory,
            "tool": manifest["tool"],
            "mode": manifest["mode"],
            "inputs": manifest["inputs"],
            "manifest_source": manifest["source"],
            "files": metadata["files"],
            "bytes": metadata["bytes"],
            "latest_mtime_ns": metadata["latest_mtime_ns"],
        })

    repeated_groups = []
    for fingerprint, entries in grouped.items():
        if len(entries) < 2:
            continue
        current_entries = [
            item for item in entries
            if current_run_dir is not None and item["path"].resolve() == current_run_dir
        ]
        # Keep the most recently touched run unless the last selected run is in the group.
        keeper = current_entries[0] if current_entries else max(
            entries, key=lambda item: (item["latest_mtime_ns"], item["name"])
        )
        duplicate_entries = sorted(
            (item for item in entries if item is not keeper),
            key=lambda item: item["name"].casefold(),
        )
        repeated_groups.append({
            "fingerprint": fingerprint,
            "tool": keeper["tool"],
            "mode": keeper["mode"],
            "inputs": [{"name": item.get("name", f"Input {item['slot']}"), "size": item["size"]}
                       for item in keeper["inputs"]],
            "manifest_source": keeper["manifest_source"],
            "keep": keeper["name"],
            "duplicates": [item["name"] for item in duplicate_entries],
            "duplicate_bytes": {item["name"]: item["bytes"] for item in duplicate_entries},
            "files": keeper["files"],
            "bytes_each": keeper["bytes"],
            "reclaimable_bytes": sum(item["bytes"] for item in duplicate_entries),
        })

    repeated_groups.sort(key=lambda item: (item["tool"], item["mode"], item["keep"].casefold()))
    log_only.sort(key=lambda item: item["name"].lower())
    return {
        "scanned_directories": scanned,
        "log_only_directories": log_only,
        "log_only_count": len(log_only),
        "log_only_bytes": sum(item["bytes"] for item in log_only),
        "duplicate_groups": repeated_groups,
        "duplicate_group_count": len(repeated_groups),
        "duplicate_directories": sum(len(item["duplicates"]) for item in repeated_groups),
        "duplicate_reclaimable_bytes": sum(item["reclaimable_bytes"] for item in repeated_groups),
        "skipped_unsafe_directories": skipped_unsafe,
    }


def scan_run_storage_cleanup_candidates() -> dict:
    """Identify logs-only runs and repeated runs that used the same input datasets."""
    with _run_storage_maintenance():
        result = _scan_run_storage_candidates_unlocked()
    scanned_at = time.strftime("%Y-%m-%d %H:%M:%S")
    _set_storage_scan_snapshot("last_run_scan", {
        "scanned_at": scanned_at,
        "log_only_count": result["log_only_count"],
        "log_only_bytes": result["log_only_bytes"],
        "duplicate_directories": result["duplicate_directories"],
        "duplicate_reclaimable_bytes": result["duplicate_reclaimable_bytes"],
        "scanned_directories": result["scanned_directories"],
    })
    result["scanned_at"] = scanned_at
    _record_storage_activity(
        "Run folder scan",
        f"Checked {result['scanned_directories']:,} folders · {result['log_only_count']:,} log-only · "
        f"{result['duplicate_directories']:,} repeated dataset run(s)",
    )
    return result


def _clear_deleted_run_state(deleted_names: set[str]) -> None:
    """Drop state/output references if a targeted cleanup removed STATE.run_dir."""
    if not deleted_names or not STATE.get("run_dir"):
        return
    try:
        current = Path(STATE["run_dir"])
        if current.name in deleted_names and current.parent.resolve() == DATA.resolve():
            STATE["run_dir"] = None
            STATE["outputs"] = []
    except OSError:
        STATE["run_dir"] = None
        STATE["outputs"] = []


def delete_log_only_run_directories() -> dict:
    """Delete empty folders or folders containing regular .log files only."""
    with _run_storage_maintenance():
        candidates = _scan_run_storage_candidates_unlocked()["log_only_directories"]
        deleted = []
        failures = []
        for item in candidates:
            directory = DATA / item["name"]
            if not _is_direct_run_directory(directory):
                failures.append(f"{item['name']}: folder is no longer a safe run directory")
                continue
            current_metadata = _run_directory_metadata(directory)
            if (current_metadata is None or not current_metadata["log_only"]
                    or current_metadata["snapshot_records"] != item.get("snapshot_records")):
                failures.append(f"{item['name']}: contents changed after the scan; skipped")
                continue
            try:
                shutil.rmtree(directory)
                deleted.append(item["name"])
            except OSError as exc:
                failures.append(f"{item['name']}: {exc}")
        with LOCK:
            _clear_deleted_run_state(set(deleted))
            result = run_storage_summary_unlocked()
            result.update({"deleted_directories": len(deleted), "deleted_names": deleted, "failures": failures})

    if deleted:
        _invalidate_storage_scan_snapshots()
        add_log(f"[WEB] Run storage cleanup removed {len(deleted)} empty/log-only director{'y' if len(deleted) == 1 else 'ies'}.")
        _record_storage_activity(
            "Empty / logs-only folders removed",
            f"Deleted {len(deleted):,} eligible folder(s)",
            sum(int(item.get("bytes", 0)) for item in candidates if item.get("name") in deleted),
        )
    return result


def delete_duplicate_run_directories() -> dict:
    """Remove older repeated runs while retaining one representative per dataset group."""
    with _run_storage_maintenance():
        scan = _scan_run_storage_candidates_unlocked()
        deleted = []
        retained = []
        failures = []
        current_run_dir = None
        if STATE.get("run_dir"):
            try:
                current_run_dir = Path(STATE["run_dir"]).resolve()
            except OSError:
                current_run_dir = None

        for group in scan["duplicate_groups"]:
            retained.append(group["keep"])
            for name in group["duplicates"]:
                directory = DATA / name
                if not _is_direct_run_directory(directory):
                    failures.append(f"{name}: folder is no longer a safe run directory")
                    continue
                try:
                    resolved = directory.resolve(strict=True)
                    if current_run_dir is not None and resolved == current_run_dir:
                        failures.append(f"{name}: the currently selected run is protected")
                        continue
                    metadata = _run_directory_metadata(directory)
                    manifest = _run_dataset_manifest_for_directory(directory)
                    if (metadata is None or not metadata["has_non_log_outputs"] or manifest is None
                            or manifest["dataset_fingerprint"] != group["fingerprint"]):
                        failures.append(f"{name}: run inputs or folder safety changed after the scan; skipped")
                        continue
                    shutil.rmtree(directory)
                    deleted.append(name)
                except OSError as exc:
                    failures.append(f"{name}: {exc}")
        with LOCK:
            _clear_deleted_run_state(set(deleted))
            result = run_storage_summary_unlocked()
            result.update({
                "deleted_directories": len(deleted),
                "deleted_names": deleted,
                "retained_directories": retained,
                "failures": failures,
            })

    if deleted:
        _invalidate_storage_scan_snapshots()
        add_log(f"[WEB] Repeated-dataset cleanup removed {len(deleted)} older run director{'y' if len(deleted) == 1 else 'ies'}.")
        # Count only folders that were actually deleted; a concurrent or unsafe
        # candidate skipped during the recheck must not inflate recovered space.
        reclaimed = sum(
            int(group.get("duplicate_bytes", {}).get(name, 0))
            for group in scan["duplicate_groups"]
            for name in group.get("duplicates", [])
            if name in deleted
        )
        _record_storage_activity(
            "Repeated dataset runs removed",
            f"Deleted {len(deleted):,} redundant run folder(s)", reclaimed,
        )
    return result


def clear_run_directories() -> dict:
    """Delete persisted run directories, preserving uploads/, library/ and app config.

    This operation is rejected while any engine job or upload is active. It only
    removes direct, non-symlink run directories under DATA and never follows links.
    """
    with _run_storage_maintenance():
        with LOCK:
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
        with LOCK:
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
    if removed:
        _invalidate_storage_scan_snapshots()
        _record_storage_activity("All run folders removed", f"Deleted {removed:,} run folder(s)")
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
        "library_preserved": True,
    }



def storage_intelligence_summary() -> dict:
    """Build a filesystem dashboard in one metadata-only pass; never hash file contents."""
    bucket_values = {
        "runs": {"key": "runs", "label": "Run folders", "files": 0, "bytes": 0},
        "library": {"key": "library", "label": "Reusable library", "files": 0, "bytes": 0},
        "uploads": {"key": "uploads", "label": "Temporary uploads", "files": 0, "bytes": 0},
        "internal": {"key": "internal", "label": "Internal metadata", "files": 0, "bytes": 0},
    }
    library_stats = {"wordlist_files": 0, "wordlist_bytes": 0, "rule_files": 0, "rule_bytes": 0}
    run_directories = 0
    total_files = 0
    total_bytes = 0
    folders = []
    largest_heap = []
    newest_library_heap = []
    sequence = 0
    largest_limit = 10
    newest_limit = 5

    def consider_file(record):
        nonlocal sequence
        sequence += 1
        candidate = (int(record["bytes"]), sequence, record)
        if len(largest_heap) < largest_limit:
            heapq.heappush(largest_heap, candidate)
        elif candidate[0] > largest_heap[0][0]:
            heapq.heapreplace(largest_heap, candidate)
        if record.get("source") == "library":
            newest = (int(record.get("modified", 0)), sequence, record)
            if len(newest_library_heap) < newest_limit:
                heapq.heappush(newest_library_heap, newest)
            elif newest[0] > newest_library_heap[0][0]:
                heapq.heapreplace(newest_library_heap, newest)

    def scan_tree(folder: Path, source: str, category: str = "") -> tuple[int, int]:
        """Count safe regular files and collect downloadable top files if applicable."""
        count = size = 0
        if folder.is_symlink() or not folder.is_dir():
            return count, size

        def raise_walk_error(error):
            raise error

        try:
            for current_root, directory_names, file_names in os.walk(
                folder, topdown=True, followlinks=False, onerror=raise_walk_error
            ):
                current_path = Path(current_root)
                safe_names = []
                for directory_name in sorted(directory_names, key=str.casefold):
                    child = current_path / directory_name
                    try:
                        child_mode = child.lstat().st_mode
                        if stat_module.S_ISDIR(child_mode) and not stat_module.S_ISLNK(child_mode):
                            safe_names.append(directory_name)
                    except OSError:
                        continue
                directory_names[:] = safe_names

                for filename in file_names:
                    if source == "run" and filename == RUN_DATASET_MANIFEST:
                        continue
                    candidate_path = current_path / filename
                    try:
                        metadata = candidate_path.lstat()
                        if not stat_module.S_ISREG(metadata.st_mode):
                            continue
                        file_size = int(metadata.st_size)
                        count += 1
                        size += file_size
                        if source == "run":
                            relative = candidate_path.relative_to(folder).as_posix()
                            consider_file({
                                "source": "run", "name": filename,
                                "path": str(candidate_path), "bytes": file_size,
                                "modified": int(metadata.st_mtime), "run_id": folder.name,
                                "relative_path": relative,
                                "download_url": "/api/run-storage/file-download?" + urllib.parse.urlencode({
                                    "run_id": folder.name, "relative_path": relative,
                                }),
                            })
                        elif (source == "library" and current_path == folder
                                and _safe_library_filename(filename)
                                and not _is_library_derived_cache(filename)):
                            consider_file({
                                "source": "library", "category": category,
                                "asset_id": filename,
                                "name": _library_asset_display_name(filename),
                                "path": str(candidate_path), "bytes": file_size,
                                "modified": int(metadata.st_mtime),
                                "download_url": "/api/library/download?" + urllib.parse.urlencode({
                                    "category": category, "asset_id": filename,
                                }),
                            })
                    except (OSError, ValueError):
                        continue
        except OSError:
            # Keep the partial metadata snapshot; inaccessible descendants are skipped.
            pass
        return count, size

    try:
        top_entries = sorted(DATA.iterdir(), key=lambda item: item.name.casefold()) if DATA.is_dir() and not DATA.is_symlink() else []
    except OSError:
        top_entries = []

    for entry in top_entries:
        try:
            metadata = entry.lstat()
            if stat_module.S_ISLNK(metadata.st_mode):
                continue
            if stat_module.S_ISREG(metadata.st_mode):
                total_files += 1
                total_bytes += int(metadata.st_size)
                bucket_values["internal"]["files"] += 1
                bucket_values["internal"]["bytes"] += int(metadata.st_size)
                continue
            if not stat_module.S_ISDIR(metadata.st_mode):
                continue
        except OSError:
            continue

        if entry.name == UPLOADS.name:
            count, size = scan_tree(entry, "uploads")
            bucket_values["uploads"]["files"] += count
            bucket_values["uploads"]["bytes"] += size
            total_files += count
            total_bytes += size
            folders.append({"name": entry.name, "path": str(entry), "source": "uploads", "files": count, "bytes": size})
        elif entry.name == "library":
            # The hash index and any non-category library metadata are counted as
            # internal files; the two selectable asset folders are reported as Library.
            try:
                library_entries = sorted(entry.iterdir(), key=lambda item: item.name.casefold())
            except OSError:
                library_entries = []
            for library_entry in library_entries:
                try:
                    child_metadata = library_entry.lstat()
                    if stat_module.S_ISLNK(child_metadata.st_mode):
                        continue
                    if stat_module.S_ISREG(child_metadata.st_mode):
                        total_files += 1
                        total_bytes += int(child_metadata.st_size)
                        bucket_values["internal"]["files"] += 1
                        bucket_values["internal"]["bytes"] += int(child_metadata.st_size)
                        continue
                    if not stat_module.S_ISDIR(child_metadata.st_mode):
                        continue
                except OSError:
                    continue
                if library_entry.name in {"wordlists", "rules"}:
                    count, size = scan_tree(library_entry, "library", library_entry.name)
                    bucket_values["library"]["files"] += count
                    bucket_values["library"]["bytes"] += size
                    total_files += count
                    total_bytes += size
                    if library_entry.name == "wordlists":
                        library_stats["wordlist_files"] += count
                        library_stats["wordlist_bytes"] += size
                    else:
                        library_stats["rule_files"] += count
                        library_stats["rule_bytes"] += size
                    folders.append({"name": library_entry.name, "path": str(library_entry), "source": "library", "files": count, "bytes": size})
                else:
                    count, size = scan_tree(library_entry, "internal")
                    bucket_values["internal"]["files"] += count
                    bucket_values["internal"]["bytes"] += size
                    total_files += count
                    total_bytes += size
        else:
            run_directories += 1
            count, size = scan_tree(entry, "run")
            bucket_values["runs"]["files"] += count
            bucket_values["runs"]["bytes"] += size
            total_files += count
            total_bytes += size
            folders.append({"name": entry.name, "path": str(entry), "source": "run", "files": count, "bytes": size})

    for bucket in bucket_values.values():
        bucket["percent"] = (bucket["bytes"] / total_bytes * 100.0) if total_bytes else 0.0

    try:
        disk = shutil.disk_usage(DATA)
        filesystem = {
            "total_bytes": int(disk.total),
            "free_bytes": int(disk.free),
            "used_percent": ((disk.total - disk.free) / disk.total * 100.0) if disk.total else 0.0,
        }
    except OSError:
        filesystem = None

    folders.sort(key=lambda item: (-item["bytes"], item["path"].casefold()))
    with LOCK:
        last_run_scan = dict(_STORAGE_INTELLIGENCE_STATE.get("last_run_scan") or {})
        last_library_scan = dict(_STORAGE_INTELLIGENCE_STATE.get("last_library_scan") or {})
        activity = [dict(item) for item in _STORAGE_INTELLIGENCE_STATE.get("activity", [])[:6]]
        active = STATE.get("status") in ("running", "stopping")

    cleanup = {
        "run_scanned_at": last_run_scan.get("scanned_at"),
        "log_only_count": last_run_scan.get("log_only_count"),
        "log_only_bytes": last_run_scan.get("log_only_bytes"),
        "duplicate_run_count": last_run_scan.get("duplicate_directories"),
        "duplicate_run_bytes": last_run_scan.get("duplicate_reclaimable_bytes"),
        "library_scanned_at": last_library_scan.get("scanned_at"),
        "duplicate_file_groups": last_library_scan.get("duplicate_group_count"),
        "same_name_review_groups": last_library_scan.get("same_name_review_groups"),
        "suggested_delete_count": last_library_scan.get("suggested_delete_count"),
        "suggested_delete_bytes": last_library_scan.get("suggested_delete_bytes"),
    }
    library_files = bucket_values["library"]["files"]
    library_bytes = bucket_values["library"]["bytes"]
    return {
        "total_files": total_files,
        "total_bytes": total_bytes,
        "run_directories": run_directories,
        "quota": {
            # This is the same aggregate runs/ tree measured by storage_preflight().
            # It intentionally remains separate from the physical filesystem capacity.
            "used_bytes": total_bytes,
            "limit_bytes": MAX_DATA_STORAGE_BYTES,
            "remaining_bytes": max(0, MAX_DATA_STORAGE_BYTES - total_bytes),
            "used_percent": (total_bytes / MAX_DATA_STORAGE_BYTES * 100.0)
                if MAX_DATA_STORAGE_BYTES else 0.0,
        },
        "buckets": list(bucket_values.values()),
        "filesystem": filesystem,
        "library": {
            "files": library_files, "bytes": library_bytes,
            **library_stats,
        },
        "largest_files": [item[2] for item in sorted(largest_heap, key=lambda item: (-item[0], item[2]["path"].casefold()))],
        "recent_library_files": [item[2] for item in sorted(newest_library_heap, key=lambda item: (-item[0], item[2]["path"].casefold()))],
        "largest_folders": folders[:8],
        "cleanup": cleanup,
        "activity": activity,
        "active": active,
        "history_scope": "since server start",
    }


ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\)|[@-Z\\-_])"
)
PROGRESS_PERCENT_RE = re.compile(r"(?<!\d)(\d{1,3})%\s*\|")
PROGRESS_COUNT_RE = re.compile(r"\|\s*([\d,]+)\s*/\s*([\d,]+)\s*\[")
CELF_SELECTED_PROGRESS_RE = re.compile(r"\bselected\s*=\s*([\d,]+)\s*/\s*([\d,]+)", re.IGNORECASE)
PROGRESS_RULES_RE = re.compile(r"\brules\s*=\s*([\d,]+)", re.IGNORECASE)
# rulest uses tqdm-style bars with an additional ``spd=12.0K words/s`` or
# ``spd=812.4M combos/s`` field. Keep this independent of the bar glyphs so
# Windows consoles, ANSI color, and different Unicode progress characters all
# produce the same parsed telemetry.
PROGRESS_RATE_RE = re.compile(
    r"\bspd\s*=\s*([\d,.]+)\s*([KMGT]?)\s*(words|combos|rules)\s*/s\b",
    re.IGNORECASE,
)


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
    if "TOP-N" in upper or "[TOPN]" in upper:
        return "Top-N · PCFG-Lite seed generation"
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
    elif active_tool == "rulestripper" and stage is None:
        upper = clean.upper()
        if "[LOAD]" in upper or "SHARED RAM" in upper:
            stage = "Rulestripper · Loading shared wordlists"
        elif "EXTRACTING" in upper or "TARGET WORDS" in upper or "RULES EXTRACTED" in upper:
            stage = "Rulestripper · Rule extraction"
        elif "TOGGLE SEEDS" in upper or "[P0]" in upper:
            stage = "Rulestripper · Finalizing rules"
    elif active_tool == "minimizer" and stage is None:
        upper = clean.upper()
        if "PROBE" in upper or "SIGNATURE" in upper or "COMPUT" in upper:
            stage = "Rule Minimizer · Signature computation"
        elif "DUPLICAT" in upper or "COLLISION" in upper or "REMOVED" in upper:
            stage = "Rule Minimizer · Deduplication"
        elif "[OUT]" in upper or "WRITTEN" in upper:
            stage = "Rule Minimizer · Writing output"
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
    celf_selected_match = CELF_SELECTED_PROGRESS_RE.search(clean)
    rate_match = PROGRESS_RATE_RE.search(clean)
    rules_match = PROGRESS_RULES_RE.search(clean)
    progress = None
    progress_completed = progress_total = None
    progress_rate = None
    progress_rules = None
    if pct_match:
        progress = min(100, int(pct_match.group(1)))
    if count_match:
        progress_completed = int(count_match.group(1).replace(",", ""))
        progress_total = int(count_match.group(2).replace(",", ""))
        if progress is None and progress_total > 0:
            progress = min(100, round(progress_completed * 100 / progress_total))
    elif celf_selected_match:
        progress_completed = int(celf_selected_match.group(1).replace(",", ""))
        progress_total = int(celf_selected_match.group(2).replace(",", ""))
        if progress_total > 0:
            progress = min(100, round(progress_completed * 100 / progress_total))
    if rate_match:
        progress_rate = (
            f"{rate_match.group(1)}{rate_match.group(2).upper()} "
            f"{rate_match.group(3).lower()}/s"
        )
    if rules_match:
        progress_rules = int(rules_match.group(1).replace(",", ""))

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
                STATE["progress_completed"] = None
                STATE["progress_total"] = None
                STATE["progress_rate"] = None
                STATE["progress_rules"] = None
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
        if progress_completed is not None:
            STATE["progress_completed"] = progress_completed
        if progress_total is not None:
            STATE["progress_total"] = progress_total
        if progress_rate is not None:
            STATE["progress_rate"] = progress_rate
        if progress_rules is not None:
            STATE["progress_rules"] = progress_rules


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
    # "topn_adaptive" is a positive UI toggle (checked = adaptive budgeting,
    # the engine's own default) over the engine's negative/inverted flag, so
    # it can't be a plain BOOL_OPTIONS entry: only send the flag when the
    # person explicitly unchecked it.
    if options.get("topn_seeds") and options.get("topn_adaptive") is False:
        cmd.append("--topn-no-adaptive-budget")
    # Optional PCFG aggregate profile path for Top-N budget nudging.
    topn_profile_path = options.get("topn_profile_path") or options.get("topn_profile")
    if options.get("topn_seeds") and topn_profile_path:
        profile_candidate = Path(str(topn_profile_path))
        if not profile_candidate.is_file():
            # Allow project-relative paths (e.g. reports/pcfg.hashmob.medium.json)
            alt = ROOT / str(topn_profile_path)
            if alt.is_file():
                profile_candidate = alt
        if not profile_candidate.is_file():
            raise ValueError(f"PCFG profile not found: {topn_profile_path}")
        cmd.extend(["--topn-profile", str(profile_candidate)])
    # Inline profile JSON written by the UI into the run directory.
    topn_profile_inline = options.get("topn_profile_json")
    if options.get("topn_seeds") and topn_profile_inline and not topn_profile_path:
        if not isinstance(topn_profile_inline, dict):
            raise ValueError("topn_profile_json must be a JSON object.")
        profile_out = run_dir / "topn_pcfg_profile.json"
        profile_out.write_text(json.dumps(topn_profile_inline), encoding="utf-8")
        cmd.extend(["--topn-profile", str(profile_out)])
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


def ranker_env_overrides(mode: str, options: dict) -> dict:
    """Return per-job Ranker environment overrides for diagnostic flags."""
    profiling_enabled = mode == "optimize" and isinstance(options, dict) and options.get("profile") is True
    return {"RANKER_GREEDY_PROFILE": "1"} if profiling_enabled else {"RANKER_GREEDY_PROFILE": None}


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



def build_rulestripper_command(options: dict, run_dir: Path):
    """Build the spawn-safe shared-memory Rulestripper CLI command."""
    base = _uploaded_path("rulestripper_base", "Rulestripper BASE wordlist")
    target = _uploaded_path("rulestripper_target", "Rulestripper TARGET wordlist")
    output_name = safe_name(options.get("output_name", "rulestripper_rules.rule"), "rulestripper_rules.rule")
    if output_name.lower() in {"control.txt", "engine.log", "auth.json"}:
        raise ValueError("This output filename is reserved.")
    output_path = run_dir / output_name
    cmd = [sys.executable, "-u", str(ROOT / "run_rulestripper.py"), str(base), str(target), "--output", str(output_path)]
    for key, flag, default, minimum, maximum in (
        ("max_depth", "--max-depth", 0, 0, 31),
        ("min_stem", "--min-stem", 4, 1, 256),
        ("leet_amb", "--leet-amb", 3, 0, 12),
        ("workers", "--workers", 0, 0, 256),
        ("chunk_size", "--chunk-size", 0, 0, 10_000_000),
        ("ascii_range", "--ascii-range", 3, 0, 9),
    ):
        value = _int_option(options, key, default, minimum, maximum)
        cmd += [flag, str(value)]
    if options.get("no_toggle_seeds"):
        cmd.append("--no-toggle-seeds")
    if options.get("no_new_modes"):
        cmd.append("--no-new-modes")
    if options.get("debug"):
        cmd.append("--debug")
    cmd.append("--no-color")
    return cmd, output_name


def build_minimizer_command(options: dict, run_dir: Path):
    """Build the standalone Hashcat-rule minimizer command."""
    rules = _uploaded_path("minimizer_rules", "Hashcat rules file")
    output_name = safe_name(options.get("output_name", "minimized_rules.rule"), "minimized_rules.rule")
    if output_name.lower() in {"control.txt", "engine.log", "auth.json"}:
        raise ValueError("This output filename is reserved.")
    output_path = run_dir / output_name
    workers = _int_option(options, "workers", 1, 0, 256)
    probe_words = _int_option(options, "probe_words", 50, 1, 1_000_000)
    seed = _int_option(options, "seed", 42, 0, 2_147_483_647)
    cmd = [sys.executable, "-u", str(ROOT / "minimizer.py"), str(rules), "-o", str(output_path),
           "--workers", str(workers), "--probe-words", str(probe_words), "--seed", str(seed)]
    probe = UPLOADS_META.get("minimizer_probe")
    if probe:
        if not Path(probe["path"]).is_file():
            raise ValueError("The selected minimizer probe wordlist is missing.")
        cmd += ["--probe-file", str(probe["path"])]
    extras = str(options.get("extra_probes", "") or "").strip()
    if extras:
        words = extras.split()
        if len(words) > 256:
            raise ValueError("At most 256 extra probe words may be supplied.")
        cmd += ["--extra-probes", *words]
    if options.get("multibyte"):
        cmd.append("--multibyte")
    return cmd, output_name


def run_worker(cmd, run_id, run_dir, control_file=None, tool="rulest", storage_baseline_bytes=None, env_overrides=None):
    global PROCESS, RUN_THREAD
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # Give progress renderers a wide virtual terminal so they do not discard
    # useful counters/postfix fields before the GUI can wrap the full line.
    env["COLUMNS"] = "200"
    env["LINES"] = "40"
    if env_overrides:
        for key, value in env_overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[str(key)] = str(value)
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
                if item.is_file() and item.name not in {"control.txt", RUN_DATASET_MANIFEST}:
                    outputs.append({"name": item.name, "size": item.stat().st_size})
        with LOCK:
            PROCESS = None
            RUN_THREAD = None
            # Retain the last child PID for completed/failed utility LIVE MONITORs.
            # Each new job resets pid to None before launching its subprocess.
            STATE["pid"] = proc.pid if proc is not None else None
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


def _is_probably_plain_text_file(path: Path) -> bool:
    """Classify a Rulestripper wordlist by content, never by filename extension.

    Samples the beginning, middle and end instead of reading a potentially huge
    wordlist again. UTF-8 and legacy single-byte text are accepted; NUL bytes and
    a high proportion of control bytes are treated as binary. This deliberately
    mirrors the useful part of the Linux ``file`` command without depending on
    an external utility that may not exist on Windows.
    """
    try:
        size = path.stat().st_size
        if size <= 0:
            return False
        sample_size = 32 * 1024
        offsets = sorted({0, max(0, (size // 2) - (sample_size // 2)), max(0, size - sample_size)})
        with path.open("rb") as stream:
            for offset in offsets:
                stream.seek(offset)
                sample = stream.read(sample_size)
                if not sample:
                    continue
                if b"\x00" in sample:
                    return False
                control_count = sum(
                    1 for value in sample
                    if (value < 32 and value not in (9, 10, 12, 13)) or value == 127
                )
                if control_count > max(2, len(sample) // 200):
                    return False
        return True
    except OSError:
        return False


def _validate_rulestripper_upload(field: str, filename: str, path: Path) -> None:
    """Accept Rulestripper wordlists by content, regardless of filename/extension."""
    if field not in {"rulestripper_base", "rulestripper_target"}:
        return
    if not _is_probably_plain_text_file(path):
        raise ValueError(
            "Rulestripper accepts plain-text wordlists regardless of filename extension; "
            "binary files are not accepted."
        )



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
        elif path == "/email-rule-extractor.html":
            self.serve_static("email-rule-extractor.html", "text/html; charset=utf-8")
        elif path == "/email-rule-extractor.css":
            self.serve_static("email-rule-extractor.css", "text/css; charset=utf-8")
        elif path == "/email-rule-extractor.js":
            self.serve_static("email-rule-extractor.js", "text/javascript; charset=utf-8")
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
        elif path == "/api/library":
            self.send_json({"ok": True, **list_library_assets()})
        elif path == "/api/library/search":
            query = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            try:
                self.send_json({"ok": True, **search_library_assets(query)})
            except ValueError as exc:
                self.send_json({"error": str(exc)}, 400)
        elif path == "/api/library/download":
            params = urllib.parse.parse_qs(parsed.query)
            category = params.get("category", [""])[0]
            asset_id = params.get("asset_id", [""])[0]
            try:
                target = resolve_library_asset(category, asset_id)
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(str(target), flags)
                metadata = os.fstat(descriptor)
                if not stat_module.S_ISREG(metadata.st_mode):
                    os.close(descriptor)
                    raise ValueError("The requested library item is not a regular file.")
            except (ValueError, OSError) as exc:
                self.send_json({"error": str(exc) or "Library file not found."}, 404)
                return
            download_name = safe_name(_library_asset_display_name(asset_id), "library-file")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.send_header("Content-Length", str(metadata.st_size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                with os.fdopen(descriptor, "rb") as handle:
                    while True:
                        block = handle.read(1024 * 1024)
                        if not block:
                            break
                        self.wfile.write(block)
            except OSError:
                self.close_connection = True
        elif path == "/api/run-storage/file-download":
            params = urllib.parse.parse_qs(parsed.query)
            run_id = params.get("run_id", [""])[0]
            relative_path = params.get("relative_path", [""])[0]
            try:
                descriptor, metadata, target = open_run_folder_file(run_id, relative_path)
            except (ValueError, OSError) as exc:
                self.send_json({"error": str(exc) or "Work-folder file not found."}, 404)
                return
            download_name = safe_name(target.name, "run-file")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
            self.send_header("Content-Length", str(metadata.st_size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                with os.fdopen(descriptor, "rb") as handle:
                    while True:
                        block = handle.read(1024 * 1024)
                        if not block:
                            break
                        self.wfile.write(block)
            except OSError:
                self.close_connection = True
        elif path == "/api/run-storage/download-outputs.zip":
            with LOCK:
                run_directory_value = STATE.get("run_dir")
                outputs = [dict(item) for item in STATE.get("outputs", []) if isinstance(item, dict)]
                output_tool = str(STATE.get("tool") or "ruleops")
                output_status = STATE.get("status")
            if output_status in ("running", "stopping"):
                self.send_json({"error": "Output files are available as a ZIP after the tool has finished."}, 409)
                return
            if len(outputs) <= 3 or not run_directory_value:
                self.send_json({"error": "A ZIP download is available only when the completed run has more than three output files."}, 409)
                return

            run_directory = Path(run_directory_value)
            run_id = run_directory.name
            opened_outputs = []
            try:
                # Confirm the active output folder is a direct child of runs/.
                resolved_run_directory = run_directory.resolve(strict=True)
                if (
                    run_directory.is_symlink()
                    or resolved_run_directory.parent != DATA.resolve(strict=True)
                    or not resolved_run_directory.is_dir()
                ):
                    raise ValueError("Current output folder is outside RULEOPS run storage.")
                seen_names = set()
                for output in outputs:
                    name = str(output.get("name") or "")
                    if (
                        not name or name in {".", ".."} or "/" in name or "\\" in name
                        or safe_name(name, "") != name or name in seen_names
                    ):
                        raise ValueError("The output list contains an unsafe or duplicate filename.")
                    seen_names.add(name)
                    descriptor, metadata, _target = open_run_folder_file(run_id, name)
                    expected_size = output.get("size")
                    if expected_size is not None and int(expected_size) != int(metadata.st_size):
                        os.close(descriptor)
                        raise ValueError(f"Output file changed since the run completed: {name}")
                    opened_outputs.append((name, descriptor, metadata))
            except (OSError, TypeError, ValueError) as exc:
                for _name, descriptor, _metadata in opened_outputs:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                self.send_json({"error": str(exc) or "Output files could not be prepared for download."}, 409)
                return

            archive_name = safe_name(f"RULEOPS-{output_tool}-outputs.zip", "RULEOPS-outputs.zip")
            self.close_connection = True  # HTTP/1.0 response is delimited by socket close.
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{archive_name}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                with zipfile.ZipFile(
                    _HTTPZipSink(self.wfile), mode="w",
                    compression=zipfile.ZIP_DEFLATED, compresslevel=1,
                ) as archive:
                    for name, descriptor, metadata in opened_outputs:
                        info = zipfile.ZipInfo(name)
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.file_size = int(metadata.st_size)
                        info.external_attr = (stat_module.S_IFREG | 0o600) << 16
                        with os.fdopen(descriptor, "rb") as source, archive.open(
                            info, mode="w", force_zip64=True
                        ) as destination:
                            shutil.copyfileobj(source, destination, length=1024 * 1024)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError, RuntimeError, zipfile.BadZipFile):
                # A disconnected client or changed output cannot be repaired
                # after streaming starts. Close the response without leaking FDs.
                self.close_connection = True
            finally:
                for _name, descriptor, _metadata in opened_outputs:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        elif path == "/api/run-storage/summary":
            self.send_json({"ok": True, **run_storage_summary()})
        elif path == "/api/run-storage/intelligence":
            try:
                self.send_json({"ok": True, **storage_intelligence_summary()})
            except (OSError, ValueError, RuntimeError) as exc:
                self.send_json({"error": f"Storage Intelligence unavailable: {exc}"}, 500)
        elif path == "/api/tools/pcfg-profiles":
            self.handle_list_pcfg_profiles()
        elif path == "/api/tools/pcfg-profiles/load":
            self.handle_load_pcfg_profile()
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
                def _upload_status(item):
                    if not item:
                        return None
                    return {key: item[key] for key in ("name", "size", "library", "asset_id", "category") if key in item}
                data["uploads"] = {
                    k: ([_upload_status(item) for item in v] if isinstance(v, list)
                        else _upload_status(v))
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
        if parsed.path == "/api/auth/logout":
            self.handle_auth_logout()
        elif parsed.path == "/api/auth/change-password":
            self.handle_auth_change_password()
        elif parsed.path == "/api/auth/set-user-password":
            self.handle_auth_set_user_password()
        elif parsed.path == "/api/library/select":
            self.handle_library_select()
        elif parsed.path == "/api/library/scan-duplicates":
            self.handle_library_duplicate_scan()
        elif parsed.path == "/api/library/delete-selected":
            self.handle_library_delete_selected()
        elif parsed.path.startswith("/api/upload/"):
            self.handle_upload(parsed, ranker=False)
        elif parsed.path.startswith("/api/ranker/upload/"):
            self.handle_upload(parsed, ranker=True)
        elif parsed.path.startswith("/api/concentrator/upload/"):
            self.handle_upload(parsed, concentrator=True)
        elif parsed.path.startswith("/api/tools/upload/"):
            self.handle_upload(parsed, tools=True)
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
        elif parsed.path == "/api/tools/run":
            self.handle_tools_run()
        elif parsed.path == "/api/tools/cancel":
            self.handle_tools_cancel()
        elif parsed.path == "/api/tools/topn-seeds":
            self.handle_topn_seeds()
        elif parsed.path == "/api/control":
            self.handle_control()
        elif parsed.path == "/api/logs/clear":
            self.handle_clear_logs()
        elif parsed.path == "/api/run-storage/clear":
            self.handle_clear_run_directories()
        elif parsed.path == "/api/run-storage/scan":
            self.handle_scan_run_storage()
        elif parsed.path == "/api/run-storage/delete-log-only":
            self.handle_delete_log_only_run_directories()
        elif parsed.path == "/api/run-storage/delete-duplicates":
            self.handle_delete_duplicate_run_directories()
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
        digest = hashlib.sha256()
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
                digest.update(chunk)
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
        return digest.hexdigest()

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

    def handle_scan_run_storage(self):
        try:
            result = scan_run_storage_cleanup_candidates()
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, 409)
            return
        self.send_json({"ok": True, **result})

    def handle_delete_log_only_run_directories(self):
        try:
            result = delete_log_only_run_directories()
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, 409)
            return
        self.send_json({"ok": not bool(result.get("failures")), **result}, 207 if result.get("failures") else 200)

    def handle_delete_duplicate_run_directories(self):
        try:
            result = delete_duplicate_run_directories()
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, 409)
            return
        self.send_json({"ok": not bool(result.get("failures")), **result}, 207 if result.get("failures") else 200)

    def handle_upload(self, parsed, ranker=False, concentrator=False, tools=False):
        field = parsed.path.rsplit("/", 1)[-1]
        allowed_fields = (CONCENTRATOR_UPLOAD_FIELDS if concentrator else
                          RANKER_UPLOAD_FIELDS if ranker else
                          UTILITY_UPLOAD_FIELDS if tools else {"base", "target", "seed"})
        if field not in allowed_fields:
            self.send_error(404)
            return
        query_params = urllib.parse.parse_qs(parsed.query)
        requested_filename = safe_name(query_params.get("filename", [f"{field}.txt"])[0], f"{field}.txt")[:180].strip(" .")
        requested_filename = requested_filename or f"{field}.txt"
        if concentrator and field == "concentrator_files":
            extension = Path(requested_filename).suffix.lower()
            if extension not in {".rule", ".rules", ".hr", ".hashcat", ".txt", ".lst"}:
                self.send_json({"error": "Concentrator accepts .rule, .rules, .hr, .hashcat, .txt and .lst files."}, 415)
                return
        if tools and field not in {"rulestripper_base", "rulestripper_target"}:
            # Rulestripper wordlists are validated by their contents after the
            # upload is streamed to disk. Do not infer text/binary type from the
            # filename: users commonly create wordlists with names such as
            # ``wordlist``, ``targets.found`` or ``dump.data``.
            extension = Path(requested_filename).suffix.lower()
            allowed = ({".rule", ".rules", ".txt", ".hr", ".hashcat"}
                       if field == "minimizer_rules" else
                       {".txt", ".lst", ".dict", ".wordlist"})
            if extension and extension not in allowed:
                self.send_json({"error": f"Unsupported file type for {field.replace('_', ' ')}."}, 415)
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
            # Only transient files are actually replaced/deleted. Saved library
            # assets remain reusable even when an input slot switches to a new file.
            replaceable_temp = 0
            replaceable_data = 0
            candidates_to_replace = [current_meta]
            exclusive_source = {
                "ranker_source_csv": "ranker_source_rules",
                "ranker_source_rules": "ranker_source_csv",
            }.get(field)
            if exclusive_source:
                candidates_to_replace.append(UPLOADS_META.get(exclusive_source))
            for previous in candidates_to_replace:
                if isinstance(previous, dict) and not previous.get("library"):
                    size = int(previous.get("size", 0))
                    replaceable_temp += size
                    replaceable_data += size
            try:
                upload_bytes = _directory_usage(UPLOADS)[1]
                data_bytes = data_storage_usage_bytes()
                free_bytes = shutil.disk_usage(UPLOADS).free
            except OSError as exc:
                self.send_json({"error": f"Storage check failed: {exc}"}, 507)
                return
            reserved_bytes = sum(int(value) for value in UPLOAD_RESERVATIONS.values())
            if upload_bytes + reserved_bytes - replaceable_temp + length > MAX_TOTAL_UPLOAD_BYTES:
                self.send_json({
                    "error": f"Combined temporary uploads (including in-flight requests) would exceed the {MAX_TOTAL_UPLOAD_BYTES:,}-byte quota. "
                             "Wait for active uploads or increase RULEOPS_MAX_UPLOAD_TOTAL_BYTES."
                }, 413)
                return
            if data_bytes + reserved_bytes - replaceable_data + length > MAX_DATA_STORAGE_BYTES:
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
        reused_library_asset = False
        try:
            try:
                upload_digest = self.read_upload_to_file(stored, length, reservation_key=field)
            except (TimeoutError, ConnectionError, OSError):
                self.close_connection = True
                raise
            _validate_rulestripper_upload(field, filename, stored)

            category = LIBRARY_FIELD_CATEGORIES.get(field)
            asset_id = None
            if category:
                # Move, do not copy: very large wordlists should not be duplicated
                # just to make them reusable. Serialize matching + publish so two
                # concurrent identical uploads cannot create two library entries.
                folder = library_category_dir(category)
                folder.mkdir(parents=True, exist_ok=True)
                with LOCK:
                    duplicate = _find_duplicate_library_asset(category, filename, length, upload_digest)
                    if duplicate is not None:
                        stored.unlink(missing_ok=True)
                        stored = duplicate
                        reused_library_asset = True
                        asset_id = duplicate.name
                    else:
                        asset_id = f"{uuid.uuid4().hex}_{filename}"
                        destination = folder / asset_id
                        os.replace(stored, destination)
                        stored = destination
                        metadata = os.stat(str(destination), follow_symlinks=False)
                        # The digest index is an optimization only. A damaged or
                        # unavailable index must never make a valid upload fail.
                        try:
                            _library_asset_sha256(category, destination, metadata, known_digest=upload_digest)
                        except (OSError, ValueError, sqlite3.Error):
                            pass
                stored_stat = os.stat(str(stored), follow_symlinks=False)
                meta = {
                    "path": stored, "name": _library_asset_display_name(asset_id), "size": length,
                    "library": True, "asset_id": asset_id, "category": category,
                    "sha256": upload_digest, "file_signature": _library_file_signature(stored_stat),
                }
            else:
                stored_stat = os.stat(str(stored), follow_symlinks=False)
                meta = {
                    "path": stored, "name": filename, "size": length, "library": False,
                    "sha256": upload_digest, "file_signature": _library_file_signature(stored_stat),
                }
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
                remove_temporary_upload(previous)
            self.send_json({"ok": True, "field": field, "name": filename, "size": length,
                            "library": bool(category), "asset_id": asset_id, "category": category})
        except Exception as exc:
            with LOCK:
                UPLOADS_ACTIVE.discard(field)
                UPLOAD_RESERVATIONS.pop(field, None)
            if not reused_library_asset:
                try:
                    stored.unlink(missing_ok=True)
                except OSError:
                    pass
            try:
                response_status = 408 if isinstance(exc, TimeoutError) else 400
                self.send_json({"error": f"Upload failed: {exc}"}, response_status)
            except OSError:
                self.close_connection = True

    def handle_library_duplicate_scan(self):
        """Scan reusable wordlists/rules for same-name or checksum duplicates."""
        data = self.read_json_body(16 * 1024)
        if data is None:
            return
        try:
            result = scan_library_duplicates()
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, 409)
            return
        except (OSError, ValueError, sqlite3.Error) as exc:
            self.send_json({"error": f"Library/work duplicate scan failed: {exc}"}, 500)
            return
        self.send_json({"ok": True, **result})

    def handle_library_delete_selected(self):
        """Delete only explicitly checked library assets after server-side revalidation."""
        data = self.read_json_body(128 * 1024)
        if not isinstance(data, dict):
            return
        try:
            result = delete_selected_library_assets(data.get("items"))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, 409)
            return
        except (OSError, sqlite3.Error) as exc:
            self.send_json({"error": f"Library cleanup failed: {exc}"}, 500)
            return
        self.send_json(result)

    def handle_library_select(self):
        """Mount an existing persistent library item into an input slot."""
        data = self.read_json_body(32 * 1024)
        if not isinstance(data, dict):
            return
        field = str(data.get("field", ""))
        category = LIBRARY_FIELD_CATEGORIES.get(field)
        if category is None:
            self.send_json({"error": "This input does not support reusable library items."}, 400)
            return
        try:
            meta = upload_meta_for_library_asset(category, data.get("asset_id"))
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 404)
            return

        replaced = []
        with LOCK:
            if STATE.get("status") in ("running", "stopping"):
                self.send_json({"error": "Saved inputs cannot be changed while a job is active."}, 409)
                return
            if UPLOADS_ACTIVE:
                self.send_json({"error": "Wait for active uploads to finish before selecting saved inputs."}, 409)
                return
            if field == "concentrator_files":
                current = UPLOADS_META.get(field) or []
                if any(item.get("asset_id") == meta["asset_id"] for item in current):
                    self.send_json({"ok": True, "field": field, "name": meta["name"],
                                    "size": meta["size"], "asset_id": meta["asset_id"], "already_selected": True})
                    return
                current_total = sum(int(item.get("size", 0)) for item in current)
                if len(current) >= MAX_CONCENTRATOR_FILES:
                    self.send_json({"error": f"Concentrator accepts at most {MAX_CONCENTRATOR_FILES} input files."}, 413)
                    return
                if current_total + meta["size"] > MAX_CONCENTRATOR_TOTAL_BYTES:
                    self.send_json({"error": "Combined Concentrator inputs exceed the 40 GiB limit."}, 413)
                    return
                current.append(meta)
                UPLOADS_META[field] = current
            else:
                replaced.append(UPLOADS_META.get(field))
                UPLOADS_META[field] = meta
                exclusive_source = {
                    "ranker_source_csv": "ranker_source_rules",
                    "ranker_source_rules": "ranker_source_csv",
                }.get(field)
                if exclusive_source:
                    replaced.append(UPLOADS_META.get(exclusive_source))
                    UPLOADS_META[exclusive_source] = None
        for previous in replaced:
            remove_temporary_upload(previous)
        add_log(f"[WEB] Selected saved {category[:-1] if category.endswith('s') else category}: {meta['name']}.")
        self.send_json({"ok": True, "field": field, "name": meta["name"],
                        "size": meta["size"], "asset_id": meta["asset_id"], "category": category})

    def handle_run(self):
        global PROCESS, RUN_THREAD
        options = self.read_json_body(1024 * 1024)
        if not isinstance(options, dict):
            return
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
                run_manifest = _write_run_dataset_manifest(run_dir, "rulest", "default")
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
                return
            STATE.update({
                "status": "running", "tool": "rulest", "paused": False, "pause_requested": False, "job_id": run_id, "started_at": time.time(), "finished_at": None,
                "pid": None, "stage": "Starting engine", "stage_detail": "Launching the engine process…",
                "stage_started_at": time.time(), "progress": None, "progress_completed": None, "progress_total": None, "progress_rate": None, "progress_rules": None, "exit_code": None,
                "logs": [], "log_seq": 0,
                "log_generation": int(STATE.get("log_generation", 0)) + 1,
                "outputs": [], "error": None,
                "control_file": str(control_file), "run_dir": str(run_dir),
            })
            add_log("[WEB] Starting rulest engine…")
            add_log("[WEB] BASE / TARGET inputs are mounted from the reusable library; temporary workflow files are cleaned after the job.")
            add_log("[WEB] Run input fingerprint recorded for repeated-dataset detection." if run_manifest else "[WEB] Run input fingerprint unavailable; this run may not appear in repeated-dataset scans.")
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
                run_manifest = _write_run_dataset_manifest(run_dir, "ranker", str(mode))
            except Exception as exc:
                shutil.rmtree(run_dir, ignore_errors=True)
                self.send_json({"error": str(exc)}, 400)
                return
            STATE.update({
                "status": "running", "tool": "ranker", "paused": False, "pause_requested": False,
                "job_id": run_id, "started_at": time.time(), "finished_at": None, "pid": None,
                "stage": "Rule Ranker · Starting", "stage_detail": f"Launching {mode} workflow…",
                "stage_started_at": time.time(), "progress": None, "progress_completed": None, "progress_total": None, "progress_rate": None, "progress_rules": None, "exit_code": None,
                "logs": [], "log_seq": 0,
                "log_generation": int(STATE.get("log_generation", 0)) + 1,
                "outputs": [], "error": None, "control_file": None, "run_dir": str(run_dir),
            })
            add_log(f"[WEB] Starting Rule Ranker workflow: {mode}.")
            add_log("[WEB] Wordlists and rules are retained in the reusable library; workflow-specific temporary files are removed after the job.")
            add_log("[WEB] Run input fingerprint recorded for repeated-dataset detection." if run_manifest else "[WEB] Run input fingerprint unavailable; this run may not appear in repeated-dataset scans.")
            add_log("[WEB] " + " ".join(cmd[3:]))
        ranker_env = ranker_env_overrides(mode, options)
        if ranker_env["RANKER_GREEDY_PROFILE"] == "1":
            add_log("[WEB] CELF GPU profiling is ENABLED for this Optimize ruleset job.")
        else:
            add_log("[WEB] CELF GPU profiling is disabled for this Ranker job.")
        thread = threading.Thread(target=run_worker, args=(cmd, run_id, run_dir, None, "ranker", storage_baseline_bytes, ranker_env), daemon=True)
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
                run_manifest = _write_run_dataset_manifest(run_dir, "concentrator", mode)
            except Exception as exc:
                shutil.rmtree(run_dir, ignore_errors=True)
                self.send_json({"error": str(exc)}, 400)
                return
            STATE.update({
                "status": "running", "tool": "concentrator", "paused": False, "pause_requested": False,
                "job_id": run_id, "started_at": time.time(), "finished_at": None, "pid": None,
                "stage": f"Concentrator · {mode.title()}", "stage_detail": "Launching Concentrator workflow…",
                "stage_started_at": time.time(), "progress": None, "progress_completed": None, "progress_total": None, "progress_rate": None, "progress_rules": None, "exit_code": None,
                "logs": [], "log_seq": 0,
                "log_generation": int(STATE.get("log_generation", 0)) + 1,
                "outputs": [], "error": None, "control_file": None, "run_dir": str(run_dir),
            })
            add_log(f"[WEB] Starting Concentrator workflow: {mode}.")
            add_log("[WEB] Rule inputs are retained in the reusable library after the job.")
            add_log("[WEB] Run input fingerprint recorded for repeated-dataset detection." if run_manifest else "[WEB] Run input fingerprint unavailable; this run may not appear in repeated-dataset scans.")
            add_log("[WEB] " + " ".join(cmd[3:]))
        thread = threading.Thread(target=run_worker, args=(cmd, run_id, run_dir, None, "concentrator", storage_baseline_bytes), daemon=True)
        with LOCK:
            RUN_THREAD = thread
        thread.start()
        self.send_json({"ok": True, "job_id": run_id, "output": output_name, "tool": "concentrator", "mode": mode})

    def handle_tools_run(self):
        """Launch the standalone Rulestripper or Hashcat-rule Minimizer utility."""
        global RUN_THREAD
        data = self.read_json_body(1024 * 1024)
        if not isinstance(data, dict):
            self.send_json({"error": "Invalid tool configuration."}, 400)
            return
        tool = str(data.get("tool", ""))
        options = data.get("options") if isinstance(data.get("options"), dict) else {}
        builders = {"rulestripper": build_rulestripper_command, "minimizer": build_minimizer_command}
        builder = builders.get(tool)
        if builder is None:
            self.send_json({"error": "Choose Rulestripper or Rule Minimizer."}, 400)
            return
        with LOCK:
            storage_ok, storage_message, storage_baseline_bytes = storage_preflight()
            if not storage_ok:
                self.send_json({"error": storage_message}, 507)
                return
            if STATE["status"] in ("running", "stopping"):
                self.send_json({"error": "Another RULEOPS job is already running."}, 409)
                return
            if UPLOADS_ACTIVE:
                self.send_json({"error": "Wait for active file uploads to finish before starting."}, 409)
                return
            run_id = uuid.uuid4().hex[:10]
            run_dir = DATA / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            try:
                cmd, output_name = builder(options, run_dir)
                workflow_mode = "extract" if tool == "rulestripper" else "minimize"
                run_manifest = _write_run_dataset_manifest(run_dir, tool, workflow_mode)
            except Exception as exc:
                shutil.rmtree(run_dir, ignore_errors=True)
                self.send_json({"error": str(exc)}, 400)
                return
            friendly = "Rulestripper" if tool == "rulestripper" else "Rule Minimizer"
            STATE.update({
                "status": "running", "tool": tool, "paused": False, "pause_requested": False,
                "job_id": run_id, "started_at": time.time(), "finished_at": None, "pid": None,
                "stage": f"{friendly} · Starting", "stage_detail": f"Launching {friendly}…",
                "stage_started_at": time.time(), "progress": None, "progress_completed": None,
                "progress_total": None, "progress_rate": None, "progress_rules": None, "exit_code": None,
                "logs": [], "log_seq": 0, "log_generation": int(STATE.get("log_generation", 0)) + 1,
                "outputs": [], "error": None, "control_file": None, "run_dir": str(run_dir),
            })
            add_log(f"[WEB] Starting {friendly}…")
            add_log("[WEB] Inputs are mounted from the reusable library; temporary workflow files are cleaned after the job.")
            add_log("[WEB] Run input fingerprint recorded for repeated-dataset detection." if run_manifest else "[WEB] Run input fingerprint unavailable; this run may not appear in repeated-dataset scans.")
            add_log("[WEB] " + " ".join(cmd[2:]))
        thread = threading.Thread(target=run_worker, args=(cmd, run_id, run_dir, None, tool, storage_baseline_bytes), daemon=True)
        with LOCK:
            RUN_THREAD = thread
        thread.start()
        self.send_json({"ok": True, "job_id": run_id, "output": output_name, "tool": tool})

    def handle_tools_cancel(self):
        with LOCK:
            tool = STATE.get("tool")
            if STATE["status"] not in ("running", "stopping") or tool not in {"rulestripper", "minimizer"}:
                self.send_json({"error": "There is no active utility job to cancel."}, 409)
                return
            proc = PROCESS
            STATE["status"] = "stopping"
        add_log(f"[WEB] Cancellation requested for {tool}.")
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

    def handle_list_pcfg_profiles(self):
        """List saved ruleops.pcfg-profile.v1 JSON reports under reports/."""
        reports_dir = ROOT / "reports"
        items = []
        if reports_dir.is_dir():
            for path in sorted(reports_dir.glob("*.json")):
                try:
                    with path.open("r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    schema = str(data.get("schema") or "")
                    if "pcfg-profile" not in schema:
                        continue
                    input_meta = data.get("input") or {}
                    length = data.get("length") or {}
                    items.append({
                        "id": path.name,
                        "name": path.name,
                        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                        "file_name": input_meta.get("file_name") or path.stem,
                        "profiled_entries": int(
                            input_meta.get("profiled_entries")
                            or input_meta.get("weighted_observations")
                            or 0
                        ),
                        "weighted_mean_length": length.get("weighted_mean"),
                    })
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    continue
        self.send_json({"ok": True, "profiles": items})

    def handle_load_pcfg_profile(self):
        """Load one saved reports/*.json profile by id (filename)."""
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        profile_id = (qs.get("id") or [""])[0].strip()
        if not profile_id or "/" in profile_id or "\\" in profile_id or ".." in profile_id:
            self.send_json({"error": "Invalid profile id."}, 400)
            return
        path = ROOT / "reports" / profile_id
        if not path.is_file() or path.suffix.lower() != ".json":
            self.send_json({"error": "Profile not found."}, 404)
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if "pcfg-profile" not in str(data.get("schema") or ""):
                self.send_json({"error": "Not a pcfg-profile report."}, 400)
                return
        except (OSError, json.JSONDecodeError) as exc:
            self.send_json({"error": f"Unable to read profile: {exc}"}, 500)
            return
        self.send_json({
            "ok": True,
            "id": profile_id,
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "profile": data,
        })

    def handle_topn_seeds(self):
        """Lightweight Top-N seed generator for Stage S (--seed-rules)."""
        try:
            payload = self.read_json_body()
        except Exception as exc:
            self.send_json({"error": f"Invalid JSON body: {exc}"}, 400)
            return

        # NOTE: 0 is the documented "unlimited" value for both fields -- must
        # check for None/missing explicitly, not falsiness, or a sent 0 gets
        # silently replaced by the default before the validation below ever
        # sees it (which is exactly what happened before this fix).
        _top_n_raw = payload.get("top_n")
        _max_seeds_raw = payload.get("max_seeds")
        top_n = int(_top_n_raw) if _top_n_raw is not None else 400_000
        max_seeds = int(_max_seeds_raw) if _max_seeds_raw is not None else 150_000
        if top_n < 0:
            self.send_json({"error": "top_n must be >= 0 (0 = unlimited)"}, 400)
            return
        if 0 < top_n < 10_000:
            self.send_json({"error": "top_n must be 0 (unlimited) or >= 10000"}, 400)
            return
        if max_seeds < 0:
            self.send_json({"error": "max_seeds must be >= 0 (0 = unlimited)"}, 400)
            return

        target_meta = UPLOADS_META.get("target")
        if not target_meta or not Path(target_meta["path"]).is_file():
            self.send_json({"error": "Upload a Target wordlist first."}, 400)
            return

        target_path = Path(target_meta["path"])
        out_name = "topn_seeds.rule"
        out_path = UPLOADS / out_name

        complementary = bool(payload.get("complementary"))
        _adaptive_raw = payload.get("adaptive")
        adaptive = bool(_adaptive_raw) if _adaptive_raw is not None else True

        # Optional aggregate PCFG corpus profile (see run_pcfg_profile.py /
        # docs/PCFG_PROFILE.md): the browser reads the user's previously
        # generated report JSON client-side and sends the parsed object
        # here, so no server-side upload slot is needed for it. It only
        # nudges the existing family-budget priors toward this corpus's
        # measured digit/symbol/uppercase prevalence -- it is never treated
        # as password/affix data itself.
        pcfg_profile = payload.get("pcfg_profile")
        if pcfg_profile is not None and not isinstance(pcfg_profile, dict):
            self.send_json({"error": "pcfg_profile must be a parsed JSON object."}, 400)
            return

        try:
            from rulest.topn_seedgen import run as topn_run
            stats = topn_run(
                target_path=target_path,
                output_path=out_path,
                top_n=top_n,
                max_seeds=max_seeds,
                complementary=complementary,
                adaptive=adaptive,
                pcfg_profile=pcfg_profile,
            )
        except Exception as exc:
            add_log(f"[TOPN] Generation failed: {exc}")
            self.send_json({"error": f"Top-N seed generation failed: {exc}"}, 500)
            return

        # Register as the active custom seed file so the next rulest run picks it up.
        UPLOADS_META["seed"] = {
            "path": str(out_path),
            "name": out_name,
            "size": out_path.stat().st_size if out_path.is_file() else 0,
        }
        profile_note = ""
        if stats.get("pcfg_profile_applied"):
            ps = stats["pcfg_profile_summary"]
            profile_note = (
                f" (pcfg-profile applied: digits={ps['digit_share']*100:.1f}% "
                f"symbols={ps['symbol_share']*100:.1f}% uppercase={ps['uppercase_share']*100:.1f}%)"
            )
        add_log(
            f"[TOPN] Generated {stats['seeds_generated']:,} seeds "
            f"from {stats['passwords_loaded']:,} top passwords → {out_name}{profile_note}"
        )
        self.send_json({
            "ok": True,
            "seeds_generated": stats["seeds_generated"],
            "passwords_loaded": stats["passwords_loaded"],
            "top_n": top_n,
            "output_name": out_name,
            "registered_as_seed": True,
            "complementary": complementary,
            "adaptive": adaptive,
            "pcfg_profile_applied": stats.get("pcfg_profile_applied", False),
            "pcfg_profile_summary": stats.get("pcfg_profile_summary"),
        })

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
        command = {
            "pause": "p", "resume": "r",
            "stop": "q", "early_quit": "q", "quit": "q",
        }.get(action)
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
            elif action in ("stop", "early_quit", "quit"):
                STATE["status"] = "stopping"
                STATE["pause_requested"] = False
        labels = {
            "pause": "Pause requested",
            "resume": "Resume requested",
            "stop": "Partial-save exit requested",
            "early_quit": "Partial-save exit requested",
            "quit": "Partial-save exit requested",
        }
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
    ensure_runtime_directories()
    cleanup_stale_uploaded_files()
    server = RulestHTTPServer((args.host, args.port), Handler)
    actual_port = server.server_address[1]
    print()
    print("  RULEOPS v2.6.4  /  HASHCAT RULE TOOLCHAIN")
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
