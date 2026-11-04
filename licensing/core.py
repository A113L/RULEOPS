"""Offline Ed25519 license verification and per-module DEMO usage for RULEOPS.

Private signing keys never belong in customer installations.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
LICENSE_FILE = ROOT / "license.lic"
PUBLIC_KEY_FILE = ROOT / "licensing" / "public_key.pem"
USAGE_DB = ROOT / "license_usage.sqlite3"

# Three full runs per module, then that module enters DEMO LIMITED.
DEMO_LIMIT = 3

MODULES = ("RULEST", "RULE_RANKER", "CONCENTRATOR")
FEATURES = {"RULEST", "RULE_RANKER", "CONCENTRATOR", "GPU", "CELF"}

# Map API / internal tool names to canonical module keys.
TOOL_ALIASES = {
    "rulest": "RULEST",
    "RULEST": "RULEST",
    "ranker": "RULE_RANKER",
    "rule_ranker": "RULE_RANKER",
    "RULE_RANKER": "RULE_RANKER",
    "concentrator": "CONCENTRATOR",
    "CONCENTRATOR": "CONCENTRATOR",
}


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def machine_id() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass
    return str(uuid.getnode())


def load_license(path: Optional[Path] = None) -> Dict[str, Any]:
    path = Path(path) if path is not None else LICENSE_FILE
    if not path.is_file() or not PUBLIC_KEY_FILE.is_file():
        return {"edition": "DEMO", "valid": False, "reason": "No signed license installed"}
    try:
        from cryptography.hazmat.primitives import serialization

        envelope = json.loads(path.read_text(encoding="utf-8"))
        payload = envelope["payload"]
        signature = base64.b64decode(envelope["signature"], validate=True)
        key = serialization.load_pem_public_key(PUBLIC_KEY_FILE.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Wrong public key type")
        key.verify(signature, canonical(payload))
        if payload.get("product") != "RULEOPS":
            raise ValueError("Wrong product")
        if payload.get("valid_until") and int(time.time()) > int(payload["valid_until"]):
            return {"edition": "DEMO", "valid": False, "reason": "License expired"}
        bound = payload.get("machine_id")
        if bound and bound != machine_id():
            return {"edition": "DEMO", "valid": False, "reason": "License belongs to another machine"}
        edition = str(payload.get("edition") or "PROFESSIONAL").upper()
        if edition not in ("PROFESSIONAL", "ENTERPRISE"):
            edition = "PROFESSIONAL"
        return {**payload, "edition": edition, "valid": True, "reason": "Valid signed license"}
    except (OSError, ValueError, KeyError, TypeError, InvalidSignature) as exc:
        return {"edition": "DEMO", "valid": False, "reason": f"Invalid license: {type(exc).__name__}"}


def is_fully_licensed() -> bool:
    lic = load_license()
    return bool(lic.get("valid")) and str(lic.get("edition", "")).upper() in ("PROFESSIONAL", "ENTERPRISE")


def normalize_module(tool: str) -> str:
    key = TOOL_ALIASES.get(str(tool or "").strip())
    if not key:
        raise ValueError(f"Unknown module/tool: {tool!r}")
    return key


def _usage_db_connect() -> sqlite3.Connection:
    USAGE_DB.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        USAGE_DB,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    os.close(descriptor)
    try:
        os.chmod(USAGE_DB, 0o600)
    except OSError:
        pass
    conn = sqlite3.connect(str(USAGE_DB), timeout=5.0)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS demo_usage (
            module TEXT NOT NULL,
            used_at INTEGER NOT NULL,
            tool_path TEXT,
            id INTEGER PRIMARY KEY AUTOINCREMENT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS demo_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    return conn


@contextmanager
def usage_db_session():
    conn = _usage_db_connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_module_usage_count(module: str) -> int:
    module = normalize_module(module)
    with usage_db_session() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM demo_usage WHERE module = ?",
            (module,),
        ).fetchone()
        return int(row[0] if row else 0)


def get_all_usage_counts() -> Dict[str, int]:
    with usage_db_session() as conn:
        rows = conn.execute(
            "SELECT module, COUNT(*) FROM demo_usage GROUP BY module"
        ).fetchall()
    counts = {m: 0 for m in MODULES}
    for module, count in rows:
        if module in counts:
            counts[module] = int(count)
    return counts


def module_mode(module: str) -> str:
    """Return FULL, DEMO, or DEMO_LIMITED for a module."""
    if is_fully_licensed():
        return "FULL"
    used = get_module_usage_count(module)
    if used >= DEMO_LIMIT:
        return "DEMO_LIMITED"
    return "DEMO"


def remaining_demo_runs(module: str) -> int:
    if is_fully_licensed():
        return -1  # unlimited
    used = get_module_usage_count(module)
    return max(0, DEMO_LIMIT - used)


def record_module_run(module: str, tool_path: str = "") -> Dict[str, Any]:
    """Atomically record one full demo run for a module. Returns new status."""
    module = normalize_module(module)
    if is_fully_licensed():
        return {
            "module": module,
            "mode": "FULL",
            "used": 0,
            "remaining": -1,
            "recorded": False,
        }
    with usage_db_session() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT COUNT(*) FROM demo_usage WHERE module = ?",
            (module,),
        ).fetchone()
        used = int(row[0] if row else 0)
        if used >= DEMO_LIMIT:
            return {
                "module": module,
                "mode": "DEMO_LIMITED",
                "used": used,
                "remaining": 0,
                "recorded": False,
            }
        conn.execute(
            "INSERT INTO demo_usage(module, used_at, tool_path) VALUES (?, ?, ?)",
            (module, int(time.time()), tool_path or ""),
        )
        used += 1
    mode = "DEMO_LIMITED" if used >= DEMO_LIMIT else "DEMO"
    return {
        "module": module,
        "mode": mode,
        "used": used,
        "remaining": max(0, DEMO_LIMIT - used),
        "recorded": True,
    }


def can_start_full_run(module: str) -> Dict[str, Any]:
    """Decide whether a run is allowed and in which mode."""
    module = normalize_module(module)
    if is_fully_licensed():
        return {"allowed": True, "mode": "FULL", "reason": "Licensed"}
    used = get_module_usage_count(module)
    if used < DEMO_LIMIT:
        return {
            "allowed": True,
            "mode": "DEMO",
            "used": used,
            "remaining": DEMO_LIMIT - used,
            "reason": f"DEMO run {used + 1} of {DEMO_LIMIT}",
        }
    return {
        "allowed": True,
        "mode": "DEMO_LIMITED",
        "used": used,
        "remaining": 0,
        "reason": (
            f"DEMO limit reached for {module} ({DEMO_LIMIT} full runs). "
            "Module is in DEMO LIMITED mode. Install a signed license for full features."
        ),
    }


def celf_restrictions(module: str) -> Dict[str, Any]:
    """Return CELF capability flags for the current license/demo state.

    FULL (licensed): no restrictions.
    DEMO (still has free full runs): basic CELF demonstration allowed with soft caps.
    DEMO_LIMITED: advanced CELF blocked; only a minimal demonstration path remains.
    """
    mode = module_mode(module)
    if mode == "FULL":
        return {
            "mode": mode,
            "celf_allowed": True,
            "celf_advanced_allowed": True,
            "max_candidates": None,
            "max_budget": None,
            "greedy_allowed": True,
            "gpu_recompute_allowed": True,
            "message": "Full CELF available",
        }
    if mode == "DEMO":
        return {
            "mode": mode,
            "celf_allowed": True,
            "celf_advanced_allowed": True,
            "max_candidates": 5000,
            "max_budget": 500,
            "greedy_allowed": True,
            "gpu_recompute_allowed": True,
            "message": "DEMO: CELF available with demonstration caps",
        }
    return {
        "mode": mode,
        "celf_allowed": True,
        "celf_advanced_allowed": False,
        "max_candidates": 500,
        "max_budget": 64,
        "greedy_allowed": False,
        "gpu_recompute_allowed": False,
        "message": (
            "DEMO LIMITED: advanced CELF disabled. "
            "Only a minimal frequency-style demonstration remains. "
            "Install a PROFESSIONAL or ENTERPRISE license to unlock full CELF."
        ),
    }


def apply_celf_limits(options: Optional[dict], module: str = "RULE_RANKER") -> Dict[str, Any]:
    """Clamp or strip advanced CELF options according to current mode."""
    opts = dict(options or {})
    rules = celf_restrictions(module)
    opts["_license_mode"] = rules["mode"]
    opts["_celf_message"] = rules["message"]

    if rules["mode"] == "FULL":
        return opts

    if rules.get("max_candidates") is not None:
        try:
            current = int(opts.get("candidates") or opts.get("max_candidates") or rules["max_candidates"])
        except (TypeError, ValueError):
            current = rules["max_candidates"]
        opts["candidates"] = min(current, rules["max_candidates"])
        opts["max_candidates"] = opts["candidates"]

    if rules.get("max_budget") is not None:
        try:
            current = int(opts.get("budget") or opts.get("select_budget") or rules["max_budget"])
        except (TypeError, ValueError):
            current = rules["max_budget"]
        opts["budget"] = min(current, rules["max_budget"])
        opts["select_budget"] = opts["budget"]

    if not rules.get("greedy_allowed"):
        opts["select_mode"] = "frequency"
        opts["greedy"] = False
        opts["celf"] = False
        opts["use_celf"] = False

    if not rules.get("gpu_recompute_allowed"):
        opts["gpu_recompute"] = False
        opts["celf_gpu"] = False

    if not rules.get("celf_advanced_allowed"):
        opts.pop("budgets", None)
        opts.pop("cost_alpha", None)
        opts["advanced_celf"] = False

    return opts


def license_summary() -> Dict[str, Any]:
    lic = load_license()
    counts = get_all_usage_counts()
    modules = {}
    for module in MODULES:
        mode = module_mode(module)
        used = counts.get(module, 0)
        modules[module] = {
            "mode": mode,
            "used": used if not is_fully_licensed() else 0,
            "limit": DEMO_LIMIT,
            "remaining": remaining_demo_runs(module),
            "celf": celf_restrictions(module),
        }
    return {
        "edition": lic.get("edition", "DEMO"),
        "valid": bool(lic.get("valid")),
        "customer": lic.get("customer", ""),
        "license_id": lic.get("license_id", ""),
        "valid_until": lic.get("valid_until"),
        "max_users": lic.get("max_users", 1),
        "machine_id": machine_id(),
        "reason": lic.get("reason", ""),
        "demo_limit": DEMO_LIMIT,
        "modules": modules,
        "fully_licensed": is_fully_licensed(),
    }


def reset_demo_usage(module: Optional[str] = None) -> None:
    """Admin-only helper: clear counters (e.g. after license install tests)."""
    with usage_db_session() as conn:
        if module:
            module = normalize_module(module)
            conn.execute("DELETE FROM demo_usage WHERE module = ?", (module,))
        else:
            conn.execute("DELETE FROM demo_usage")
