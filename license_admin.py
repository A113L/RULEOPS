#!/usr/bin/env python3
"""Private, LAN-accessible offline license issuer. Run only on the owner's machine.

Authentication is password-only (no username). The issuer password is verified
against a PBKDF2-HMAC-SHA256 hash embedded in this file; the plaintext password
is never stored in the source. Run:

    python3 license_admin.py --host 0.0.0.0 --port 8766
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
KEYDIR = ROOT / "license_issuer_private"
OUT = ROOT / "issued_licenses"
KEYDIR.mkdir(mode=0o700, exist_ok=True)
OUT.mkdir(mode=0o700, exist_ok=True)
PRIV = KEYDIR / "ed25519_private.pem"
PUB = ROOT / "licensing" / "public_key.pem"

# In-memory sessions after form login (password-only).
SESSIONS: dict[str, float] = {}
SESSION_TTL = 12 * 60 * 60
SESSION_COOKIE = "ruleops_issuer_session"

# Built-in issuer credential verifier. This is a salted PBKDF2-HMAC-SHA256
# digest, not an encrypted/reversible password. Keep the plaintext out of source.
ISSUER_PASSWORD_ITERATIONS = 600_000
ISSUER_PASSWORD_SALT = base64.b64decode("05w7dO9w55cWfd0JDZ5pGQ==")
ISSUER_PASSWORD_HASH = base64.b64decode("R/Ef7H9riS0vYErQ87mBN9h3i+roKaltIYDlTPnbkzc=")


def ensure_keys() -> None:
    if PRIV.exists() and PUB.exists():
        return
    if PRIV.exists() or PUB.exists():
        raise RuntimeError(
            "Incomplete keypair. Restore both keys from backup; refusing to replace."
        )
    key = Ed25519PrivateKey.generate()
    PRIV.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    PUB.parent.mkdir(parents=True, exist_ok=True)
    PUB.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(PRIV, 0o600)
    os.chmod(KEYDIR, 0o700)


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def password_ok(supplied: str) -> bool:
    """Verify the built-in issuer password without storing it in plaintext."""
    if not isinstance(supplied, str) or not supplied or len(supplied) > 1024:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        supplied.encode("utf-8"),
        ISSUER_PASSWORD_SALT,
        ISSUER_PASSWORD_ITERATIONS,
        dklen=len(ISSUER_PASSWORD_HASH),
    )
    return hmac.compare_digest(actual, ISSUER_PASSWORD_HASH)


def purge_sessions() -> None:
    now = time.time()
    dead = [token for token, expires in SESSIONS.items() if expires <= now]
    for token in dead:
        SESSIONS.pop(token, None)


def create_session() -> str:
    purge_sessions()
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token


def session_valid(handler: BaseHTTPRequestHandler) -> bool:
    purge_sessions()
    cookie = handler.headers.get("Cookie", "")
    token = None
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith(SESSION_COOKIE + "="):
            token = part.split("=", 1)[1].strip()
            break
    if not token:
        return False
    expires = SESSIONS.get(token)
    if not expires or expires <= time.time():
        SESSIONS.pop(token, None)
        return False
    # Sliding expiry
    SESSIONS[token] = time.time() + SESSION_TTL
    return True


def login_page(error: str = "") -> str:
    err = (
        f'<p class="err">{html.escape(error)}</p>'
        if error
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RULEOPS License Manager — Sign in</title>
<style>
  body{{font:16px system-ui,sans-serif;max-width:420px;margin:64px auto;padding:0 18px;background:#101827;color:#e8eef8}}
  h1{{font-size:1.35rem;margin:0 0 8px}}
  p{{color:#9aa8bd;line-height:1.45}}
  section{{background:#1b2940;padding:24px;border-radius:14px;margin:18px 0}}
  label{{display:block;margin:12px 0 6px;font-size:13px;color:#b7c3d6}}
  input{{width:100%;box-sizing:border-box;font:inherit;padding:12px;border-radius:8px;border:1px solid #52627b;background:#0d1420;color:#e8eef8}}
  button{{margin-top:16px;width:100%;font:inherit;padding:12px;border-radius:8px;border:0;background:#68a7ff;color:#071426;font-weight:700;cursor:pointer}}
  .err{{color:#f0a090;background:#2a1612;border:1px solid #6b3a2a;padding:10px 12px;border-radius:8px}}
  .hint{{font-size:12px;color:#7a8aa3;margin-top:14px}}
</style>
<h1>RULEOPS License Manager</h1>
<section>
  <form method="post" action="/login" autocomplete="current-password">
    <label for="password">Issuer password</label>
    <input id="password" name="password" type="password" required minlength="16" autofocus
           autocomplete="current-password" placeholder="Enter issuer password">
    {err}
    <button type="submit">Sign in</button>
  </form>
</section>
"""


def app_page(msg: str = "") -> str:
    notice = f'<p class="msg">{html.escape(msg)}</p>' if msg else ""
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RULEOPS License Manager</title>
<style>
  body{{font:16px system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 18px;background:#101827;color:#e8eef8}}
  section{{background:#1b2940;padding:24px;border-radius:14px;margin:18px 0}}
  input,select,button{{font:inherit;padding:10px;margin:6px 0;border-radius:7px;border:1px solid #52627b}}
  input,select{{width:min(95%,480px);background:#0d1420;color:#e8eef8}}
  button{{background:#68a7ff;color:#071426;font-weight:bold;cursor:pointer;border:0}}
  label{{display:block;margin-top:10px}}
  .msg{{color:#9fe3b1}}
  .top{{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}}
  a.logout{{color:#9eb0c8;font-size:14px}}
</style>
<div class="top">
  <h1>RULEOPS License Manager</h1>
  <a class="logout" href="/logout">Sign out</a>
</div>
<p>Private offline license issuer — keep this service on your trusted LAN.</p>
{notice}
<section>
  <h2>Generate signed license</h2>
  <form method="post" action="/issue">
    <label>Customer / company</label>
    <input name="customer" required maxlength="120">
    <label>Edition</label>
    <select name="edition"><option>PROFESSIONAL</option><option>ENTERPRISE</option></select>
    <label>Validity</label>
    <select name="days">
      <option value="0">Forever (no expiry)</option>
      <option value="30">30 days</option>
      <option value="365">1 year</option>
      <option value="730">2 years</option>
    </select>
    <label>Max users (ENTERPRISE only; recorded in license)</label>
    <input name="max_users" type="number" min="1" max="500" value="1">
    <label>Optional machine-id bind (Linux /etc/machine-id; leave blank for transferable)</label>
    <input name="machine_id" maxlength="128" placeholder="optional">
    <button type="submit">Issue &amp; download .lic</button>
  </form>
</section>
<section>
  <h2>Issuer status</h2>
  <p>Ed25519 signing key: present. Private key only on this machine in <code>license_issuer_private/</code>.</p>
  <p>Back up that private key securely. Losing it means previously issued licenses remain valid, but you cannot issue compatible new ones with a new key.</p>
  <p>Public key for customer installs: <code>licensing/public_key.pem</code></p>
</section>
"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _send_html(self, body: str, status: int = 200, extra_headers: list | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers:
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _require_session(self) -> bool:
        if session_valid(self):
            return True
        self._send_html(login_page())
        return False

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/logout":
            # Clear cookie; best-effort drop token
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith(SESSION_COOKIE + "="):
                    SESSIONS.pop(part.split("=", 1)[1].strip(), None)
            self._send_html(
                login_page("Signed out."),
                extra_headers=[
                    ("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                ],
            )
            return
        if path in ("/", "/index", "/index.html"):
            if not session_valid(self):
                self._send_html(login_page())
                return
            self._send_html(app_page())
            return
        self.send_error(404)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        length = max(0, min(length, 8192))
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        data = parse_qs(raw)

        if path == "/login":
            password = (data.get("password") or [""])[0]
            if not password_ok(password):
                self._send_html(login_page("Incorrect password."), status=401)
                return
            token = create_session()
            self._send_html(
                app_page("Signed in."),
                extra_headers=[
                    (
                        "Set-Cookie",
                        f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}",
                    )
                ],
            )
            return

        if path == "/issue":
            if not session_valid(self):
                self._send_html(login_page("Sign in required."), status=401)
                return
            try:
                customer = (data.get("customer") or [""])[0].strip()[:120]
                edition = (data.get("edition") or [""])[0]
                days = int((data.get("days") or ["0"])[0])
                users = int((data.get("max_users") or ["1"])[0])
                mid = (data.get("machine_id") or [""])[0].strip()[:128]
                if not customer or edition not in ("PROFESSIONAL", "ENTERPRISE"):
                    raise ValueError("Invalid form data")
                if days not in (0, 30, 365, 730) or not 1 <= users <= 500:
                    raise ValueError("Invalid form data")
                if edition == "PROFESSIONAL":
                    users = 1
                payload = {
                    "product": "RULEOPS",
                    "edition": edition,
                    "license_id": "ROP-"
                    + time.strftime("%Y%m%d")
                    + "-"
                    + uuid.uuid4().hex[:10].upper(),
                    "customer": customer,
                    "issued_at": int(time.time()),
                    "valid_until": int(time.time()) + days * 86400 if days else None,
                    "max_users": users,
                    "machine_id": mid or None,
                    "features": ["RULEST", "RULE_RANKER", "CONCENTRATOR", "GPU"],
                }
                key = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
                envelope = {
                    "payload": payload,
                    "signature": base64.b64encode(key.sign(canonical(payload))).decode(),
                }
                blob = (json.dumps(envelope, indent=2, ensure_ascii=False) + "\n").encode()
                name = payload["license_id"] + ".lic"
                target = OUT / name
                target.write_bytes(blob)
                os.chmod(target, 0o600)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Content-Length", str(len(blob)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(blob)
            except Exception as exc:
                self._send_html(app_page("Could not issue license: " + str(exc)), status=400)
            return

        self.send_error(404)


def main() -> None:
    parser = argparse.ArgumentParser(description="RULEOPS offline license issuer")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    ensure_keys()
    print(f"RULEOPS License Manager: http://<this-LAN-IP>:{args.port}/")
    print("Password-only login (no username). Built-in PBKDF2 verifier; trusted LAN only. Ctrl+C to stop.")
    ThreadingHTTPServer((args.host, args.port), H).serve_forever()


if __name__ == "__main__":
    main()
