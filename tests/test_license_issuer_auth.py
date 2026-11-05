import base64
import hashlib

import license_admin


def test_issuer_password_verification_uses_salted_pbkdf2(monkeypatch):
    phrase = "issuer-test-passphrase-2026"
    salt = b"test-only-salt-123"
    iterations = 10_000
    digest = hashlib.pbkdf2_hmac("sha256", phrase.encode("utf-8"), salt, iterations, dklen=32)

    monkeypatch.setattr(license_admin, "ISSUER_PASSWORD_SALT", salt)
    monkeypatch.setattr(license_admin, "ISSUER_PASSWORD_HASH", digest)
    monkeypatch.setattr(license_admin, "ISSUER_PASSWORD_ITERATIONS", iterations)

    assert license_admin.password_ok(phrase)
    assert not license_admin.password_ok("different-passphrase")
    assert not license_admin.password_ok("")
    assert not license_admin.password_ok(None)
    assert not license_admin.password_ok("x" * 1025)


def test_issuer_password_is_not_taken_from_environment(monkeypatch):
    monkeypatch.setenv("RULEOPS_LICENSE_ADMIN_PASSWORD", "environment-override-that-must-not-work")
    assert not license_admin.password_ok("environment-override-that-must-not-work")


def test_builtin_issuer_verifier_is_well_formed():
    assert license_admin.ISSUER_PASSWORD_ITERATIONS >= 600_000
    assert len(license_admin.ISSUER_PASSWORD_SALT) >= 16
    assert len(license_admin.ISSUER_PASSWORD_HASH) == 32
