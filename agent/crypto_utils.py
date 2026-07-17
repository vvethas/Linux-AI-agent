"""
Symmetric encryption helpers for sensitive credential storage.

All encryption/decryption uses Fernet (AES-128-CBC + HMAC-SHA256) with a
32-byte URL-safe base-64-encoded symmetric key supplied via the
AGENT_MASTER_KEY environment variable.

Key generation (run once, store the output as AGENT_MASTER_KEY):
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import base64
import hashlib
import io
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
import paramiko

_PW_KWARG = "password"


def _get_fernet() -> Fernet:
    """Return a Fernet instance using AGENT_MASTER_KEY, or raise RuntimeError."""
    raw = os.environ.get("AGENT_MASTER_KEY", "")
    if not raw:
        raise RuntimeError(
            "AGENT_MASTER_KEY environment variable is not set. "
            "Generate a key with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
            "and set it in the service environment before starting the agent."
        )
    return Fernet(raw.encode() if isinstance(raw, str) else raw)


def validate_master_key() -> None:
    """Called at startup to hard-fail if AGENT_MASTER_KEY is missing or invalid."""
    _get_fernet()  # raises RuntimeError if not set, TypeError if malformed


def encrypt_value(plaintext: str) -> str:
    """Encrypt *plaintext* and return a URL-safe base64 Fernet token (str)."""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_value(token: str) -> str:
    """Decrypt a Fernet *token* and return the original plaintext (str)."""
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Decryption failed — token is invalid or key has changed") from exc


def ssh_key_fingerprint(key_pem: str, passphrase: Optional[str] = None) -> str:
    """
    Return the SHA-256 fingerprint of *key_pem* in the format ``SHA256:xxxx``.

    Raises ``ValueError`` if the PEM cannot be parsed (wrong passphrase, bad format, etc.).
    """
    pw = passphrase.encode("utf-8") if passphrase else None
    kw = {_PW_KWARG: pw}
    for key_cls in (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,

    ):
        try:
            key = key_cls.from_private_key(io.StringIO(key_pem), **kw)
            pub_bytes = base64.b64decode(key.get_base64())
            digest = hashlib.sha256(pub_bytes).digest()
            b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
            return f"SHA256:{b64}"
        except paramiko.ssh_exception.PasswordRequiredException:
            raise ValueError("Private key requires a passphrase")
        except Exception:
            continue
    raise ValueError("Unable to parse private key — unsupported format or wrong passphrase")


def load_private_key(
    key_pem: str,
    passphrase: Optional[str] = None,
) -> paramiko.PKey:
    """
    Parse *key_pem* and return a :class:`paramiko.PKey` suitable for use in
    :meth:`paramiko.SSHClient.connect`.

    Raises ``ValueError`` on parse failure.
    """
    pw = passphrase.encode("utf-8") if passphrase else None
    kw = {_PW_KWARG: pw}
    for key_cls in (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,

    ):
        try:
            return key_cls.from_private_key(io.StringIO(key_pem), **kw)
        except paramiko.ssh_exception.PasswordRequiredException:
            raise ValueError("Private key requires a passphrase")
        except Exception:
            continue
    raise ValueError("Unable to parse private key — unsupported format or wrong passphrase")
