"""SSH key lifecycle helpers.

Pure functions over the ``cryptography`` library. The admin layer wraps
these into REST endpoints; the DB layer just stores the resulting text.

Supported types:
* ed25519 (recommended; fixed 256-bit)
* rsa     (2048 / 3072 / 4096 bits)
* ecdsa   (256 / 384 / 521 bit nistp curves)

Imported keys are tolerated even when the operator only provides the
private key — we always derive the public key + fingerprint so the UI
can show them consistently.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
  dsa,
  ec,
  ed25519,
  rsa,
)
from cryptography.hazmat.backends import default_backend

LOGGER = logging.getLogger("ssl_proxy_controller.ssh_keys")

KEY_TYPES = ("ed25519", "rsa", "ecdsa", "dsa")
RSA_DEFAULT_BITS = 3072
RSA_VALID_BITS = (2048, 3072, 4096)
ECDSA_CURVES = {
  256: ec.SECP256R1,  # nistp256
  384: ec.SECP384R1,  # nistp384
  521: ec.SECP521R1,  # nistp521
}


@dataclass(slots=True)
class GeneratedKey:
  """Output of ``generate_keypair`` — also matches what the DB stores."""
  key_type: str
  bits: int | None
  private_key: str
  public_key: str
  fingerprint_sha256: str
  comment: str


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def generate_keypair(
  key_type: str = "ed25519",
  *,
  bits: int | None = None,
  comment: str = "",
  passphrase: str | None = None,
) -> GeneratedKey:
  """Generate a fresh SSH keypair.

  ``passphrase`` encrypts the private-key PEM at rest. Stored as-is in
  the DB record's ``passphrase`` column so a future read can serialize
  the same passphrase back into the OpenSSH file.
  """
  key_type = (key_type or "ed25519").lower()
  if key_type not in KEY_TYPES:
    raise ValueError(f"unsupported key_type: {key_type}")

  if key_type == "ed25519":
    private = ed25519.Ed25519PrivateKey.generate()
    actual_bits = 256
  elif key_type == "rsa":
    n = bits or RSA_DEFAULT_BITS
    if n not in RSA_VALID_BITS:
      raise ValueError(f"rsa bits must be one of {RSA_VALID_BITS}")
    private = rsa.generate_private_key(public_exponent=65537, key_size=n, backend=default_backend())
    actual_bits = n
  elif key_type == "ecdsa":
    curve_bits = bits or 256
    curve_cls = ECDSA_CURVES.get(curve_bits)
    if curve_cls is None:
      raise ValueError(f"ecdsa bits must be one of {sorted(ECDSA_CURVES)}")
    private = ec.generate_private_key(curve_cls(), backend=default_backend())
    actual_bits = curve_bits
  elif key_type == "dsa":
    n = bits or 2048
    private = dsa.generate_private_key(key_size=n, backend=default_backend())
    actual_bits = n
  else:  # pragma: no cover — guarded above
    raise ValueError(f"unsupported key_type: {key_type}")

  enc = (
    serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    if passphrase
    else serialization.NoEncryption()
  )
  private_pem = private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH,
    encryption_algorithm=enc,
  ).decode("utf-8")

  public_ssh = private.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH,
  ).decode("utf-8")

  if comment:
    public_ssh = public_ssh.split(" ", 2)
    if len(public_ssh) >= 2:
      public_ssh = f"{public_ssh[0]} {public_ssh[1]} {comment}"
    else:
      public_ssh = f"{public_ssh[0]} {comment}"
  fp = sha256_fingerprint(public_ssh)
  return GeneratedKey(
    key_type=key_type,
    bits=actual_bits,
    private_key=private_pem,
    public_key=public_ssh,
    fingerprint_sha256=fp,
    comment=comment or "",
  )


# ---------------------------------------------------------------------------
# Import / parsing
# ---------------------------------------------------------------------------


def parse_private_key(
  private_key_text: str,
  passphrase: str | None = None,
) -> dict[str, Any]:
  """Parse a pasted private key and return metadata + derived public key.

  Returns ``{key_type, bits, private_key, public_key, fingerprint_sha256, comment}``.
  Raises ``ValueError`` with a friendly message on failure.
  """
  text = (private_key_text or "").strip()
  if not text:
    raise ValueError("private key is empty")

  pw = passphrase.encode("utf-8") if passphrase else None
  data = text.encode("utf-8")

  # Try the standard loaders in order.
  loaders = (
    ("openssh", lambda: serialization.load_ssh_private_key(data, password=pw, backend=default_backend())),
    ("pem",     lambda: serialization.load_pem_private_key(data, password=pw, backend=default_backend())),
    ("der",     lambda: serialization.load_der_private_key(data, password=pw, backend=default_backend())),
  )
  last_exc: Exception | None = None
  private = None
  for label, fn in loaders:
    try:
      private = fn()
      LOGGER.debug("parsed private key as %s", label)
      break
    except Exception as exc:  # noqa: BLE001
      last_exc = exc
  if private is None:
    msg = str(last_exc) if last_exc else "unrecognized format"
    raise ValueError(f"could not parse private key: {msg}")

  if isinstance(private, ed25519.Ed25519PrivateKey):
    key_type, bits = "ed25519", 256
  elif isinstance(private, rsa.RSAPrivateKey):
    key_type, bits = "rsa", private.key_size
  elif isinstance(private, ec.EllipticCurvePrivateKey):
    key_type, bits = "ecdsa", private.curve.key_size
  elif isinstance(private, dsa.DSAPrivateKey):
    key_type, bits = "dsa", private.key_size
  else:
    raise ValueError(f"unsupported key type: {type(private).__name__}")

  enc = (
    serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
  )
  # Re-serialize so the stored PEM is canonical OpenSSH form.
  private_pem = private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH,
    encryption_algorithm=enc,
  ).decode("utf-8")
  public_ssh = private.public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH,
  ).decode("utf-8")
  fp = sha256_fingerprint(public_ssh)
  return {
    "key_type": key_type,
    "bits": bits,
    "private_key": private_pem,
    "public_key": public_ssh,
    "fingerprint_sha256": fp,
    "comment": "",
  }


def parse_public_key(public_key_text: str) -> dict[str, Any]:
  """Parse a pasted public key (e.g. authorized_keys line).

  Returns ``{key_type, bits, public_key, fingerprint_sha256, comment}``.
  """
  text = (public_key_text or "").strip()
  if not text:
    raise ValueError("public key is empty")
  parts = text.split(None, 2)
  if len(parts) < 2:
    raise ValueError("expected at least 'algorithm base64' on one line")
  algo = parts[0]
  comment = parts[2] if len(parts) >= 3 else ""

  try:
    public = serialization.load_ssh_public_key(text.encode("utf-8"), backend=default_backend())
  except Exception as exc:  # noqa: BLE001
    raise ValueError(f"could not parse public key: {exc}") from exc

  if isinstance(public, ed25519.Ed25519PublicKey):
    key_type, bits = "ed25519", 256
  elif isinstance(public, rsa.RSAPublicKey):
    key_type, bits = "rsa", public.key_size
  elif isinstance(public, ec.EllipticCurvePublicKey):
    key_type, bits = "ecdsa", public.curve.key_size
  elif isinstance(public, dsa.DSAPublicKey):
    key_type, bits = "dsa", public.key_size
  else:
    raise ValueError(f"unsupported public key type: {algo}")

  fp = sha256_fingerprint(text)
  return {
    "key_type": key_type,
    "bits": bits,
    "public_key": text,
    "fingerprint_sha256": fp,
    "comment": comment,
  }


def sha256_fingerprint(public_key_ssh: str) -> str:
  """Return ``SHA256:...`` fingerprint identical to ``ssh-keygen -lf``."""
  text = (public_key_ssh or "").strip()
  parts = text.split(None, 2)
  if len(parts) < 2:
    raise ValueError("public key has no base64 body")
  try:
    raw = base64.b64decode(parts[1])
  except Exception as exc:  # noqa: BLE001
    raise ValueError(f"bad base64: {exc}") from exc
  digest = hashlib.sha256(raw).digest()
  return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


__all__ = [
  "KEY_TYPES",
  "RSA_DEFAULT_BITS",
  "RSA_VALID_BITS",
  "ECDSA_CURVES",
  "GeneratedKey",
  "generate_keypair",
  "parse_private_key",
  "parse_public_key",
  "sha256_fingerprint",
]
