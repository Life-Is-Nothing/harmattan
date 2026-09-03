"""
HARMATTAN — Auto-generate self-signed TLS certificate.
Uses cryptography library (already a dependency via scikit-learn chain).
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("harmattan.https_cert")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def ensure_self_signed_cert(
    cert_dir: Path,
    key_size: int = 2048,
    validity_days: int = 365,
) -> tuple[Path, Path]:
    """Generate a self-signed cert+key pair in *cert_dir* if not present.

    Returns (cert_path, key_path).
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "harmattan.crt"
    key_path = cert_dir / "harmattan.key"

    if cert_path.is_file() and key_path.is_file():
        log.info("Existing TLS cert found at %s", cert_path)
        return cert_path, key_path

    if not _CRYPTO_AVAILABLE:
        log.warning("cryptography not available — HTTPS cert generation skipped")
        raise RuntimeError("cryptography library required for HTTPS cert generation")

    log.info("Generating self-signed TLS certificate…")

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HARMATTAN"),
        x509.NameAttribute(NameOID.COMMON_NAME, "harmattan.local"),
    ])

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("harmattan.local"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    # Write key (PKCS8 "BEGIN PRIVATE KEY" format)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)

    # Write cert
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    log.info("Self-signed cert generated: %s", cert_path)
    return cert_path, key_path
