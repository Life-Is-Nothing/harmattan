"""
HARMATTAN — TLS-Analyzer: certificate inspection & weakness hints.

For each host:port running TLS (443, 8443, 10443, 5000…), opens a socket, performs a
TLS handshake and inspects the presented certificate (expiry, issuer, SAN, self-signed,
weak key length). Emits hardening hints. No private key handling; informational only.

Authorized targets only.
"""
from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from core.logging_setup import get_logger

log = get_logger("harmattan.tls_analyzer")

TLS_PORTS = [443, 8443, 4433, 10443, 5000, 4443]
EXPIRY_WARN_DAYS = 30
EXPIRY_CRIT_DAYS = 7


def _weak_hints(cert: dict) -> list[str]:
    hints = []
    if cert.get("self_signed"):
        hints.append("Certificat auto-signé — vérifier l'authenticité.")
    sig = (cert.get("signature_algo") or "").lower()
    if "sha1" in sig or "md5" in sig or "sha-1" in sig:
        hints.append("Signature faible (SHA-1/MD5) — renouveler avec SHA-256+.")
    # key length heuristics
    try:
        kl = int(cert.get("key_bits") or 0)
        if kl and kl < 2048:
            hints.append(f"Clé RSA faible ({kl} bits) — ≥2048 recommandé.")
    except (TypeError, ValueError):
        pass
    if cert.get("days_remaining") is not None and cert["days_remaining"] < EXPIRY_CRIT_DAYS:
        hints.append("Certificat expire très bientôt !")
    elif cert.get("days_remaining") is not None and cert["days_remaining"] < EXPIRY_WARN_DAYS:
        hints.append("Certificat expire bientôt (renouvellement à prévoir).")
    if cert.get("expired"):
        hints.append("Certificat EXPIRÉ.")
    return hints[:8]


def inspect_host(ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Connect and inspect TLS certificate on (ip, port).

    NOTE: this is a READ-ONLY scanner (like Nmap's ssl-cert script). It deliberately
    disables verification (CERT_NONE) because its job is to *accept and inspect*
    arbitrary certificates — including self-signed / expired ones — so it can report
    their properties. This context never makes a trusted, confidential connection and
    never handles private keys. Do not copy this pattern into anything that carries
    real traffic.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # intentional: scanner must inspect untrusted certs
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                der = s.getpeercert(binary_form=True)
                # parse via ssl or cryptography
                try:
                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(der)
                    now = datetime.now(timezone.utc)
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    days = (not_after - now).days
                    san = []
                    try:
                        san = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                    except Exception:  # noqa: BLE001
                        pass
                    data = {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_remaining": days,
                        "expired": days < 0,
                        "self_signed": cert.subject == cert.issuer,
                        "signature_algo": cert.signature_algorithm_oid._name,
                        "key_bits": (cert.public_key().key_size
                                     if hasattr(cert.public_key(), "key_size") else None),
                        "san": san,
                    }
                except ImportError:
                    # fallback: minimal from ssl module
                    data = {
                        "subject": s.getpeercert().get("subject"),
                        "days_remaining": None,
                        "expired": None,
                        "self_signed": None,
                        "hints": ["cryptography non installé — analyse limitée"],
                    }
                data["port"] = port
                data["hints"] = _weak_hints(data)
                return data
    except ssl.SSLError as e:
        return {"ip": ip, "port": port, "ok": False, "error": f"TLS: {e}"}
    except OSError as e:
        return {"ip": ip, "port": port, "ok": False, "error": str(e)}


def scan_hosts(hosts: list[dict], ports: list[int] | None = None,
               max_hosts: int = 40, timeout: float = 2.5) -> dict:
    """
    Scan hosts (dicts with `ip`) for TLS certs. Returns:
        {
            "certificates": [ {ip, port, ...}, ... ],
            "count": int,
            "hints": [str, ...],   # unique weakness hints
            "generated_at": None,
        }
    """
    ports = [int(p) for p in (ports or TLS_PORTS)]
    results = []
    all_hints = set()

    for h in (hosts or [])[:max_hosts]:
        ip = h.get("ip")
        if not ip:
            continue
        # try each TLS port, stop at first that yields a cert
        found = False
        for port in ports:
            r = inspect_host(ip, port, timeout)
            if r.get("ok") is False:
                continue
            r["ip"] = ip
            results.append(r)
            for hint in r.get("hints") or []:
                all_hints.add(hint)
            found = True
            break
        if not found:
            # record a single "no tls" entry per host to bound output
            results.append({"ip": ip, "ok": False, "error": "no tls service on common ports"})

    return {
        "certificates": results,
        "count": len(results),
        "hints": sorted(all_hints),
        "generated_at": None,
    }


def summarize(result: dict) -> str:
    n = result.get("count", 0)
    bad = sum(1 for c in result.get("certificates") or []
              if c.get("expired") or (c.get("days_remaining") is not None
                                      and c["days_remaining"] < EXPIRY_WARN_DAYS))
    return f"TLS-Analyzer: {n} cert(s), {bad} risque(s) expiration/faiblesse"
