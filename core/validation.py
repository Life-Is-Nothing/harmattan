"""
HARMATTAN — Strict input validation (anti command-injection / scan abuse).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

from core.config import NMAP_ALLOWED_FLAGS

# Hostname: labels with alnum/hyphen, optional trailing dot, max 253 chars
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_IFACE_RE = re.compile(r"^[A-Za-z0-9_./-]{1,32}$")
_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class ValidationError(ValueError):
    def __init__(self, message: str, code: str = "invalid_input"):
        super().__init__(message)
        self.message = message
        self.code = code


def validate_ip(value: str, allow_private: bool = True) -> str:
    value = (value or "").strip()
    if not value:
        raise ValidationError("Adresse IP manquante.", "missing_ip")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as e:
        raise ValidationError(f"IP invalide: {value}", "invalid_ip") from e
    if addr.is_multicast or addr.is_unspecified:
        raise ValidationError(f"IP non autorisée: {value}", "forbidden_ip")
    if not allow_private and (addr.is_private or addr.is_loopback or addr.is_link_local):
        raise ValidationError(f"IP privée non autorisée: {value}", "forbidden_ip")
    return str(addr)


def validate_cidr(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValidationError("Subnet manquant.", "missing_subnet")
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as e:
        raise ValidationError(f"CIDR invalide: {value}", "invalid_cidr") from e
    # Cap scan size to /16 equivalent hosts to avoid accidental huge scans
    if net.num_addresses > 65536:
        raise ValidationError(
            "Subnet trop large (max /16). Affinez la plage.",
            "subnet_too_large",
        )
    return str(net)


def validate_hostname(value: str) -> str:
    value = (value or "").strip().rstrip(".")
    if not value or not _HOSTNAME_RE.match(value):
        raise ValidationError(f"Hostname invalide: {value}", "invalid_hostname")
    return value


def validate_target(value: str) -> str:
    """IP, hostname, or CIDR for nmap targets."""
    value = (value or "").strip()
    if not value:
        raise ValidationError("Cible manquante.", "missing_target")
    if "/" in value:
        return validate_cidr(value)
    # IPv6 may contain colons
    try:
        return validate_ip(value)
    except ValidationError:
        pass
    return validate_hostname(value)


def validate_port(value) -> int:
    try:
        p = int(value)
    except (TypeError, ValueError) as e:
        raise ValidationError("Port invalide.", "invalid_port") from e
    if p < 1 or p > 65535:
        raise ValidationError("Port hors plage (1-65535).", "invalid_port")
    return p


def validate_iface(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    value = str(value).strip()
    if not _IFACE_RE.match(value):
        raise ValidationError(f"Interface invalide: {value}", "invalid_iface")
    return value


def validate_count(value, default: int = 3, min_v: int = 1, max_v: int = 20) -> int:
    try:
        n = int(value if value is not None else default)
    except (TypeError, ValueError):
        n = default
    return max(min_v, min(max_v, n))


def sanitize_nmap_custom_args(custom_args: str) -> list[str]:
    """
    Parse custom nmap args and only keep whitelisted flags / safe values.
    Rejects shell metacharacters entirely.
    """
    if not custom_args:
        return []
    raw = custom_args.strip()
    if re.search(r"[;|&`$(){}<>\\\n\r]", raw):
        raise ValidationError(
            "Caractères interdits dans les arguments nmap.",
            "nmap_args_forbidden",
        )
    tokens = raw.split()
    safe: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        # Combined short form like -p22
        if tok.startswith("-p") and len(tok) > 2:
            ports = tok[2:]
            if not _PORT_RE.match(ports):
                raise ValidationError(f"Ports nmap invalides: {ports}", "invalid_ports")
            safe.append(tok)
            i += 1
            continue
        if tok in NMAP_ALLOWED_FLAGS:
            safe.append(tok)
            # flags that take a value
            if tok in ("-p", "--top-ports", "--script", "--version-intensity",
                       "--max-retries", "--host-timeout", "--min-rate", "--max-rate"):
                if i + 1 >= len(tokens):
                    raise ValidationError(f"Valeur manquante pour {tok}", "nmap_args_value")
                val = tokens[i + 1]
                if tok == "-p" and not _PORT_RE.match(val) and val != "-":
                    raise ValidationError(f"Ports invalides: {val}", "invalid_ports")
                if tok == "--script":
                    if not re.match(r"^[A-Za-z0-9_,.*+-]+$", val):
                        raise ValidationError("Script NSE non autorisé.", "invalid_script")
                if re.search(r"[;|&`$(){}<>\\]", val):
                    raise ValidationError("Valeur nmap interdite.", "nmap_args_forbidden")
                safe.append(val)
                i += 2
                continue
            i += 1
            continue
        raise ValidationError(f"Option nmap non autorisée: {tok}", "nmap_flag_denied")
    return safe


def validate_bpf_filter(value: str) -> str:
    """Basic BPF filter sanitization (no shell metacharacters)."""
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > 200:
        raise ValidationError("Filtre BPF trop long.", "bpf_too_long")
    if re.search(r"[;|&`$(){}<>\\\n\r]", value):
        raise ValidationError("Filtre BPF invalide.", "invalid_bpf")
    return value
