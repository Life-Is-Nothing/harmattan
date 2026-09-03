"""
HARMATTAN — DNS-Enumerator: subdomain brute-force + zone-transfer attempt.

Small, dependency-light DNS enumerator for authorized targets. Uses Python's socket /
dns.resolver (if available) to resolve names from a wordlist against a target domain,
and attempts a zone transfer against the authoritative nameservers.

Authorized targets only (labs, domains you own, bug-bounty scope).
"""
from __future__ import annotations

import socket
import threading
from typing import Optional

from core.logging_setup import get_logger

log = get_logger("harmattan.dns_enum")

# Tiny built-in wordlist (common subdomains). Expanded by caller-provided list.
DEFAULT_WORDS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ftp", "ssh",
    "vpn", "remote", "intranet", "extranet", "admin", "portal", "gateway", "api",
    "dev", "staging", "test", "blog", "shop", "store", "app", "m", "static",
    "cdn", "backup", "mx", "dns", "cloud", "web", "owa", "exchange",
    "autodiscover", "owa", "radius", "cpanel", "whm", "panel", "status", "login",
]

_CACHE: dict[str, bool] = {}


def resolve(name: str, timeout: float = 2.0) -> Optional[list[str]]:
    """Resolve a hostname to IP(s). Returns None on NXDOMAIN/failure."""
    if name in _CACHE:
        return [name] if _CACHE[name] else None
    try:
        addrs = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        ips = sorted({a[4][0] for a in addrs})
        _CACHE[name] = bool(ips)
        return ips or None
    except socket.gaierror:
        _CACHE[name] = False
        return None


def zone_transfer(domain: str, ns_list: list[str] | None = None,
                  timeout: float = 4.0) -> list[dict]:
    """Attempt AXFR against authoritative nameservers."""
    found = []
    try:
        import dns.resolver  # dnspython
        import dns.query
        import dns.zone
    except ImportError:
        # dnspython not installed — fall back to a plain socket AXFR (best-effort)
        log.debug("dnspython absent, zone-transfer skipped (install dnspython)")
        return []

    if not ns_list:
        try:
            ns_list = [str(n) for n in dns.resolver.resolve(domain, "NS")]
        except Exception:  # noqa: BLE001
            ns_list = []

    for ns in ns_list:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=timeout))
            for name in z.keys():
                fqdn = str(name.derelativize(z.origin)).rstrip(".")
                found.append({"name": fqdn, "ns": ns, "type": "AXFR"})
        except Exception as e:  # noqa: BLE001
            log.debug("AXFR %s via %s refusé: %s", domain, ns, e)
    return found


def enumerate_subdomains(domain: str, words: list[str] | None = None,
                         max_threads: int = 40, timeout: float = 2.0) -> dict:
    """
    Brute-force subdomains of `domain`. Returns:
        {
            "domain": str,
            "resolved": [ {name, ips}, ... ],
            "found": int,
            "zone_transfer": [ {name, ns}, ... ],   # AXFR results (rare)
            "generated_at": None,
        }
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return {"domain": "", "found": 0, "resolved": [], "zone_transfer": []}

    words = [w for w in (words or DEFAULT_WORDS) if w and w != "*"]
    names = [f"{w}.{domain}" for w in words]
    # dedupe
    seen = set(); uniq = []
    for n in names:
        if n not in seen:
            seen.add(n); uniq.append(n)
    names = uniq

    results: list[dict] = []
    results_lock = threading.Lock()
    index = 0
    index_lock = threading.Lock()

    def worker():
        nonlocal index
        while True:
            with index_lock:
                if index >= len(names):
                    return
                name = names[index]
                index += 1
            ips = resolve(name, timeout)
            if ips:
                with results_lock:
                    results.append({"name": name, "ips": ips})

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(max_threads, len(names) or 1))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 5)

    results.sort(key=lambda r: r["name"])
    axfr = zone_transfer(domain)

    return {
        "domain": domain,
        "resolved": results,
        "found": len(results),
        "zone_transfer": axfr,
        "generated_at": None,
    }


def summarize(result: dict) -> str:
    d = result.get("domain") or "?"
    found = result.get("found", 0)
    axfr = len(result.get("zone_transfer") or [])
    extra = f", AXFR {axfr}" if axfr else ""
    return f"DNS-Enum: {found} sous-domaine(s) pour {d}{extra}"
