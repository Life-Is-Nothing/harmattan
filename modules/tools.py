"""
HARMATTAN — Network tools: ping, traceroute, banner, DNS, TLS cert.
"""
from __future__ import annotations

import re
import socket
import ssl
import subprocess
from datetime import datetime
from typing import Optional

from core.validation import ValidationError, validate_count, validate_port, validate_target


def ping_host(ip: str, count: int = 3, timeout: int = 2) -> dict:
    started = datetime.now().isoformat()
    try:
        ip = validate_target(ip)
        count = validate_count(count, 3, 1, 10)
        timeout = validate_count(timeout, 2, 1, 10)
    except ValidationError as e:
        return {"ip": ip, "ok": False, "error": e.message, "started": started}

    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), ip],
            capture_output=True,
            text=True,
            timeout=count * timeout + 5,
        )
        out = result.stdout + result.stderr
        rtt = None
        m = re.search(r"rtt min/avg/max/[^=]+=\s*([\d.]+)/([\d.]+)/([\d.]+)", out)
        if m:
            rtt = {"min": float(m.group(1)), "avg": float(m.group(2)), "max": float(m.group(3))}
        loss = None
        lm = re.search(r"(\d+)% packet loss", out)
        if lm:
            loss = int(lm.group(1))
        return {
            "ip": ip,
            "ok": result.returncode == 0,
            "loss_pct": loss,
            "rtt_ms": rtt,
            "output": out.strip(),
            "started": started,
        }
    except Exception as e:
        return {"ip": ip, "ok": False, "error": str(e), "started": started}


def traceroute(ip: str, max_hops: int = 20) -> dict:
    started = datetime.now().isoformat()
    try:
        ip = validate_target(ip)
        max_hops = validate_count(max_hops, 20, 1, 64)
    except ValidationError as e:
        return {"ip": ip, "error": e.message, "hops": [], "started": started}

    cmd = None
    for candidate in (
        ["traceroute", "-n", "-m", str(max_hops), "-w", "2", ip],
        ["tracepath", "-n", "-m", str(max_hops), ip],
    ):
        try:
            which = subprocess.run(["which", candidate[0]], capture_output=True)
            if which.returncode == 0:
                cmd = candidate
                break
        except Exception:
            pass

    if not cmd:
        return {
            "ip": ip,
            "error": "traceroute_missing",
            "message": "Installez traceroute : sudo apt install traceroute",
            "hops": [],
            "started": started,
        }

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        hops = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {
            "ip": ip,
            "hops": hops,
            "raw": result.stdout.strip(),
            "started": started,
        }
    except subprocess.TimeoutExpired:
        return {"ip": ip, "error": "timeout", "hops": [], "started": started}
    except Exception as e:
        return {"ip": ip, "error": str(e), "hops": [], "started": started}


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> dict:
    started = datetime.now().isoformat()
    try:
        ip = validate_target(ip)
        port = validate_port(port)
    except ValidationError as e:
        return {"ip": ip, "port": port, "error": e.message, "banner": "", "started": started}

    # TLS ports
    if port in (443, 8443, 993, 995, 465, 636):
        tls = tls_inspect(ip, port, timeout=timeout)
        if tls.get("error") and not tls.get("banner"):
            return {**tls, "started": started}
        return {
            "ip": ip,
            "port": port,
            "banner": tls.get("banner") or "",
            "tls": tls,
            "started": started,
        }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in (80, 8080, 8000, 8888, 8008):
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HARMATTAN/3.0\r\n\r\n".encode())
        else:
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
        data = sock.recv(2048)
        sock.close()
        banner = data.decode("utf-8", errors="replace").strip()
        return {"ip": ip, "port": port, "banner": banner[:800], "started": started}
    except Exception as e:
        return {"ip": ip, "port": port, "error": str(e), "banner": "", "started": started}


def dns_lookup(name: str) -> dict:
    started = datetime.now().isoformat()
    try:
        name = validate_target(name)
    except ValidationError as e:
        return {"query": name, "error": e.message, "started": started}

    result = {"query": name, "started": started, "a": [], "aaaa": [], "ptr": None}
    try:
        infos = socket.getaddrinfo(name, None)
        for info in infos:
            addr = info[4][0]
            if ":" in addr:
                if addr not in result["aaaa"]:
                    result["aaaa"].append(addr)
            else:
                if addr not in result["a"]:
                    result["a"].append(addr)
    except Exception as e:
        result["error"] = str(e)

    try:
        # reverse if it looks like an IP
        try:
            import ipaddress
            ipaddress.ip_address(name)
            result["ptr"] = socket.gethostbyaddr(name)[0]
        except Exception:
            pass
    except Exception:
        pass
    return result


def tls_inspect(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    started = datetime.now().isoformat()
    try:
        host = validate_target(host)
        port = validate_port(port)
    except ValidationError as e:
        return {"host": host, "port": port, "error": e.message, "started": started}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if not _is_ip(host) else None) as ssock:
                cert = ssock.getpeercert()
                # binary form for subject when getpeercert empty due to CERT_NONE
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                # Parse with openssl-less approach: try decoded cert
                subject = issuer = not_before = not_after = None
                san = []
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")
                    for typ, val in cert.get("subjectAltName", ()) or []:
                        san.append(f"{typ}:{val}")

                banner = f"TLS {version} | cipher={cipher[0] if cipher else '?'}"
                if subject:
                    banner += f" | CN={subject.get('commonName', '?')}"
                if not_after:
                    banner += f" | expires={not_after}"

                return {
                    "host": host,
                    "port": port,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else None,
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "san": san,
                    "has_cert": bool(der),
                    "banner": banner,
                    "started": started,
                }
    except Exception as e:
        return {"host": host, "port": port, "error": str(e), "banner": "", "started": started}


def _is_ip(value: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False
