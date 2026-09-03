"""
HARMATTAN — Network utilities toolkit.
Ping, traceroute, banner, DNS, TLS, HTTP, ports, routes, neighbors, whois, subnet, dig…
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import struct
import subprocess
import time
from datetime import datetime
from typing import Any, Optional
from urllib.request import Request, urlopen

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
            sock.sendall(
                f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HARMATTAN/3.0\r\n\r\n".encode()
            )
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

    result: dict[str, Any] = {"query": name, "started": started, "a": [], "aaaa": [], "ptr": None}
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
        import ipaddress as ipa
        ipa.ip_address(name)
        result["ptr"] = socket.gethostbyaddr(name)[0]
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
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
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


def port_check(ip: str, port: int, timeout: float = 2.0) -> dict:
    """TCP connect probe for a single port."""
    started = datetime.now().isoformat()
    try:
        ip = validate_target(ip)
        port = validate_port(port)
    except ValidationError as e:
        return {"ip": ip, "port": port, "open": False, "error": e.message, "started": started}
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))
        sock.close()
        ms = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "ip": ip,
            "port": port,
            "open": err == 0,
            "latency_ms": ms,
            "started": started,
        }
    except Exception as e:
        return {"ip": ip, "port": port, "open": False, "error": str(e), "started": started}


def port_scan(ip: str, ports: str = "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080", timeout: float = 0.8) -> dict:
    """Lightweight sequential TCP probe of a port list (max 40)."""
    started = datetime.now().isoformat()
    try:
        ip = validate_target(ip)
    except ValidationError as e:
        return {"ip": ip, "error": e.message, "ports": [], "started": started}

    plist: list[int] = []
    for part in re.split(r"[\s,;]+", ports.strip()):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                lo, hi = int(a), int(b)
                for p in range(max(1, lo), min(65535, hi) + 1):
                    plist.append(p)
                    if len(plist) >= 40:
                        break
            except ValueError:
                continue
        else:
            try:
                plist.append(int(part))
            except ValueError:
                continue
        if len(plist) >= 40:
            break

    results = []
    for p in plist[:40]:
        r = port_check(ip, p, timeout=timeout)
        results.append({"port": p, "open": r.get("open"), "latency_ms": r.get("latency_ms"), "error": r.get("error")})
    open_ports = [x["port"] for x in results if x.get("open")]
    return {
        "ip": ip,
        "scanned": len(results),
        "open": open_ports,
        "ports": results,
        "started": started,
    }


def http_probe(url_or_host: str, port: int = 80, path: str = "/", timeout: float = 5.0, https: bool = False) -> dict:
    """HTTP(S) HEAD/GET probe — status, headers, title snippet."""
    started = datetime.now().isoformat()
    target = (url_or_host or "").strip()
    try:
        if target.startswith("http://") or target.startswith("https://"):
            url = target
        else:
            host = validate_target(target)
            scheme = "https" if https or port in (443, 8443) else "http"
            if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                url = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"
            else:
                url = f"{scheme}://{host}:{int(port)}{path if path.startswith('/') else '/' + path}"
    except ValidationError as e:
        return {"error": e.message, "started": started}
    except Exception as e:
        return {"error": str(e), "started": started}

    try:
        req = Request(url, method="GET", headers={"User-Agent": "HARMATTAN/3.13 Network-Utils"})
        t0 = time.perf_counter()
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192)
            headers = {k: v for k, v in resp.headers.items()}
            ms = round((time.perf_counter() - t0) * 1000, 1)
            text = body.decode("utf-8", errors="replace")
            title = None
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
            return {
                "url": url,
                "ok": True,
                "status": getattr(resp, "status", None) or resp.getcode(),
                "latency_ms": ms,
                "headers": headers,
                "title": title,
                "body_preview": text[:400],
                "started": started,
            }
    except Exception as e:
        return {"url": url, "ok": False, "error": str(e), "started": started}


def dig_records(name: str, types: str = "A,AAAA,MX,NS,TXT,CNAME,SOA") -> dict:
    """Full DNS via dig/host if available, else socket A/AAAA."""
    started = datetime.now().isoformat()
    try:
        name = validate_target(name)
    except ValidationError as e:
        return {"query": name, "error": e.message, "started": started}

    records: dict[str, list] = {}
    raw_parts = []
    tlist = [t.strip().upper() for t in types.split(",") if t.strip()][:10]

    dig_ok = subprocess.run(["which", "dig"], capture_output=True).returncode == 0
    if dig_ok:
        for t in tlist:
            try:
                r = subprocess.run(
                    ["dig", "+short", name, t],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
                records[t] = lines
                if lines:
                    raw_parts.append(f"; {t}\n" + "\n".join(lines))
            except Exception as e:
                records[t] = [f"error:{e}"]
    else:
        basic = dns_lookup(name)
        records["A"] = basic.get("a") or []
        records["AAAA"] = basic.get("aaaa") or []
        if basic.get("ptr"):
            records["PTR"] = [basic["ptr"]]
        raw_parts.append("(dig absent — fallback socket)")

    return {
        "query": name,
        "records": records,
        "raw": "\n".join(raw_parts) if raw_parts else "",
        "tool": "dig" if dig_ok else "socket",
        "started": started,
    }


def whois_lookup(query: str) -> dict:
    """WHOIS via system whois or RDAP HTTP fallback."""
    started = datetime.now().isoformat()
    try:
        query = validate_target(query)
    except ValidationError as e:
        return {"query": query, "error": e.message, "started": started}

    if subprocess.run(["which", "whois"], capture_output=True).returncode == 0:
        try:
            r = subprocess.run(
                ["whois", query],
                capture_output=True,
                text=True,
                timeout=15,
            )
            text = (r.stdout or r.stderr or "").strip()
            return {
                "query": query,
                "ok": bool(text),
                "source": "whois",
                "output": text[:8000],
                "started": started,
            }
        except Exception as e:
            pass

    # RDAP for IP
    try:
        if _is_ip(query):
            url = f"https://rdap.org/ip/{query}"
        else:
            url = f"https://rdap.org/domain/{query}"
        req = Request(url, headers={"Accept": "application/rdap+json", "User-Agent": "HARMATTAN/3.13"})
        with urlopen(req, timeout=10) as resp:
            import json
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return {
                "query": query,
                "ok": True,
                "source": "rdap",
                "data": data,
                "output": _rdap_summary(data),
                "started": started,
            }
    except Exception as e:
        return {
            "query": query,
            "ok": False,
            "error": str(e),
            "message": "whois/rdap unavailable — apt install whois",
            "started": started,
        }


def _rdap_summary(data: dict) -> str:
    lines = []
    if data.get("name"):
        lines.append(f"name: {data['name']}")
    if data.get("handle"):
        lines.append(f"handle: {data['handle']}")
    if data.get("type"):
        lines.append(f"type: {data['type']}")
    for e in (data.get("entities") or [])[:5]:
        vcard = e.get("vcardArray") or []
        lines.append(f"entity: {e.get('handle') or e.get('roles')}")
    if data.get("startAddress"):
        lines.append(f"range: {data.get('startAddress')} - {data.get('endAddress')}")
    if data.get("country"):
        lines.append(f"country: {data['country']}")
    return "\n".join(lines) if lines else str(data)[:1500]


def neighbors() -> dict:
    """ARP / neighbor table."""
    started = datetime.now().isoformat()
    entries = []
    raw = ""
    for cmd in (["ip", "neigh", "show"], ["arp", "-n"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                raw = r.stdout.strip()
                for line in raw.splitlines():
                    entries.append(line.strip())
                break
        except Exception:
            continue
    return {"ok": bool(entries), "count": len(entries), "entries": entries, "raw": raw, "started": started}


def routes() -> dict:
    """Routing table."""
    started = datetime.now().isoformat()
    raw = ""
    for cmd in (["ip", "route", "show"], ["route", "-n"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                raw = r.stdout.strip()
                break
        except Exception:
            continue
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    return {"ok": bool(lines), "routes": lines, "raw": raw, "started": started}


def listening_ports() -> dict:
    """Local listening TCP/UDP sockets (ss)."""
    started = datetime.now().isoformat()
    raw = ""
    try:
        r = subprocess.run(
            ["ss", "-lntup"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raw = (r.stdout or "").strip()
    except Exception as e:
        return {"ok": False, "error": str(e), "started": started}
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    return {"ok": True, "count": max(0, len(lines) - 1), "lines": lines[:200], "raw": raw[:8000], "started": started}


def subnet_info(cidr: str) -> dict:
    """Calculate network / broadcast / hosts for a CIDR or IP+mask."""
    started = datetime.now().isoformat()
    raw = (cidr or "").strip()
    try:
        if "/" not in raw:
            # assume /24 for bare IPv4
            if _is_ip(raw) and ":" not in raw:
                raw = raw + "/24"
            else:
                return {"error": "cidr_required", "message": "Ex: 192.168.1.0/24", "started": started}
        net = ipaddress.ip_network(raw, strict=False)
        hosts = list(net.hosts())
        return {
            "ok": True,
            "network": str(net.network_address),
            "broadcast": str(getattr(net, "broadcast_address", "")),
            "netmask": str(net.netmask),
            "prefix": net.prefixlen,
            "num_addresses": net.num_addresses,
            "num_hosts": len(hosts),
            "first_host": str(hosts[0]) if hosts else None,
            "last_host": str(hosts[-1]) if hosts else None,
            "is_private": net.is_private,
            "version": net.version,
            "started": started,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "started": started}


def mac_lookup(mac: str) -> dict:
    """OUI vendor lookup from local oui.csv if present."""
    started = datetime.now().isoformat()
    mac = (mac or "").strip().upper().replace("-", ":")
    mac = re.sub(r"[^0-9A-F:]", "", mac)
    if len(mac) < 8:
        return {"mac": mac, "error": "invalid_mac", "started": started}
    prefix = mac.replace(":", "")[:6]
    vendor = None
    # try modules/oui.csv
    from pathlib import Path
    oui_path = Path(__file__).resolve().parent / "oui.csv"
    try:
        if oui_path.is_file():
            # format varies — try common: prefix,vendor
            with oui_path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if prefix.lower() in line.lower() or prefix in line:
                        # crude parse
                        parts = re.split(r"[,;\t]", line.strip(), maxsplit=1)
                        if len(parts) >= 2:
                            vendor = parts[-1].strip().strip('"')
                            break
                        if "\t" in line:
                            vendor = line.split("\t")[-1].strip()
                            break
    except Exception as e:
        return {"mac": mac, "prefix": prefix, "error": str(e), "started": started}

    # fallback: try fingerprinting module
    if not vendor:
        try:
            from modules.fingerprinting import lookup_oui  # type: ignore
            vendor = lookup_oui(mac)
        except Exception:
            pass

    return {
        "mac": mac,
        "prefix": prefix,
        "vendor": vendor or "unknown",
        "ok": vendor is not None and vendor != "unknown",
        "started": started,
    }


def ssh_keyscan(ip: str, port: int = 22, timeout: int = 5) -> dict:
    """Fetch SSH host keys via ssh-keyscan."""
    started = datetime.now().isoformat()
    try:
        ip = validate_target(ip)
        port = validate_port(port)
    except ValidationError as e:
        return {"ip": ip, "error": e.message, "started": started}

    if subprocess.run(["which", "ssh-keyscan"], capture_output=True).returncode != 0:
        return {
            "ip": ip,
            "port": port,
            "error": "ssh-keyscan_missing",
            "message": "openssh-client requis",
            "started": started,
        }
    try:
        r = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), "-p", str(port), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        keys = [ln for ln in (r.stdout or "").splitlines() if ln.strip() and not ln.startswith("#")]
        return {
            "ip": ip,
            "port": port,
            "ok": bool(keys),
            "keys": keys,
            "raw": (r.stdout or r.stderr or "").strip()[:4000],
            "started": started,
        }
    except Exception as e:
        return {"ip": ip, "port": port, "error": str(e), "started": started}


def mtu_check(ip: str, size: int = 1400) -> dict:
    """Path MTU probe via ping -M do (Linux)."""
    started = datetime.now().isoformat()
    try:
        ip = validate_target(ip)
        size = max(64, min(int(size), 9000))
    except ValidationError as e:
        return {"ip": ip, "error": e.message, "started": started}
    except Exception as e:
        return {"ip": ip, "error": str(e), "started": started}

    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-M", "do", "-s", str(size), "-W", "2", ip],
            capture_output=True,
            text=True,
            timeout=8,
        )
        out = (r.stdout or "") + (r.stderr or "")
        ok = r.returncode == 0
        return {
            "ip": ip,
            "payload": size,
            "ok": ok,
            "output": out.strip()[:1500],
            "hint": "Si fail, réduire size (fragmentation / MTU path)",
            "started": started,
        }
    except Exception as e:
        return {"ip": ip, "error": str(e), "started": started}


def reverse_dns_batch(ips: list[str] | None = None) -> dict:
    """PTR lookup for a list of IPs (max 30)."""
    started = datetime.now().isoformat()
    ips = ips or []
    results = []
    for ip in ips[:30]:
        try:
            ip = validate_target(str(ip).strip())
            name = socket.gethostbyaddr(ip)[0]
            results.append({"ip": ip, "ptr": name, "ok": True})
        except Exception as e:
            results.append({"ip": str(ip), "ptr": None, "ok": False, "error": str(e)[:80]})
    return {"count": len(results), "results": results, "started": started}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False
