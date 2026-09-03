"""
HARMATTAN — Remediation: generate hardening scripts based on findings.
"""
from __future__ import annotations

def generate_bash_script(ip: str, exposures: list[dict]) -> str:
    script = [
        "#!/bin/bash",
        f"# HARMATTAN Hardening Script for {ip}",
        "# Usage: sudo bash hardening.sh",
        "set -e",
        "",
        "echo '[*] Starting hardening for " + ip + "...'",
    ]

    services_to_stop = []
    ports_to_block = []

    for exp in exposures:
        p = exp.get("port")
        if p == 23:
            services_to_stop.append("telnet")
        elif p == 21:
            services_to_stop.append("vsftpd")
        elif p == 445:
            services_to_stop.append("smbd")
        elif p == 161:
            services_to_stop.append("snmpd")

        if exp.get("risk") in ("critique", "haute"):
            ports_to_block.append(p)

    if services_to_stop:
        script.append("\necho '[!] Stopping insecure services...'")
        for svc in set(services_to_stop):
            script.append(f"systemctl stop {svc} || true")
            script.append(f"systemctl disable {svc} || true")

    if ports_to_block:
        script.append("\necho '[!] Configuring UFW to block sensitive ports...'")
        script.append("command -v ufw >/dev/null 2>&1 || { echo 'ufw not installed, skipping.'; }")
        for p in set(ports_to_block):
            script.append(f"ufw deny {p}/tcp || true")

    script.append("\necho '[+] Hardening complete.'")
    return "\n".join(script)
