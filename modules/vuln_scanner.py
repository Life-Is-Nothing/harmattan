"""
HARMATTAN — CVE correlation via NVD API with local cache.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

import requests

from core.config import NVD_API_KEY, NVD_RATE_DELAY
from core.db import cve_cache_get, cve_cache_set
from core.logging_setup import get_logger

log = get_logger("harmattan.vuln")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity_bucket(score: Optional[float]) -> str:
    if score is None:
        return "inconnue"
    if score >= 9.0:
        return "critique"
    if score >= 7.0:
        return "haute"
    if score >= 4.0:
        return "moyenne"
    return "faible"


def lookup_cves(product: str, version: str = "", max_results: int = 10) -> dict:
    if not product:
        return {"query": "", "cves": []}

    keyword = f"{product} {version}".strip()
    cache_key = f"cve:{keyword.lower()}:{max_results}"
    cached = cve_cache_get(cache_key)
    if cached is not None:
        cached["cached"] = True
        return cached

    headers = {"User-Agent": "HARMATTAN-NetworkSuite/3.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=20,
            headers=headers,
        )
        if resp.status_code == 429:
            log.warning("NVD rate limit, sleeping…")
            time.sleep(6)
            resp = requests.get(
                NVD_API,
                params={"keywordSearch": keyword, "resultsPerPage": max_results},
                timeout=20,
                headers=headers,
            )

        if resp.status_code != 200:
            return {"query": keyword, "error": f"nvd_http_{resp.status_code}", "cves": []}

        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "?")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            if not desc:
                desc = next((d["value"] for d in descriptions if d.get("lang") == "fr"), "")

            score = None
            vector = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {})
                    score = cvss.get("baseScore")
                    vector = cvss.get("vectorString")
                    break

            cves.append({
                "id": cve_id,
                "score": score,
                "vector": vector,
                "severity": _severity_bucket(score),
                "description": (desc or "")[:400],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        cves.sort(key=lambda c: (c["score"] or 0), reverse=True)
        result = {"query": keyword, "count": len(cves), "cves": cves, "cached": False}
        cve_cache_set(cache_key, result)
        return result

    except requests.exceptions.RequestException as e:
        log.error("NVD network error: %s", e)
        return {"query": keyword, "error": "network_error", "message": str(e), "cves": []}


def correlate_scan_results(
    nmap_hosts: list,
    max_per_service: int = 5,
    progress: Optional[Callable[[int, str], None]] = None,
) -> dict:
    report = {
        "hosts": [],
        "total_findings": 0,
        "by_severity": {"critique": 0, "haute": 0, "moyenne": 0, "faible": 0, "inconnue": 0},
    }

    # Collect work items
    work = []
    for host in nmap_hosts:
        for port in host.get("ports", []):
            product = (port.get("product") or "").strip()
            if not product:
                continue
            work.append((host, port, product, (port.get("version") or "").strip()))

    total = max(len(work), 1)
    for i, (host, port, product, version) in enumerate(work):
        if progress:
            progress(int(10 + 85 * i / total), f"CVE {product} {version}".strip())

        result = lookup_cves(product, version, max_results=max_per_service)
        if result.get("cves"):
            # find or create host entry
            host_findings = next((h for h in report["hosts"] if h["ip"] == host["ip"]), None)
            if host_findings is None:
                host_findings = {"ip": host["ip"], "services": []}
                report["hosts"].append(host_findings)
            host_findings["services"].append({
                "port": port["port"],
                "service": port.get("service"),
                "product": product,
                "version": version,
                "cves": result["cves"],
            })
            report["total_findings"] += len(result["cves"])
            for c in result["cves"]:
                sev = c.get("severity", "inconnue")
                report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1

        if not result.get("cached"):
            time.sleep(NVD_RATE_DELAY)

    if progress:
        progress(100, f"{report['total_findings']} CVE")
    return report
