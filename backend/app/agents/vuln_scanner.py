"""
Vuln Scanner Agent — V1, tactical, scan-only.

Real banner-grab against open ports on a verified asset: connects, reads
whatever the service announces (SSH/HTTP/SMTP/FTP banners all do this by
default), and matches the announced version string against a small local
table of known-vulnerable version ranges. This is deterministic pattern
matching, not an LLM call -- the whole point of a tactical agent is that it
runs a real, auditable check, not a judgment call. Read-only: it never
modifies the target.

The local CVE table here is intentionally small and illustrative. Phase 2
of the real roadmap swaps `KNOWN_VULNERABLE` for a live NVD/CVE feed lookup
keyed off the same (service, version) tuples this module already extracts.
"""
import re
import socket

CONNECT_TIMEOUT = 2.0

# service -> [(version_prefix_regex, CVE id, severity, note)]
KNOWN_VULNERABLE = {
    "ssh": [
        (re.compile(r"OpenSSH_7\.[0-2]"), "CVE-2018-15473", "med", "Username enumeration via crafted auth packets."),
        (re.compile(r"OpenSSH_[1-6]\."), "CVE-2016-0777", "high", "Legacy OpenSSH version, multiple known CVEs, end of support."),
    ],
    "http": [
        (re.compile(r"Apache/2\.4\.([0-9]|[1-2][0-9])\b"), "CVE-2021-41773", "high", "Apache <=2.4.49 path traversal / RCE."),
        (re.compile(r"nginx/1\.1[0-8]\."), "CVE-2019-9511", "med", "Older nginx vulnerable to known HTTP/2 DoS class."),
    ],
    "ftp": [
        (re.compile(r"vsFTPd 2\.3\.4"), "CVE-2011-2523", "high", "Backdoored vsFTPd build, full compromise."),
    ],
}

PORT_SERVICE = {21: "ftp", 22: "ssh", 25: "smtp", 80: "http", 443: "http", 8080: "http", 8443: "http"}


def grab_banner(host: str, port: int) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(CONNECT_TIMEOUT)
            if port in (80, 8080, 443, 8443):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(512)
            return data.decode("utf-8", errors="ignore").strip()
    except (OSError, socket.timeout):
        return None


def match_vulnerabilities(service: str, banner: str) -> list[dict]:
    findings = []
    for pattern, cve, severity, note in KNOWN_VULNERABLE.get(service, []):
        if pattern.search(banner):
            findings.append({"cve": cve, "severity": severity, "note": note})
    return findings


def run(asset, open_ports: list[int]) -> dict | None:
    """Banner-grab + match across the ports Network Recon already found
    open. Returns a finding dict if anything matched, else None."""
    if asset.status != "verified":
        raise PermissionError(
            f"Refusing to scan unverified asset '{asset.target}' -- "
            f"scope enforcement blocked this call."
        )

    try:
        host = socket.gethostbyname(asset.target)
    except socket.gaierror as e:
        return {"summary": f"DNS resolution failed for {asset.target}: {e}", "findings": []}

    all_findings = []
    banners = {}
    for port in open_ports:
        service = PORT_SERVICE.get(port)
        if not service:
            continue
        banner = grab_banner(host, port)
        if not banner:
            continue
        banners[port] = banner
        for f in match_vulnerabilities(service, banner):
            f["port"] = port
            f["service"] = service
            all_findings.append(f)

    if not all_findings:
        return None

    top = max(all_findings, key=lambda f: {"high": 2, "med": 1, "low": 0}[f["severity"]])
    summary = (
        f"Vuln Scanner found {len(all_findings)} match(es) on {asset.target}. "
        f"Most severe: {top['cve']} on port {top['port']}/{top['service']} -- {top['note']}"
    )
    return {"summary": summary, "findings": all_findings, "severity_hint": top["severity"]}
