"""
Network Recon Agent — V1, tactical, scan-only.

Runs a real TCP-connect port sweep against an asset's resolved IP, strictly
limited to assets with status == 'verified' in the registry. Compares the
result to the asset's last known baseline (stored as a JSON string on the
Asset row) and reports anything new or changed. Never writes anything itself
-- it produces a finding, which gets pushed into the same Alert pipeline
Triage already classifies, so a human still confirms before anything else
happens downstream.

This is a real scanner, not a simulation: it opens real sockets against the
real resolved host. Scope is the safety boundary, not "pretend ports."
"""
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# A representative common-port list. Real deployment would let customers
# tune this per asset; kept fixed and small here to keep scans fast and
# polite by default.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

CONNECT_TIMEOUT = 1.5


def _check_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except (OSError, socket.timeout):
        return False


def scan_ports(host: str, ports: list[int] = None) -> list[int]:
    """Real concurrent TCP-connect scan. Returns the list of ports that
    accepted a connection."""
    ports = ports or COMMON_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_check_port, host, p): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


def run(asset) -> dict | None:
    """Scan one verified asset and return a finding dict if anything is new
    relative to its stored baseline, else None. Does NOT touch the DB --
    caller is responsible for persisting baseline updates and raising an
    alert."""
    if asset.status != "verified":
        raise PermissionError(
            f"Refusing to scan unverified asset '{asset.target}' -- "
            f"scope enforcement blocked this call."
        )

    try:
        resolved_ip = socket.gethostbyname(asset.target)
    except socket.gaierror as e:
        return {
            "summary": f"DNS resolution failed for {asset.target}: {e}",
            "open_ports": [],
            "new_ports": [],
            "resolved_ip": None,
        }

    open_ports = scan_ports(resolved_ip)
    baseline = json.loads(asset.scan_baseline) if asset.scan_baseline else []
    new_ports = sorted(set(open_ports) - set(baseline))

    if not new_ports and baseline:
        return None  # nothing changed since last scan -- no finding needed

    summary = (
        f"Network Recon swept {asset.target} ({resolved_ip}): "
        f"{len(open_ports)} open port(s) found"
        + (f", {len(new_ports)} new since baseline: {new_ports}" if baseline else f": {open_ports}")
        + "."
    )
    return {
        "summary": summary,
        "open_ports": open_ports,
        "new_ports": new_ports if baseline else open_ports,
        "resolved_ip": resolved_ip,
    }
