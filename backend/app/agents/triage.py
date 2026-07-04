"""
Triage Agent — V1, classify-only.

Pipeline for every alert:
  1. Deterministic rules pass — catches obvious known-benign noise cheaply,
     no LLM call needed.
  2. LangChain LLM pass — uses whichever provider is configured:
       groq        → Llama 3.1 8B via Groq (free tier, fastest)
       openai      → GPT-4o-mini (paid, backward-compatible)
       huggingface → Mistral-7B via HuggingFace Inference API (free tier)
       mock        → deterministic keyword fallback (no key needed)
     Provider priority when LLM_PROVIDER=auto: groq → openai → huggingface → mock

Nothing here ever closes, blocks, or patches anything. It only ever
writes a recommendation; a human confirms via the /alerts/{id}/confirm or
/dismiss endpoints.
"""
import json
import re
from datetime import datetime

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

from app.config import (
    resolve_llm_provider,
    GROQ_API_KEY, GROQ_MODEL,
    OPENAI_API_KEY, OPENAI_MODEL,
    HUGGINGFACE_API_KEY, HUGGINGFACE_MODEL,
)
from app.schemas import TriageClassification
from app.agents.threat_intel import retriever as _threat_retriever

# ---------------------------------------------------------------------------
# 1. Deterministic rules layer (always runs first, no LLM cost)
# ---------------------------------------------------------------------------
BENIGN_PATTERNS = [
    re.compile(r"scheduled maintenance", re.I),
    re.compile(r"password reset.*self-service", re.I),
    re.compile(r"successful login.*known device", re.I),
]

# (pattern, ATT&CK technique_id, technique_name, tactic)
CRITICAL_PATTERNS = [
    (re.compile(r"ransomware", re.I),   "T1486", "Data Encrypted for Impact", "Impact"),
    (re.compile(r"critical cve", re.I), "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (re.compile(r"public poc", re.I),   "T1190", "Exploit Public-Facing Application", "Initial Access"),
]


def run_rules(description: str) -> TriageClassification | None:
    for pat in BENIGN_PATTERNS:
        if pat.search(description):
            return TriageClassification(
                severity="low",
                confidence=0.95,
                rationale=f"Matched known-benign rule pattern: '{pat.pattern}'.",
                suggested_action="dismiss",
            )
    for pat, tid, tname, tactic in CRITICAL_PATTERNS:
        if pat.search(description):
            return TriageClassification(
                severity="high",
                confidence=0.9,
                rationale=f"Matched critical-pattern rule: '{pat.pattern}'.",
                suggested_action="escalate",
                mitre_technique_id=tid,
                mitre_technique_name=tname,
                mitre_tactic=tactic,
            )
    return None


# ---------------------------------------------------------------------------
# 2. LangChain LLM layer
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are the Triage Agent inside a security operations platform. "
    "You read a single security alert, classify it, and map it to the "
    "most relevant MITRE ATT&CK technique where applicable. "
    "You NEVER take action yourself -- you only recommend. "
    "Be conservative: when genuinely unsure, prefer 'escalate' with a lower "
    "confidence score over silently dismissing something that could be real. "
    "Keep the rationale to 1-2 plain-English sentences a non-expert could understand. "
    "For MITRE mapping: set mitre_technique_id to the technique ID (e.g. T1110), "
    "mitre_technique_name to the technique name (e.g. Brute Force), and "
    "mitre_tactic to the parent tactic (e.g. Credential Access). "
    "Set all three to null if the alert does not map to a known ATT&CK technique."
)

# ---------------------------------------------------------------------------
# Mock ATT&CK keyword map (used when no LLM key is configured)
# ---------------------------------------------------------------------------
_MOCK_MITRE: list[tuple[list[str], str, str, str]] = [
    (["ssh", "brute", "fail", "repeated login"],      "T1110", "Brute Force",                          "Credential Access"),
    (["phish", "spear", "email link", "malicious url"],"T1566", "Phishing",                            "Initial Access"),
    (["ransomware", "encrypted", "ransom"],            "T1486", "Data Encrypted for Impact",            "Impact"),
    (["s3", "bucket", "public acl", "public read"],   "T1530", "Data from Cloud Storage",              "Collection"),
    (["exfil", "data transfer", "dns tunnel"],         "T1041", "Exfiltration Over C2 Channel",         "Exfiltration"),
    (["rdp", "remote desktop"],                        "T1021.001", "Remote Desktop Protocol",          "Lateral Movement"),
    (["privilege", "escalat", "sudo", "root"],         "T1068", "Exploitation for Privilege Escalation","Privilege Escalation"),
    (["scan", "port sweep", "nmap", "discovery"],      "T1046", "Network Service Discovery",            "Discovery"),
    (["inject", "log4", "jndi", "rce", "sqli"],        "T1190", "Exploit Public-Facing Application",   "Initial Access"),
    (["credential", "mimikatz", "lsass", "hash dump"], "T1003", "OS Credential Dumping",               "Credential Access"),
    (["dos", "ddos", "flood", "amplification"],        "T1498", "Network Denial of Service",            "Impact"),
    (["lateral", "smb", "pass the hash", "wmi"],       "T1021", "Remote Services",                     "Lateral Movement"),
    (["security group", "firewall", "open port 22", "open port 3389"], "T1562.007", "Disable or Modify Cloud Firewall", "Defense Evasion"),
]

_parser = PydanticOutputParser(pydantic_object=TriageClassification)

_PROMPT_TEMPLATE = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT + "\n\n{format_instructions}"),
    ("human", (
        "Source tool: {source}\n"
        "Alert description: {description}\n\n"
        "{threat_context}"
    )),
])

_chain_cache: dict = {}


def _build_chain(provider: str):
    """Build and cache a LangChain LCEL chain for the given provider."""
    if provider in _chain_cache:
        return _chain_cache[provider]

    if provider == "groq":
        if not GROQ_API_KEY:
            return None
        from langchain_groq import ChatGroq
        llm = ChatGroq(model=GROQ_MODEL, api_key=GROQ_API_KEY, temperature=0)
        chain = _PROMPT_TEMPLATE | llm.with_structured_output(TriageClassification)

    elif provider == "openai":
        if not OPENAI_API_KEY:
            return None
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model=OPENAI_MODEL, api_key=OPENAI_API_KEY, temperature=0)
        chain = _PROMPT_TEMPLATE | llm.with_structured_output(TriageClassification)

    elif provider == "huggingface":
        if not HUGGINGFACE_API_KEY:
            return None
        # HuggingFace Inference API doesn't reliably support tool-calling /
        # structured output, so we use prompt-based JSON extraction instead.
        from langchain_huggingface import HuggingFaceEndpoint
        llm = HuggingFaceEndpoint(
            repo_id=HUGGINGFACE_MODEL,
            huggingfacehub_api_token=HUGGINGFACE_API_KEY,
            temperature=0.1,
            max_new_tokens=256,
        )
        chain = _PROMPT_TEMPLATE | llm | _parse_hf_output

    else:
        return None

    _chain_cache[provider] = chain
    return chain


def _parse_hf_output(text: str) -> TriageClassification:
    """Extract JSON from HuggingFace text output and parse into TriageClassification."""
    # Models often wrap JSON in markdown code fences -- strip them
    text = re.sub(r"```(?:json)?", "", text).strip().rstrip("`").strip()
    # Find first {...} block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            return TriageClassification(**data)
        except Exception:
            pass
    # Fallback if JSON parsing fails
    return TriageClassification(
        severity="med",
        confidence=0.5,
        rationale="[HuggingFace output could not be parsed as structured JSON. Treating as medium severity.]",
        suggested_action="escalate",
    )


def run_llm(description: str, source: str, provider: str) -> TriageClassification:
    chain = _build_chain(provider)
    if chain is None:
        return run_mock_llm(description, source)
    # RAG: retrieve relevant threat intel and inject as context
    threat_context = _threat_retriever.retrieve_as_context(description, top_k=3)
    result = chain.invoke({
        "description": description,
        "source": source,
        "format_instructions": _parser.get_format_instructions(),
        "threat_context": threat_context,
    })
    if isinstance(result, TriageClassification):
        return result
    # with_structured_output should already return the right type, but be safe
    return TriageClassification(**result) if isinstance(result, dict) else run_mock_llm(description, source)


def _mock_mitre_lookup(description: str):
    """Keyword-based ATT&CK technique lookup for mock mode."""
    lower = description.lower()
    for keywords, tid, tname, tactic in _MOCK_MITRE:
        if any(kw in lower for kw in keywords):
            return tid, tname, tactic
    return None, None, None


def run_mock_llm(description: str, source: str) -> TriageClassification:
    """Deterministic stand-in used when no LLM key is configured. Mirrors
    the LLM output shape exactly so the pipeline is fully runnable in
    local/dev without any API key."""
    severity = "med"
    confidence = 0.6
    action = "escalate"
    lower = description.lower()
    if any(w in lower for w in ["fail", "denied", "unauthorized", "suspicious", "anomal"]):
        severity, confidence = "med", 0.65
    if any(w in lower for w in ["multiple", "repeated", "privilege", "exfil"]):
        severity, confidence = "high", 0.8
    if any(w in lower for w in ["info", "drift", "minor", "open port"]):
        severity, confidence, action = "low", 0.55, "escalate"
    tid, tname, tactic = _mock_mitre_lookup(description)
    return TriageClassification(
        severity=severity,
        confidence=confidence,
        rationale=(
            f"[MOCK MODE - no LLM key configured] Heuristic classification of "
            f"a {source} alert based on keyword signal in the description. "
            f"Set GROQ_API_KEY (free at console.groq.com) to enable real LLM classification."
        ),
        suggested_action=action,
        mitre_technique_id=tid,
        mitre_technique_name=tname,
        mitre_tactic=tactic,
    )


# ---------------------------------------------------------------------------
# Entry point used by the API layer and runner.py
# ---------------------------------------------------------------------------

def classify(description: str, source: str) -> TriageClassification:
    # Rules layer first -- free, instant, no LLM call
    ruled = run_rules(description)
    if ruled is not None:
        return ruled

    provider = resolve_llm_provider()
    if provider == "mock":
        return run_mock_llm(description, source)

    try:
        return run_llm(description, source, provider)
    except Exception as e:
        # Any provider failure degrades to mock rather than crashing the pipeline
        return TriageClassification(
            severity="med",
            confidence=0.4,
            rationale=(
                f"[LLM ERROR - {provider}] Classification failed: {str(e)[:120]}. "
                f"Defaulting to medium/escalate. Check your API key and provider config."
            ),
            suggested_action="escalate",
        )


def apply_classification(alert, result: TriageClassification) -> None:
    alert.severity = result.severity
    alert.confidence = result.confidence
    alert.rationale = result.rationale
    alert.suggested_action = result.suggested_action
    alert.mitre_technique_id = result.mitre_technique_id
    alert.mitre_technique_name = result.mitre_technique_name
    alert.mitre_tactic = result.mitre_tactic
    alert.status = "classified"
    alert.classified_at = datetime.utcnow()
