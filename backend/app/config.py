import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./longclaw.db")
ENV = os.getenv("ENV", "development")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")]
SCAN_INTERVAL_MINUTES = int(os.getenv("SCAN_INTERVAL_MINUTES", "10"))

# Background sweep runs inside the API process via APScheduler. If you ever
# scale to >1 worker/instance, set this to "false" on all but one so the
# sweep doesn't fire once per worker -- see deployment guide.
ENABLE_SCHEDULER = os.getenv("ENABLE_SCHEDULER", "true").lower() == "true"

# ---------------------------------------------------------------------------
# LLM provider config
#
# LLM_PROVIDER controls which backend the Triage agent uses.
# Priority (auto-detect if not set): groq → openai → huggingface → mock
#
# Groq   — free tier (14,400 req/day), fastest, best for cloud MVP.
#           Get a free key at console.groq.com
# OpenAI — paid, backward-compatible fallback.
# HuggingFace — free tier serverless inference, slower, rate-limited.
#               Get a free key at huggingface.co/settings/tokens
# ---------------------------------------------------------------------------
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto")   # groq | openai | huggingface | auto | mock

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY", "")
HUGGINGFACE_MODEL = os.getenv("HUGGINGFACE_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")


def resolve_llm_provider() -> str:
    """Return the effective provider name based on LLM_PROVIDER + available keys."""
    if LLM_PROVIDER != "auto":
        return LLM_PROVIDER
    if GROQ_API_KEY:
        return "groq"
    if OPENAI_API_KEY:
        return "openai"
    if HUGGINGFACE_API_KEY:
        return "huggingface"
    return "mock"
