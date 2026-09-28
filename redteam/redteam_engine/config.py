import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_URL = os.getenv("REDTEAM_DATABASE_URL", f"sqlite:///{DATA_DIR / 'redteam.db'}")
PORT = int(os.getenv("REDTEAM_PORT", "8002"))
TARGET_AGENT_URL = os.getenv("TARGET_AGENT_URL", "http://localhost:8001")
# Sent as X-API-Key on every request to the target agent -- only matters
# if that target has ADMIN_API_KEY set (target_agent/config.py).
TARGET_ADMIN_API_KEY = os.getenv("TARGET_ADMIN_API_KEY", "")

# Gates this service's own write endpoints (/campaigns/run,
# /findings/{id}/regression, /regression/run-all). Empty (default) = open,
# fine for local/CI use. Read-only endpoints (scorecard, findings list)
# stay open even when this is set, so the dashboard stays viewable.
REDTEAM_API_KEY = os.getenv("REDTEAM_API_KEY", "")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_JUDGE_MODEL = os.getenv("OLLAMA_JUDGE_MODEL", os.getenv("OLLAMA_MODEL", "llama3.2:3b"))
USE_OLLAMA = os.getenv("USE_OLLAMA", "false").lower() == "true"

# Optional free-text second opinion (llm_judge.py) alongside every
# deterministic ground-truth judge. Off by default -- adds a real LLM
# call per attempt, so it trades campaign speed for nuance. Never
# overrides the deterministic `success` verdict.
ENABLE_LLM_JUDGE = os.getenv("ENABLE_LLM_JUDGE", "false").lower() == "true"

# Attack-planner loop bounds
MAX_MUTATIONS_PER_TECHNIQUE = int(os.getenv("MAX_MUTATIONS_PER_TECHNIQUE", "3"))

# Independent (family, technique) runs execute concurrently across this
# many worker threads. 1 = fully sequential (old behavior). httpx.Client
# is thread-safe for concurrent requests; each worker opens its own DB
# session, so this is safe to raise for large-scale campaigns.
MAX_WORKERS = int(os.getenv("REDTEAM_MAX_WORKERS", "4"))

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 5}

CATEGORY_LABELS = {
    "prompt_injection": "Prompt Injection",
    "jailbreak": "Jailbreak",
    "system_prompt_extraction": "System Prompt Extraction",
    "rag_poisoning": "RAG Security",
    "memory_poisoning": "Memory Security",
    "tool_poisoning": "Tool Security",
    "mcp_attacks": "MCP Security",
    "data_exfiltration": "Data Protection",
    "privilege_escalation": "Agent Authorization",
    "excessive_agency": "Excessive Agency",
    "agent_to_agent": "Agent-to-Agent Security",
}

# Dashboard scorecard groups a couple of raw categories together to match
# the requested top-level scorecard rows.
SCORECARD_ROWS = {
    "Prompt Injection": ["prompt_injection", "jailbreak", "system_prompt_extraction"],
    "RAG Security": ["rag_poisoning"],
    "Memory Security": ["memory_poisoning"],
    "Tool Security": ["tool_poisoning", "excessive_agency"],
    "MCP Security": ["mcp_attacks"],
    "Data Protection": ["data_exfiltration"],
    "Agent Authorization": ["privilege_escalation", "agent_to_agent"],
}
