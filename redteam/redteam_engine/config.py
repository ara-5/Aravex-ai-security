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

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_JUDGE_MODEL = os.getenv("OLLAMA_JUDGE_MODEL", os.getenv("OLLAMA_MODEL", "llama3.2:3b"))
USE_OLLAMA = os.getenv("USE_OLLAMA", "false").lower() == "true"

# Attack-planner loop bounds
MAX_MUTATIONS_PER_TECHNIQUE = int(os.getenv("MAX_MUTATIONS_PER_TECHNIQUE", "3"))

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
