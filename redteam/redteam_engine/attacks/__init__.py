"""Attack family registry — every category in the AgentShield taxonomy."""
from redteam_engine.attacks.base import AttackFamily
from redteam_engine.attacks.prompt_injection import PromptInjectionFamily
from redteam_engine.attacks.jailbreak import JailbreakFamily
from redteam_engine.attacks.system_prompt_extraction import SystemPromptExtractionFamily
from redteam_engine.attacks.rag_poisoning import RagPoisoningFamily
from redteam_engine.attacks.memory_poisoning import MemoryPoisoningFamily
from redteam_engine.attacks.tool_poisoning import ToolPoisoningFamily
from redteam_engine.attacks.mcp_attacks import McpAttackFamily
from redteam_engine.attacks.data_exfiltration import DataExfiltrationFamily
from redteam_engine.attacks.privilege_escalation import PrivilegeEscalationFamily
from redteam_engine.attacks.excessive_agency import ExcessiveAgencyFamily
from redteam_engine.attacks.agent_to_agent import AgentToAgentFamily

ALL_FAMILIES: list[AttackFamily] = [
    PromptInjectionFamily(),
    JailbreakFamily(),
    SystemPromptExtractionFamily(),
    RagPoisoningFamily(),
    MemoryPoisoningFamily(),
    ToolPoisoningFamily(),
    McpAttackFamily(),
    DataExfiltrationFamily(),
    PrivilegeEscalationFamily(),
    ExcessiveAgencyFamily(),
    AgentToAgentFamily(),
]

FAMILY_BY_CATEGORY = {f.category: f for f in ALL_FAMILIES}
