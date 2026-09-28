"""Agent IAM registry.

Loads the Human -> Agent -> Tool identity chain from YAML and answers the
only question that matters at request time: does this agent hold this
permission on this resource, through a tool it is actually allowed to use.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from gateway.models import AgentIdentity, HumanIdentity, ResourcePermission, ToolIdentity

DEFAULT_REGISTRY_PATH = Path(__file__).parent / "agents.yaml"


class IdentityRegistry:
    def __init__(self, path: Path | str = DEFAULT_REGISTRY_PATH):
        self.path = Path(path)
        self.humans: dict[str, HumanIdentity] = {}
        self.agents: dict[str, AgentIdentity] = {}
        self.tools: dict[str, ToolIdentity] = {}
        self.reload()

    def reload(self) -> None:
        raw = yaml.safe_load(self.path.read_text()) or {}

        self.humans = {
            h["human_id"]: HumanIdentity(**h) for h in raw.get("humans", [])
        }

        agents: dict[str, AgentIdentity] = {}
        for a in raw.get("agents", []):
            permissions = {
                category: ResourcePermission(**perms)
                for category, perms in (a.get("permissions") or {}).items()
            }
            agents[a["agent_id"]] = AgentIdentity(
                agent_id=a["agent_id"],
                name=a["name"],
                description=a.get("description", ""),
                owner_human_id=a["owner_human_id"],
                trust_level=a.get("trust_level", "standard"),
                allowed_tools=a.get("allowed_tools", []),
                permissions=permissions,
            )
        self.agents = agents

        self.tools = {
            t["tool_id"]: ToolIdentity(**t) for t in raw.get("tools", [])
        }

    def get_human(self, human_id: str) -> HumanIdentity | None:
        return self.humans.get(human_id)

    def get_agent(self, agent_id: str) -> AgentIdentity | None:
        return self.agents.get(agent_id)

    def get_tool(self, tool_id: str) -> ToolIdentity | None:
        return self.tools.get(tool_id)

    def tool_authorized_for_agent(self, agent: AgentIdentity, tool_id: str) -> bool:
        return tool_id in agent.allowed_tools

    @staticmethod
    def resource_category(resource: str) -> str:
        return resource.split(".", 1)[0]

    def has_permission(self, agent: AgentIdentity, resource: str, action: str) -> bool:
        category = self.resource_category(resource)
        perm = agent.permissions.get(category)
        if perm is None:
            return False
        return bool(getattr(perm, action, False))


registry = IdentityRegistry()
