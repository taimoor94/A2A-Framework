"""a2agw: a framework-agnostic A2A (Agent2Agent) gateway.

Serve agents inbound over A2A and give them registered partner agents as tools.

The core never imports an agent framework. Native framework adapters live behind extras:
``a2agw.adapters.langchain``, ``a2agw.adapters.langgraph``, ``a2agw.adapters.openai_agents``,
``a2agw.adapters.claude_agent``, ``a2agw.adapters.adk``, ``a2agw.adapters.ag2``,
``a2agw.adapters.llamaindex`` and ``a2agw.adapters.crewai``; ``a2agw.adapters.callable``
serves plain Python functions.

Agents in any language join through the sidecar: ``a2agw.adapters.webhook`` (HTTP) and
``a2agw.adapters.stdio`` (a supervised process) serve them inbound, and the gateway's
outbound APIs in ``a2agw.gateway`` let them consult partners: the REST API
(``a2agw.gateway.rest``, ``/a2agw/v1``) and the MCP server (``a2agw.gateway.mcp_server``,
``/a2agw/mcp``, the ``mcp`` extra).
"""

from a2agw.adapters.callable import agent
from a2agw.adapters.stdio import StdioAdapter
from a2agw.adapters.webhook import WebhookAdapter
from a2agw.consult.client import PartnerClient
from a2agw.consult.registry import PartnerRegistry
from a2agw.consult.results import ToolResult
from a2agw.consult.tools import partner_tools
from a2agw.context.call_context import CallContext
from a2agw.core.events import (
    ArtifactChunk,
    Done,
    Failed,
    NeedAuth,
    NeedInput,
    Reply,
    Status,
    Usage,
)
from a2agw.ops.telemetry import setup_telemetry
from a2agw.security.auth import AgentAccess, AuthConfig
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

__version__ = "0.1.0"

__all__ = [
    "AgentAccess",
    "AgentHost",
    "AgentSpec",
    "ArtifactChunk",
    "AuthConfig",
    "CallContext",
    "Done",
    "Failed",
    "NeedAuth",
    "NeedInput",
    "PartnerClient",
    "PartnerRegistry",
    "Reply",
    "SkillSpec",
    "Status",
    "StdioAdapter",
    "ToolResult",
    "Usage",
    "WebhookAdapter",
    "__version__",
    "agent",
    "partner_tools",
    "setup_telemetry",
]
