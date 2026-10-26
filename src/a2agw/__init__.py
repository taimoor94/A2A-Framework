"""a2agw: a framework-agnostic A2A (Agent2Agent) gateway.

The core never imports langchain or langgraph; the adapters live in
``a2agw.adapters.langchain`` and ``a2agw.adapters.langgraph`` behind extras.
"""

from a2agw.adapters.callable import agent
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
    "ToolResult",
    "Usage",
    "WebhookAdapter",
    "__version__",
    "agent",
    "partner_tools",
    "setup_telemetry",
]
