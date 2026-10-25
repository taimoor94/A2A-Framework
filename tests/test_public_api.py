import subprocess
import sys

import a2agw


def test_public_api_exports():
    assert a2agw.__version__
    for name in a2agw.__all__:
        assert hasattr(a2agw, name), name
    for name in (
        "AgentHost",
        "AgentSpec",
        "SkillSpec",
        "agent",
        "PartnerRegistry",
        "PartnerClient",
        "partner_tools",
        "CallContext",
        "Status",
        "ArtifactChunk",
        "NeedInput",
        "NeedAuth",
        "Usage",
        "Done",
        "Failed",
        "Reply",
        "AuthConfig",
        "AgentAccess",
        "setup_telemetry",
        "ToolResult",
    ):
        assert name in a2agw.__all__, name


def test_import_a2agw_does_not_load_adapters_or_frameworks():
    code = (
        "import sys, a2agw;"
        "bad=[m for m in sys.modules if m.split('.')[0] in ('langchain_core','langchain','langgraph')"
        " or m in ('a2agw.adapters.langchain','a2agw.adapters.langgraph')];"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"
