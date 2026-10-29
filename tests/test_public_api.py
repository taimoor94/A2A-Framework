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
        "WebhookAdapter",
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


def test_package_docstring_names_every_adapter_and_the_sidecar():
    import pkgutil

    import a2agw
    import a2agw.adapters

    doc = a2agw.__doc__ or ""
    adapters = [m.name for m in pkgutil.iter_modules(a2agw.adapters.__path__)]
    for name in (n for n in adapters if not n.startswith("_")):
        assert f"a2agw.adapters.{name}" in doc, name
    for part in ("a2agw.gateway", "sidecar", "MCP"):
        assert part in doc, part


def test_readme_known_limitations_name_consult_token_affinity():
    from pathlib import Path

    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    limits = readme.split("## Known limitations", 1)[1].split("\n## ", 1)[0]
    line = next((x for x in limits.splitlines() if "consult token" in x.lower()), "")
    assert "sticky" in line and "replica" in line, line
