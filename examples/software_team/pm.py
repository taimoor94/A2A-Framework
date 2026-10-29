"""PM agent: a LangGraph orchestrator with a scripted (deterministic) fake model.

No LLM decides what to do: the graph encodes the plan and its nodes call the partner tools
from ``as_langchain_tools`` directly, exactly as a tool-calling model would. The PM

1. asks the architect for a design and, when the architect needs input, answers from its own
   state ("PostgreSQL") on the same task and context;
2. with the Node coder on the team (``coder=True``), asks it to implement the design (the
   coder consults security itself, through the gateway's REST API);
3. asks security for a review with a short wait, gets a ``working`` handle back, and calls
   ``a2a_wait`` until the review is done;
4. assembles the answers into one report.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage
from langchain_core.tools import BaseTool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from a2agw.adapters.langgraph import GraphAdapter, as_langchain_tools
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

DATABASE = "PostgreSQL"  # the PM's answer when the architect asks
SECURITY_WAIT_S = 0.5  # short on purpose: the review outlasts it, so a handle comes back
WAIT_SECONDS = 10.0
MAX_WAITS = 6


class PMState(TypedDict, total=False):
    messages: Annotated[list, add_messages]
    goal: str
    database: str
    design: str
    code: str
    review: str


class PartnerError(RuntimeError):
    pass


def _tools(host: AgentHost) -> dict[str, BaseTool]:
    # host.client exists only after startup, so the tools are built per run.
    assert host.client is not None
    # host.partner_tools applies the host's routing policy for this agent (forbidden partners
    # are hidden, and consult refuses them anyway).
    return {t.name: t for t in as_langchain_tools(host.partner_tools("pm"), host.client)}


async def _call(tool: BaseTool, args: dict[str, Any]) -> dict[str, Any]:
    return json.loads(await tool.ainvoke(args))


def _expect_completed(result: dict[str, Any], who: str) -> str:
    if result.get("state") != "completed":
        raise PartnerError(f"{who} ended in state {result.get('state')!r}")
    return result.get("text") or ""


def build_graph(host: AgentHost, *, coder: bool = False):
    async def ask_architect(state: PMState) -> dict[str, Any]:
        ask = _tools(host)["ask_architect"]
        result = await _call(ask, {"message": f"Design a todo API: {state['goal']}"})
        if result.get("state") == "input_required":
            # The architect asked a question; answer it from our own state, same task.
            result = await _call(
                ask,
                {
                    "message": state["database"],
                    "task_id": result["task_id"],
                    "context_id": result["context_id"],
                },
            )
        return {"design": _expect_completed(result, "architect")}

    async def ask_coder(state: PMState) -> dict[str, Any]:
        ask = _tools(host)["ask_coder"]
        result = await _call(ask, {"message": f"Implement the design:\n{state['design']}"})
        return {"code": _expect_completed(result, "coder")}

    async def ask_security(state: PMState) -> dict[str, Any]:
        tools = _tools(host)
        result = await _call(
            tools["ask_security"],
            {"message": f"Review the design: {state['design']}", "wait_seconds": SECURITY_WAIT_S},
        )
        for _ in range(MAX_WAITS):
            if result.get("state") != "working":
                break
            handle = {"partner_id": "security", "task_id": result["task_id"]}
            waited = await _call(tools["a2a_wait"], {"tasks": [handle], "seconds": WAIT_SECONDS})
            result = waited["results"][0]
        return {"review": _expect_completed(result, "security")}

    async def assemble(state: PMState) -> dict[str, Any]:
        code = f"## Code\n\n{state['code']}\n\n" if state.get("code") else ""
        report = (
            f"## Architecture\n\n{state['design']}\n\n{code}## Security review\n\n{state['review']}"
        )
        return {"messages": [AIMessage(content=report)]}

    graph = StateGraph(PMState)
    graph.add_node("ask_architect", ask_architect)
    graph.add_node("ask_security", ask_security)
    graph.add_node("assemble", assemble)
    graph.add_edge(START, "ask_architect")
    if coder:
        graph.add_node("ask_coder", ask_coder)
        graph.add_edge("ask_architect", "ask_coder")
        graph.add_edge("ask_coder", "ask_security")
    else:
        graph.add_edge("ask_architect", "ask_security")
    graph.add_edge("ask_security", "assemble")
    graph.add_edge("assemble", END)
    return graph.compile(checkpointer=InMemorySaver())


def _input(ctx: InboundContext) -> dict[str, Any]:
    return {"messages": [("user", ctx.text)], "goal": ctx.text, "database": DATABASE}


def pm_agent(host: AgentHost, *, coder: bool = False) -> AgentSpec:
    return AgentSpec(
        id="pm",
        name="PM",
        description="Project manager: turns a goal into a reviewed design using the team.",
        skills=[
            SkillSpec(
                id="plan",
                name="Plan a feature",
                description="Gets a design from the architect and a review from security.",
                examples=["Build a todo API"],
            )
        ],
        adapter=GraphAdapter(build_graph(host, coder=coder), input_mapper=_input),
    )
