"""Architect agent: a LangChain ``RunnableLambda`` that asks one clarifying question.

The design text comes from a ``RunnableLambda`` that reads a per-thread message history
(keyed on the LangGraph-style ``thread_id``, which is the A2A ``contextId``). The
LangChain adapter has no input-required path for plain runnables, so the agent is served
through ``CallableAdapter``: its wrapper yields ``NeedInput("Which database?")`` on the
first turn and calls the runnable on the resumed turn.

With ``ANTHROPIC_API_KEY`` set and ``A2AGW_DEMO_LLM=1`` the design is written by Claude via
``langchain-anthropic`` (imported lazily; not a declared dependency). Otherwise, or if that
package is missing, a scripted design is used.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.runnables import RunnableConfig, RunnableLambda

from a2agw.adapters.callable import CallableAdapter
from a2agw.core.events import AgentEvent, Done, NeedInput
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec

QUESTION = "Which database?"
LLM_MODEL = "claude-opus-5-5"
LLM_SYSTEM = (
    "You are a software architect. Write a concise API design: endpoints, "
    "data model and storage, auth. Plain text, under 25 lines."
)


class Histories:
    """Chat message histories keyed on ``thread_id`` (in memory, for the demo)."""

    def __init__(self) -> None:
        self._by_thread: dict[str, list[BaseMessage]] = {}

    def get(self, thread_id: str) -> list[BaseMessage]:
        return self._by_thread.setdefault(thread_id, [])


def scripted_design(goal: str, database: str) -> str:
    return (
        f"Design for: {goal}\n"
        "- REST endpoints: GET /todos, POST /todos, GET/PATCH/DELETE /todos/{id}\n"
        f"- Storage: {database}, table todos(id uuid pk, title text, done bool, "
        "created_at timestamptz)\n"
        "- Auth: bearer tokens; each todo belongs to one user\n"
        "- Validation: title 1-200 chars; pagination with limit/cursor on GET /todos"
    )


def _llm_enabled() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and os.environ.get("A2AGW_DEMO_LLM") == "1"


async def _llm_design(goal: str, database: str) -> str | None:
    """Claude's design, or None if ``langchain-anthropic`` is not installed."""
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:
        return None
    llm = ChatAnthropic(model=LLM_MODEL, max_tokens=2048)
    reply = await llm.ainvoke(
        [
            ("system", LLM_SYSTEM),
            ("user", f"Goal: {goal}\nDatabase: {database}"),
        ]
    )
    return reply.text or None


def design_runnable(histories: Histories) -> RunnableLambda:
    """``{"database": str}`` -> design text, using the thread's history for the goal."""

    async def design(inputs: dict, config: RunnableConfig) -> str:
        thread_id = config["configurable"]["thread_id"]
        # History ends [..., goal, "Which database?", answer]: the goal is the human turn
        # before the answer.
        asked = [m for m in histories.get(thread_id) if isinstance(m, HumanMessage)]
        goal = str(asked[-2].content) if len(asked) >= 2 else ""
        database = inputs["database"]
        text = await _llm_design(goal, database) if _llm_enabled() else None
        return text or scripted_design(goal, database)

    return RunnableLambda(design, name="architect_design")


def architect_agent() -> AgentSpec:
    histories = Histories()
    runnable = design_runnable(histories)

    async def run(ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        history = histories.get(ctx.context_id)
        history.append(HumanMessage(ctx.text))
        if not ctx.resumed:
            history.append(AIMessage(QUESTION))
            yield NeedInput(QUESTION)
            return
        design = await runnable.ainvoke(
            {"database": ctx.text.strip()},
            config={"configurable": {"thread_id": ctx.context_id}},
        )
        history.append(AIMessage(design))
        yield Done(design)

    return AgentSpec(
        id="architect",
        name="Architect",
        description="Designs software systems and APIs; asks which database to use.",
        skills=[
            SkillSpec(
                id="design",
                name="System design",
                description="Designs an API or service from a short goal.",
                examples=["Design a todo API"],
            )
        ],
        adapter=CallableAdapter(run),
    )
