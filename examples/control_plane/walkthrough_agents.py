"""The walkthrough's agents: ``planner`` on gw-east, ``p`` (the partner) on gw-west."""

from a2agw.adapters.callable import agent


@agent(id="planner", description="Plans trips (gw-east).")
async def planner(ctx):
    return f"planner: {ctx.text}"


@agent(id="p", description="Books things for other agents (gw-west); the shared partner.")
async def p(ctx):
    return f"p says: {ctx.text}"
