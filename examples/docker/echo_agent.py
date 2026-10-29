"""Echo agent used by the Docker example and the image test."""

from a2agw.adapters.callable import agent


@agent(id="echo", description="Echoes the user's message back.")
async def echo(ctx):
    return f"echo: {ctx.text}"
