"""Sidecar / gateway mode (spec 7.7): agents in any language join the network through a2agw.

``a2agw.gateway.protocol`` is the invoke contract the gateway uses to hand inbound work to an
external agent (see ``docs/sidecar.md``). ``a2agw.gateway.rest`` is the outbound REST API
those agents consult partners through, authenticated by ``a2agw.gateway.auth`` with a
run-scoped consult token (``a2agw.gateway.tokens``) or the gateway's own auth.
``a2agw.gateway.mcp_server`` serves the same partner tools over MCP (the ``mcp`` extra; never
imported by the core); both run calls through ``a2agw.gateway.calls``.
"""
