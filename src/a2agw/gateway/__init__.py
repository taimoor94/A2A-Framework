"""Sidecar / gateway mode (spec 7.7): agents in any language join the network through a2agw.

``a2agw.gateway.protocol`` is the invoke contract the gateway uses to hand inbound work to an
external agent (see ``docs/sidecar.md``). ``a2agw.gateway.rest`` is the outbound REST API
those agents consult partners through, authenticated by ``a2agw.gateway.auth`` with a
run-scoped consult token (``a2agw.gateway.tokens``) or the gateway's own auth.
"""
