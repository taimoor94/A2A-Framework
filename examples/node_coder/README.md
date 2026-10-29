# Node coder (webhook agent)

`agent.mjs` is an a2agw agent written in Node 24 with the standard library only
(`node:http`, `node:https`, `node:crypto`). The gateway serves it as an A2A agent and hands it
each turn over the webhook transport of the invoke protocol `a2agw.invoke/1`
([docs/sidecar.md](../../docs/sidecar.md)). It is the "non-Python agent" of the Phase 3 demo
([examples/software_team](../software_team/README.md)).

## What it does

For each `POST /a2agw/invoke`:

1. **Verifies the request** before parsing it. The `X-A2AGW-Timestamp` must be within 300 s of
   now, and `X-A2AGW-Signature` must equal `v1=` + hex HMAC-SHA256 of `timestamp + "." + body`
   with the shared secret, compared with `crypto.timingSafeEqual`. Anything else is `401`.
   A body that is not JSON or not `a2agw.invoke/1` is `400`.
2. **Streams NDJSON**: a `status` ("drafting code"), then the code as `text` events, then
   `done`.
3. **Consults `security`** during the turn, through the gateway's outbound REST API:
   `POST {consult.url}/partners/security/messages` with `Authorization: Bearer {consult.token}`.
   The call is linked to the coder's inbound task (cancel cascades, one trace, audited with the
   grant id). The token is kept in memory and never logged. If the consult fails, the coder
   still answers, noting that the review is unavailable.
4. **Treats a client disconnect as a cancel**: when the gateway closes the connection (the A2A
   task was cancelled or timed out), the turn stops and its consult request is aborted.

`GET /healthz` answers `ok` (a readiness probe). On start it prints `{"listening": <port>}` on
stdout; logs go to stderr.

## Run it

```bash
export CODER_SECRET=$(openssl rand -hex 32)       # shared with the gateway
PORT=9000 node examples/node_coder/agent.mjs
```

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `9000` | Port to listen on (`0`: a free one, printed on stdout) |
| `HOST` | `127.0.0.1` | Address to listen on (`0.0.0.0` in a container) |
| `SECRET_ENV` | `CODER_SECRET` | Name of the variable holding the signing secret |

It refuses to start without the secret. The gateway side names the same variable:

```yaml
agents:
  - id: coder
    name: Coder
    description: Writes code from a design.
    skills: [{id: code, name: Code, description: Writes code.}]
    webhook:
      url: http://127.0.0.1:9000/a2agw/invoke
      secret_env: CODER_SECRET
```

`examples/docker/compose.yaml` runs it next to the gateway. In the demo,
`examples/software_team/run_demo.py` starts it as a subprocess on a free loopback port with a
throwaway secret, waits for the readiness probe, and stops it at the end.
