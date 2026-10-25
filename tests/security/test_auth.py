import asyncio
import base64
import hashlib
import hmac
import json
import logging
import socket
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from a2agw.security import auth as auth_mod
from a2agw.security.auth import (
    BEARER_STATE_KEY,
    AgentAccess,
    ApiKeyEntry,
    AuthConfig,
    GatewayAuthBackend,
    GatewayCallContextBuilder,
    JwtConfig,
    PermissionDenied,
    authorize,
    on_auth_error,
)
from a2agw.security.principal import Principal, PrincipalUser

ISS, AUD = "https://idp.test", "a2agw"


def _sha(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def pub_pem(rsa_key):
    return (
        rsa_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


@pytest.fixture(scope="module")
def priv_pem(rsa_key):
    return rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def make_client(config: AuthConfig) -> AsyncClient:
    async def whoami(request: Request):
        ctx = GatewayCallContextBuilder().build(request)
        p = request.user.principal
        return JSONResponse(
            {
                "id": p.id,
                "kind": p.kind,
                "scopes": sorted(p.scopes),
                "auth": request.auth.scopes,
                "ctx_user": ctx.user.user_name,
                "authenticated": ctx.user.is_authenticated,
                "bearer": ctx.state.get(BEARER_STATE_KEY),
                "headers": sorted(ctx.state["headers"]),
            }
        )

    app = Starlette(
        routes=[Route("/", whoami)],
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                backend=GatewayAuthBackend(config),
                on_error=on_auth_error,
            )
        ],
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def token(priv_pem, **over):
    claims = {
        "sub": "alice",
        "iss": ISS,
        "aud": AUD,
        "exp": int(time.time()) + 300,
        "scope": "read write",
    }
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, priv_pem, algorithm="RS256")


def jwt_config(pub_pem, **kw):
    return AuthConfig(jwt=JwtConfig(issuer=ISS, audience=AUD, public_key_pem=pub_pem, **kw))


KEYS = AuthConfig(api_keys={_sha("s3cret"): ApiKeyEntry(principal_id="svc", scopes=["a", "b"])})


async def assert_401(r):
    assert r.status_code == 401
    assert r.json() == {"error": "unauthenticated"}
    assert r.headers["www-authenticate"] == "Bearer"


async def test_api_key_header_authenticates():
    async with make_client(KEYS) as c:
        r = await c.get("/", headers={"X-API-Key": "s3cret"})
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "key:svc" and body["scopes"] == ["a", "b"] and body["kind"] == "api_key"
    assert body["auth"] == ["a", "b"]
    assert body["ctx_user"] == "key:svc" and body["authenticated"] is True


async def test_bearer_without_dots_is_api_key():
    async with make_client(KEYS) as c:
        r = await c.get("/", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and r.json()["id"] == "key:svc"


async def test_unknown_key_is_401():
    async with make_client(KEYS) as c:
        await assert_401(await c.get("/", headers={"X-API-Key": "nope"}))
        await assert_401(await c.get("/", headers={"Authorization": "Bearer nope"}))


async def test_jwt_rs256_valid(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        r = await c.get("/", headers={"Authorization": f"Bearer {token(priv_pem)}"})
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "jwt:alice" and body["kind"] == "jwt"
    assert body["scopes"] == ["read", "write"]


async def test_jwt_subject_with_nul_is_401(pub_pem, priv_pem):
    bad = token(priv_pem, sub="a\x00b")
    async with make_client(jwt_config(pub_pem)) as c:
        r = await c.get("/", headers={"Authorization": f"Bearer {bad}"})
    await assert_401(r)


async def test_jwt_scope_list_claim(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem, scopes_claim="perms")) as c:
        t = token(priv_pem, perms=["x", "y"])
        r = await c.get("/", headers={"Authorization": f"Bearer {t}"})
    assert r.json()["scopes"] == ["x", "y"]


async def test_jwt_wrong_audience_401(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        t = token(priv_pem, aud="other")
        await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))


async def test_jwt_wrong_issuer_401(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        t = token(priv_pem, iss="https://evil")
        await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))


async def test_expired_jwt_401(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        t = token(priv_pem, exp=int(time.time()) - 3600)
        await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))


async def test_jwt_within_leeway_ok(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        t = token(priv_pem, exp=int(time.time()) - 10)
        r = await c.get("/", headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 200


@pytest.mark.parametrize("missing", ["exp", "iss", "aud", "sub"])
async def test_jwt_missing_required_claim_401(pub_pem, priv_pem, missing):
    async with make_client(jwt_config(pub_pem)) as c:
        t = token(priv_pem, **{missing: None})
        await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))


async def test_alg_none_and_hs256_rejected(pub_pem):
    claims = {"sub": "alice", "iss": ISS, "aud": AUD, "exp": int(time.time()) + 300}
    none_tok = jwt.encode(claims, key=None, algorithm="none")

    # true confusion attack: HS256 token HMAC-signed with the PEM public key bytes,
    # assembled by hand because PyJWT refuses to sign with a PEM key.
    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    signing_input = (
        b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        + "."
        + b64(json.dumps(claims).encode())
    )
    sig = hmac.new(pub_pem.encode(), signing_input.encode(), hashlib.sha256).digest()
    hs_tok = f"{signing_input}.{b64(sig)}"
    async with make_client(jwt_config(pub_pem)) as c:
        for t in (none_tok, hs_tok):
            await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))


async def test_jwt_not_configured_401(priv_pem):
    async with make_client(KEYS) as c:
        await assert_401(await c.get("/", headers={"Authorization": f"Bearer {token(priv_pem)}"}))


async def test_anonymous_rejected_by_default():
    async with make_client(KEYS) as c:
        await assert_401(await c.get("/"))


async def test_anonymous_allowed_when_configured():
    async with make_client(AuthConfig(allow_anonymous=True)) as c:
        r = await c.get("/")
        bad = await c.get("/", headers={"X-API-Key": "nope"})
    body = r.json()
    assert r.status_code == 200
    assert body["id"] == "anonymous" and body["scopes"] == [] and body["authenticated"] is False
    await assert_401(bad)  # bad credentials never fall back to anonymous


def test_principal_user():
    p = Principal("key:svc", "api_key", frozenset({"a"}))
    u = PrincipalUser(p)
    assert u.principal is p and u.user_name == "key:svc" and u.is_authenticated


def test_authorize_scope_missing_raises():
    p = Principal("svc", "api_key", frozenset({"a"}))
    with pytest.raises(PermissionDenied):
        authorize(p, AgentAccess(required_scopes=frozenset({"a", "b"})))
    authorize(p, AgentAccess(required_scopes=frozenset({"a"})))


def test_authorize_principal_allowlist_and_anonymous():
    p = Principal("svc", "api_key", frozenset())
    authorize(p, AgentAccess())
    authorize(p, AgentAccess(allowed_principals=frozenset({"svc"})))
    with pytest.raises(PermissionDenied):
        authorize(p, AgentAccess(allowed_principals=frozenset({"other"})))
    with pytest.raises(PermissionDenied):
        authorize(None, AgentAccess())
    anon = Principal("anonymous", "anonymous", frozenset())
    with pytest.raises(PermissionDenied):
        authorize(anon, AgentAccess())


# ---- JWKS ----


@pytest.fixture
def jwks_url(tmp_path, rsa_key):
    # PyJWT refuses file:// JWKS URIs, so serve the JWKS from a loopback HTTP server.
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key()))
    jwk.update(kid="k1", use="sig", alg="RS256")
    (tmp_path / "jwks.json").write_text(json.dumps({"keys": [jwk]}))

    class Quiet(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(tmp_path), **kw)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/jwks.json"
    srv.shutdown()
    srv.server_close()


def jwks_config(url):
    return AuthConfig(jwt=JwtConfig(issuer=ISS, audience=AUD, jwks_url=url))


def kid_token(priv_pem, kid):
    claims = {"sub": "alice", "iss": ISS, "aud": AUD, "exp": int(time.time()) + 300}
    return jwt.encode(claims, priv_pem, algorithm="RS256", headers={"kid": kid})


async def test_jwks_valid_token_resolved_by_kid(jwks_url, priv_pem):
    async with make_client(jwks_config(jwks_url)) as c:
        r = await c.get("/", headers={"Authorization": f"Bearer {kid_token(priv_pem, 'k1')}"})
    assert r.status_code == 200 and r.json()["id"] == "jwt:alice"


async def test_jwks_unknown_kid_401(jwks_url, priv_pem):
    async with make_client(jwks_config(jwks_url)) as c:
        t = kid_token(priv_pem, "nope")
        await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))


async def test_jwks_unreachable_401_and_logged(priv_pem, caplog):
    with socket.socket() as sk:  # grab a port that nothing listens on
        sk.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{sk.getsockname()[1]}/jwks.json"
    t = kid_token(priv_pem, "k1")
    with caplog.at_level(logging.DEBUG, logger="a2agw.security.auth"):
        async with make_client(jwks_config(url)) as c:
            await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))
    assert "jwks unreachable" in caplog.text
    assert t not in caplog.text


async def test_jwks_fetched_once_and_cached(jwks_url, priv_pem, monkeypatch):
    from a2agw.consult import netguard

    calls: list[dict] = []
    real = netguard.safe_get

    async def spy(url, tier, **kw):
        calls.append({"url": url, "tier": tier, **kw})
        return await real(url, tier, **kw)

    monkeypatch.setattr(netguard, "safe_get", spy)
    async with make_client(jwks_config(jwks_url)) as c:
        h = {"Authorization": f"Bearer {kid_token(priv_pem, 'k1')}"}
        assert (await c.get("/", headers=h)).status_code == 200
        assert (await c.get("/", headers=h)).status_code == 200
    assert len(calls) == 1
    assert calls[0]["deadline_s"] == 5 and calls[0]["tier"] == "internal"
    assert "http" not in calls[0]  # no injected client: the guarded one


async def test_jwks_host_vetted_by_guarded_client(priv_pem, monkeypatch, caplog):
    """The JWKS host is resolved and vetted at connect time for ``jwks_tier`` (internal by
    default): a host resolving to a metadata address is never connected to."""
    from a2agw.consult import netguard
    from a2agw.consult.guarded_net import GuardedBackend

    seen: list[tuple[str, str]] = []
    real_connect = GuardedBackend.connect_tcp

    async def record(self, host, port, timeout=None, local_address=None, socket_options=None):
        seen.append((host, self._tier_for_host(host)))
        return await real_connect(self, host, port, timeout, local_address, socket_options)

    async def to_metadata(host):
        return ["169.254.169.254"]

    connected: list[str] = []

    async def never(self, host, port, timeout=None, local_address=None, socket_options=None):
        connected.append(host)
        raise AssertionError("must not connect")

    import httpcore

    monkeypatch.setattr(GuardedBackend, "connect_tcp", record)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", never)
    monkeypatch.setattr(netguard, "_resolve", to_metadata)
    t = kid_token(priv_pem, "k1")
    for tier in ("internal", "public"):
        cfg = AuthConfig(
            jwt=JwtConfig(
                issuer=ISS, audience=AUD, jwks_url="https://idp.example/jwks", jwks_tier=tier
            )
        )
        with caplog.at_level(logging.ERROR, logger="a2agw.security.auth"):
            async with make_client(cfg) as c:
                await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))
    # public: refused by the pre-check before any connection attempt; internal: at connect.
    assert seen == [("idp.example", "internal")]
    assert connected == []
    assert "jwks unreachable" in caplog.text and "idp.example" not in caplog.text


async def test_jwks_concurrent_misses_share_one_fetch(jwks_url, priv_pem, monkeypatch):
    from a2agw.consult import netguard

    calls = 0
    real = netguard.safe_get

    async def slow(url, tier, **kw):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return await real(url, tier, **kw)

    monkeypatch.setattr(netguard, "safe_get", slow)
    h = {"Authorization": f"Bearer {kid_token(priv_pem, 'k1')}"}
    async with make_client(jwks_config(jwks_url)) as c:
        rs = await asyncio.gather(*(c.get("/", headers=h) for _ in range(10)))
    assert [r.status_code for r in rs] == [200] * 10
    assert calls == 1


async def test_jwks_unknown_kid_refetch_rate_limited(jwks_url, priv_pem, monkeypatch):
    from a2agw.consult import netguard

    calls = 0
    real = netguard.safe_get

    async def count(url, tier, **kw):
        nonlocal calls
        calls += 1
        return await real(url, tier, **kw)

    monkeypatch.setattr(netguard, "safe_get", count)
    async with make_client(jwks_config(jwks_url)) as c:
        ok = {"Authorization": f"Bearer {kid_token(priv_pem, 'k1')}"}
        bad = {"Authorization": f"Bearer {kid_token(priv_pem, 'rotated')}"}
        assert (await c.get("/", headers=ok)).status_code == 200
        for _ in range(5):  # unknown kids right after a fetch: no refetch flood
            await assert_401(await c.get("/", headers=bad))
        assert calls == 1
        monkeypatch.setattr(auth_mod, "JWKS_REFETCH_MIN_S", 0.0)
        await assert_401(await c.get("/", headers=bad))
        assert calls == 2  # one bypass once the rate limit allows it
        monkeypatch.setattr(auth_mod, "JWKS_TTL_S", 0.0)
        assert (await c.get("/", headers=ok)).status_code == 200
        assert calls == 3  # expired set refetched


# ---- logging ----


async def test_jwt_rejection_logs_class_not_token(pub_pem, priv_pem, caplog):
    t = token(priv_pem, aud="other")
    with caplog.at_level(logging.DEBUG, logger="a2agw.security.auth"):
        async with make_client(jwt_config(pub_pem)) as c:
            await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))
    assert "jwt rejected: InvalidAudienceError" in caplog.text
    assert t not in caplog.text and t.split(".")[1] not in caplog.text


# ---- namespacing, validation, overlaps ----


async def test_same_name_key_and_jwt_have_distinct_user_names(pub_pem, priv_pem):
    cfg = AuthConfig(
        api_keys={_sha("k"): ApiKeyEntry(principal_id="svc")},
        jwt=JwtConfig(issuer=ISS, audience=AUD, public_key_pem=pub_pem),
    )
    async with make_client(cfg) as c:
        a = await c.get("/", headers={"X-API-Key": "k"})
        b = await c.get("/", headers={"Authorization": f"Bearer {token(priv_pem, sub='svc')}"})
    assert a.json()["ctx_user"] == "key:svc" and b.json()["ctx_user"] == "jwt:svc"


@pytest.mark.parametrize("sub", ["", "   "])
async def test_blank_sub_401(pub_pem, priv_pem, sub):
    async with make_client(jwt_config(pub_pem)) as c:
        t = token(priv_pem, sub=sub)
        await assert_401(await c.get("/", headers={"Authorization": f"Bearer {t}"}))


async def test_empty_credential_headers_401_even_if_anonymous_allowed():
    async with make_client(AuthConfig(allow_anonymous=True)) as c:
        await assert_401(await c.get("/", headers={"X-API-Key": ""}))
        await assert_401(await c.get("/", headers={"Authorization": ""}))
        await assert_401(await c.get("/", headers={"Authorization": "Bearer "}))


async def test_jwt_in_api_key_header_401(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        await assert_401(await c.get("/", headers={"X-API-Key": token(priv_pem)}))


async def test_api_key_header_wins_over_authorization(pub_pem, priv_pem):
    cfg = AuthConfig(
        api_keys={_sha("k"): ApiKeyEntry(principal_id="svc")},
        jwt=JwtConfig(issuer=ISS, audience=AUD, public_key_pem=pub_pem),
    )
    async with make_client(cfg) as c:
        h = {"X-API-Key": "k", "Authorization": f"Bearer {token(priv_pem)}"}
        r = await c.get("/", headers=h)
    assert r.json()["id"] == "key:svc"


async def test_non_bearer_scheme_401():
    async with make_client(KEYS) as c:
        await assert_401(await c.get("/", headers={"Authorization": "Basic czNjcmV0"}))
        await assert_401(await c.get("/", headers={"Authorization": "Token s3cret"}))


async def test_stored_hash_case_insensitive():
    cfg = AuthConfig(api_keys={_sha("s3cret").upper(): ApiKeyEntry(principal_id="svc")})
    async with make_client(cfg) as c:
        r = await c.get("/", headers={"X-API-Key": "s3cret"})
    assert r.status_code == 200


async def test_non_string_non_list_scopes_claim_is_empty(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        r = await c.get("/", headers={"Authorization": f"Bearer {token(priv_pem, scope=5)}"})
    assert r.status_code == 200 and r.json()["scopes"] == []


def test_config_validation(pub_pem):
    with pytest.raises(ValueError):
        JwtConfig(issuer=ISS, audience=AUD)
    with pytest.raises(ValueError):
        JwtConfig(issuer=ISS, audience=AUD, jwks_url="https://x", public_key_pem=pub_pem)
    with pytest.raises(ValueError):
        JwtConfig(issuer=ISS, audience=AUD, jwks_url="file:///etc/passwd")
    with pytest.raises(ValueError):
        AuthConfig(api_keys={"abc": ApiKeyEntry(principal_id="a")})
    h = _sha("k")
    with pytest.raises(ValueError):
        AuthConfig(
            api_keys={h: ApiKeyEntry(principal_id="a"), h.upper(): ApiKeyEntry(principal_id="b")}
        )
    assert list(AuthConfig(api_keys={h.upper(): ApiKeyEntry(principal_id="a")}).api_keys) == [h]


async def test_jwt_bearer_kept_for_exchange_api_keys_never(pub_pem, priv_pem):
    config = AuthConfig(
        api_keys={_sha("s3cret"): ApiKeyEntry(principal_id="svc")},
        jwt=JwtConfig(issuer=ISS, audience=AUD, public_key_pem=pub_pem),
    )
    tok = token(priv_pem)
    async with make_client(config) as c:
        r = await c.get("/", headers={"Authorization": f"Bearer {tok}"})
        assert r.json()["kind"] == "jwt"
        assert r.json()["bearer"] == tok
        for headers in ({"Authorization": "Bearer s3cret"}, {"X-API-Key": "s3cret"}):
            r = await c.get("/", headers={**headers, "X-Other": "1"})
            body = r.json()
            assert body["kind"] == "api_key" and body["bearer"] is None
            # The SDK's copy of the request headers no longer holds credentials.
            assert "authorization" not in body["headers"]
            assert "x-api-key" not in body["headers"]
            assert "x-other" in body["headers"]
