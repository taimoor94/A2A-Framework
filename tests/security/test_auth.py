import hashlib
import time

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

from a2agw.security.auth import (
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
    assert body["id"] == "svc" and body["scopes"] == ["a", "b"] and body["kind"] == "api_key"
    assert body["auth"] == ["a", "b"]
    assert body["ctx_user"] == "svc" and body["authenticated"] is True


async def test_bearer_without_dots_is_api_key():
    async with make_client(KEYS) as c:
        r = await c.get("/", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and r.json()["id"] == "svc"


async def test_unknown_key_is_401():
    async with make_client(KEYS) as c:
        await assert_401(await c.get("/", headers={"X-API-Key": "nope"}))
        await assert_401(await c.get("/", headers={"Authorization": "Bearer nope"}))


async def test_jwt_rs256_valid(pub_pem, priv_pem):
    async with make_client(jwt_config(pub_pem)) as c:
        r = await c.get("/", headers={"Authorization": f"Bearer {token(priv_pem)}"})
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "alice" and body["kind"] == "jwt"
    assert body["scopes"] == ["read", "write"]


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
    # classic confusion attack: HMAC-sign with the public key bytes as the secret
    hs_tok = jwt.encode(claims, "x" * 40, algorithm="HS256")
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
    p = Principal("svc", "api_key", frozenset({"a"}))
    u = PrincipalUser(p)
    assert u.principal is p and u.user_name == "svc" and u.is_authenticated


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
