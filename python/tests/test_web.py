import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
import structlog
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware import Middleware
from starlette.responses import Response

from gate import rbac
from gate.auth.sso import Identity, Policy, Registration, Registry
from gate.domain import InvalidTokenError, Principal, UserKind
from gate.service import TokenPair
from gate.web.app import install_error_handlers
from gate.web.deps import make_authenticate, rate_limit, require_kind, require_permissions, require_public_type
from gate.web.dto import LoginRequest
from gate.web.middleware import GateMiddleware
from gate.web.ratelimit import IPRateLimiter
from gate.web.routes_sso import SSO_COOKIE, sso_routes

LOG = structlog.get_logger()


def principal(kind: UserKind, *perms: str, types: tuple[str, ...] = ()) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        kind=kind,
        public_types=types,
        permissions=frozenset(rbac.Permission(p) for p in perms),
    )


class FakeAuthn:
    def __init__(self, tokens: dict[str, Principal]) -> None:
        self.tokens = tokens

    async def authenticate(self, raw_token: str) -> Principal:
        if raw_token in self.tokens:
            return self.tokens[raw_token]
        raise InvalidTokenError


def new_app(*, max_body: int = 1 << 20) -> FastAPI:
    app = FastAPI(middleware=[Middleware(GateMiddleware, log=LOG, max_body_bytes=max_body, trusted=())])
    install_error_handlers(app)
    return app


def test_authorization() -> None:
    authn = make_authenticate(
        FakeAuthn(
            {
                "staff": principal(UserKind.INTERNAL, rbac.USERS_READ),
                "vendor": principal(UserKind.PUBLIC, rbac.USERS_READ, types=("customer", "vendor")),
                "customer": principal(UserKind.PUBLIC, types=("customer",)),
            }
        )
    )
    internal, public = Depends(require_kind(authn, UserKind.INTERNAL)), Depends(require_kind(authn, UserKind.PUBLIC))
    app = new_app()

    async def ok() -> Response:
        return Response(status_code=200)

    app.get("/any", dependencies=[Depends(authn)])(ok)
    app.get("/admin", dependencies=[internal, Depends(require_permissions(authn, rbac.USERS_READ))])(ok)
    app.get(
        "/admin/write",
        dependencies=[internal, Depends(require_permissions(authn, rbac.USERS_READ, rbac.USERS_CREATE))],
    )(ok)
    app.get("/app", dependencies=[public])(ok)
    app.get("/app/vendor", dependencies=[public, Depends(require_public_type(authn, "vendor"))])(ok)

    client = TestClient(app)
    cases = [
        ("/any", "", 401),
        ("/any", "bogus", 401),
        ("/any", "customer", 200),
        ("/admin", "staff", 200),
        ("/admin/write", "staff", 403),
        ("/admin", "vendor", 403),  # a public user holding the permission is still blocked
        ("/app", "staff", 403),
        ("/app", "customer", 200),
        ("/app/vendor", "customer", 403),
        ("/app/vendor", "vendor", 200),
    ]
    for path, token, want in cases:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = client.get(path, headers=headers)
        assert r.status_code == want, (path, token, r.text)
        if want >= 400:
            assert r.headers["content-type"].startswith("application/problem+json")
            body = r.json()
            assert body["status"] == want and body["code"] and body["request_id"]
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-content-type-options"] == "nosniff"


def test_request_id_propagation() -> None:
    app = new_app()
    app.get("/")(lambda: {"ok": True})
    client = TestClient(app)
    assert client.get("/", headers={"X-Request-ID": "trace-123"}).headers["x-request-id"] == "trace-123"
    replaced = client.get("/", headers={"X-Request-ID": "bad id <script>"}).headers["x-request-id"]
    uuid.UUID(replaced)  # malformed IDs are replaced


def test_validation_and_body_limits() -> None:
    app = new_app(max_body=64)

    @app.post("/login")
    async def login(req: LoginRequest) -> dict[str, str]:
        return {"id": req.identifier}

    client = TestClient(app)
    r = client.post("/login", json={"identifier": "a@b.io"})
    assert r.status_code == 400 and r.json()["detail"] == "password is required"
    r = client.post("/login", json={"identifier": "a@b.io", "password": "x", "admin": True})
    assert r.status_code == 400 and 'unknown field "admin"' in r.json()["detail"]
    r = client.post("/login", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 400 and r.json()["code"] == "invalid_request"
    r = client.post("/login", json={"identifier": "a" * 100, "password": "x"})
    assert r.status_code == 413
    assert client.get("/nope").json()["code"] == "not_found"
    assert client.get("/login").status_code == 405


def test_rate_limit() -> None:
    app = new_app()
    app.post("/login", dependencies=[Depends(rate_limit(IPRateLimiter(per_minute=60, burst=2)))])(lambda: {})
    client = TestClient(app)
    assert [client.post("/login").status_code for _ in range(3)] == [200, 200, 429]
    assert client.post("/login").headers["retry-after"] == "2"


def test_trusted_proxy_client_ip() -> None:
    from ipaddress import ip_network

    from gate.web.middleware import client_ip

    trusted = (ip_network("10.0.0.0/8"),)
    scope = {"client": ("10.0.0.5", 1234)}
    assert client_ip(scope, b"203.0.113.9, 10.0.0.7", trusted) == "203.0.113.9"
    assert client_ip({"client": ("198.51.100.1", 1)}, b"203.0.113.9", trusted) == "198.51.100.1"  # untrusted peer
    assert client_ip(scope, b"203.0.113.9", ()) == "10.0.0.5"  # no trusted proxies


# --- SSO flow ---------------------------------------------------------------------


class FakeProvider:
    def __init__(self) -> None:
        self.got_verifier = self.got_nonce = ""

    @property
    def name(self) -> str:
        return "fake"

    def auth_code_url(self, state: str, nonce: str, code_challenge: str) -> str:
        return f"https://idp.example/authorize?state={state}&nonce={nonce}&code_challenge={code_challenge}"

    async def exchange(self, code: str, code_verifier: str, nonce: str) -> Identity:
        self.got_verifier, self.got_nonce = code_verifier, nonce
        return Identity(provider="", subject="sub-1", email="a@example.com", email_verified=True)


class FakeSignIn:
    def __init__(self) -> None:
        self.got: Identity | None = None

    async def sign_in(self, provider_name: str, identity: Identity) -> TokenPair:
        self.got = identity
        now = datetime.now(UTC)
        return TokenPair(
            access_token="at",
            refresh_token="rt",
            access_token_expires_at=now + timedelta(minutes=1),
            refresh_token_expires_at=now + timedelta(hours=1),
            session_id=uuid.uuid4(),
        )


async def no_limit() -> None:
    return None


def test_sso_flow() -> None:
    prov, sign_in = FakeProvider(), FakeSignIn()
    router = sso_routes(
        registry=Registry.of(Registration(prov, Policy(kind=UserKind.PUBLIC))),
        state_key=b"k" * 32,
        sign_in=sign_in,
        limiter=no_limit,
        log=LOG,
    )
    assert router is not None
    app = new_app()
    app.include_router(router)
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)

    # Start: redirect with state, nonce and S256 challenge; state cookie set.
    r = client.get("/v1/auth/sso/fake/start")
    assert r.status_code == 302
    q = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
    set_cookie = r.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "secure" in set_cookie and "samesite=lax" in set_cookie
    sealed = r.cookies[SSO_COOKIE]

    def callback(query: str, with_cookie: bool) -> int:
        client.cookies.clear()
        if with_cookie:
            client.cookies.set(SSO_COOKIE, sealed)
        return client.get(f"/v1/auth/sso/fake/callback?{query}").status_code

    assert callback(f"code=c&state={q['state']}", with_cookie=False) == 400
    assert callback("code=c&state=forged", with_cookie=True) == 400
    assert callback(f"code=c&state={q['state']}", with_cookie=True) == 200
    assert prov.got_nonce == q["nonce"] and prov.got_verifier
    assert sign_in.got is not None and sign_in.got.provider == "fake"
    assert client.get("/v1/auth/sso/unknown/start").status_code == 404


def test_sso_disabled_without_providers() -> None:
    assert sso_routes(registry=Registry.of(), state_key=b"", sign_in=FakeSignIn(), limiter=no_limit, log=LOG) is None
    with pytest.raises(ValueError, match="32 bytes"):
        sso_routes(
            registry=Registry.of(Registration(FakeProvider(), Policy(kind=UserKind.PUBLIC))),
            state_key=b"short",
            sign_in=FakeSignIn(),
            limiter=no_limit,
            log=LOG,
        )
