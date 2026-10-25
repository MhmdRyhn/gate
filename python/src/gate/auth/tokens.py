"""Signed access tokens (JWT, RFC 9068) and opaque refresh tokens.

Tokens carry identity only (who, which session, which kind). Roles and
permissions are resolved from the database on each request, so changes
take effect immediately.
"""

import base64
import hashlib
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

import jwt

from gate.auth.keys import ALG_EDDSA, ALG_RS256, KeySet
from gate.domain import UserKind

# JOSE "typ" header of access tokens (RFC 9068). Checking it prevents other
# JWTs (e.g. ID tokens) being replayed as access tokens.
ACCESS_TOKEN_TYPE: Final = "at+jwt"
_LEEWAY: Final = timedelta(seconds=30)


class TokenError(Exception):
    """Any token that fails verification. The cause is deliberately not
    exposed to clients."""


@dataclass(frozen=True, slots=True, kw_only=True)
class AccessClaims:
    subject: uuid.UUID
    session_id: uuid.UUID  # "sid": the token dies with its session
    kind: UserKind  # "kind": immutable per user
    issuer: str
    audience: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    token_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class IssuedToken:
    token: str
    expires_at: datetime


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True, kw_only=True)
class TokenIssuer:
    """Signs and verifies access tokens."""

    keys: KeySet
    issuer: str
    audience: str
    ttl: timedelta
    now: Callable[[], datetime] = _utcnow

    def issue(self, user_id: uuid.UUID, session_id: uuid.UUID, kind: UserKind) -> IssuedToken:
        now = self.now()
        exp = now + self.ttl
        k = self.keys.signing
        if k.private is None:
            raise TokenError("the signing key has no private half")
        claims = {
            "iss": self.issuer,
            "sub": str(user_id),
            "aud": [self.audience],
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": str(uuid.uuid4()),
            "sid": str(session_id),
            "kind": str(kind),
        }
        token = jwt.encode(claims, k.private, algorithm=k.algorithm, headers={"typ": ACCESS_TOKEN_TYPE, "kid": k.id})
        return IssuedToken(token=token, expires_at=exp)

    def parse(self, raw: str) -> AccessClaims:
        """Verifies signature, header type, issuer, audience and time claims.
        The key is selected by "kid" and must match the token's "alg", which
        rules out algorithm-confusion attacks."""
        try:
            header = jwt.get_unverified_header(raw)
            if header.get("typ") != ACCESS_TOKEN_TYPE:
                raise TokenError
            key = self.keys.lookup(str(header.get("kid", "")))
            if key is None or header.get("alg") != key.algorithm or key.algorithm not in (ALG_EDDSA, ALG_RS256):
                raise TokenError
            claims = jwt.decode(
                raw,
                key.public,
                algorithms=[key.algorithm],
                audience=self.audience,
                issuer=self.issuer,
                leeway=_LEEWAY,
                options={"require": ["exp", "iat", "sub", "sid"], "verify_iat": True},
            )
            # PyJWT checks expiry against the wall clock; also honour the
            # injected clock (tests, and a defence against clock skew bugs).
            if self.now().timestamp() > claims["exp"] + _LEEWAY.total_seconds():
                raise TokenError
            aud = claims["aud"]
            return AccessClaims(
                subject=uuid.UUID(claims["sub"]),
                session_id=uuid.UUID(claims["sid"]),
                kind=UserKind(str(claims["kind"])),
                issuer=claims["iss"],
                audience=tuple(aud) if isinstance(aud, list) else (aud,),
                issued_at=datetime.fromtimestamp(claims["iat"], UTC),
                expires_at=datetime.fromtimestamp(claims["exp"], UTC),
                token_id=str(claims.get("jti", "")),
            )
        except TokenError:
            raise
        except (jwt.PyJWTError, ValueError, KeyError, TypeError) as e:
            raise TokenError from e


@dataclass(frozen=True, slots=True)
class OpaqueToken:
    plain: str  # given to the client once
    hash: bytes  # persisted


def new_opaque_token() -> OpaqueToken:
    """A random 256-bit token (base64url) and its SHA-256 hash. Used for
    refresh tokens."""
    plain = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    return OpaqueToken(plain=plain, hash=hash_opaque_token(plain))


def hash_opaque_token(plain: str) -> bytes:
    """A fast hash is appropriate: the token has 256 bits of entropy."""
    return hashlib.sha256(plain.encode()).digest()
