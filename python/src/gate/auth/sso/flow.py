"""Client-side state of an SSO sign-in, kept in a signed HttpOnly cookie
between the start and callback. Keeping it out of the database makes the
flow stateless and horizontally scalable."""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Final

# Bounds how long a user may take at the provider's login page.
FLOW_TTL: Final = timedelta(minutes=10)
MIN_STATE_KEY_LENGTH: Final = 32


class InvalidStateError(ValueError):
    """The state cookie is missing, tampered, expired or does not match."""


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _random() -> str:
    return _b64url(secrets.token_bytes(32))


@dataclass(frozen=True, slots=True, kw_only=True)
class FlowState:
    provider: str
    state: str  # CSRF protection (RFC 6749 §10.12)
    nonce: str  # ID token replay protection (OIDC)
    code_verifier: str  # PKCE (RFC 7636)
    expires_at: float  # unix seconds

    def code_challenge(self) -> str:
        """The PKCE S256 challenge for the verifier."""
        return _b64url(hashlib.sha256(self.code_verifier.encode()).digest())


def new_flow_state(provider: str, now: datetime) -> FlowState:
    return FlowState(
        provider=provider,
        state=_random(),
        nonce=_random(),
        code_verifier=_random() + _random(),  # 86 chars
        expires_at=(now + FLOW_TTL).timestamp(),
    )


@dataclass(frozen=True, slots=True, repr=False)
class StateCodec:
    """Seals and opens FlowState with HMAC-SHA256. The payload is signed,
    not encrypted: it contains only one-time random values."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) < MIN_STATE_KEY_LENGTH:
            raise ValueError("SSO_STATE_KEY must be at least 32 bytes")

    def seal(self, f: FlowState) -> str:
        p = _b64url(json.dumps(asdict(f), separators=(",", ":")).encode())
        return f"{p}.{self._sign(p)}"

    def open(self, sealed: str, now: datetime) -> FlowState:
        p, _, sig = sealed.partition(".")
        if not sig or not hmac.compare_digest(sig, self._sign(p)):
            raise InvalidStateError
        try:
            f = FlowState(**json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))))
        except (ValueError, TypeError) as e:
            raise InvalidStateError from e
        if now.timestamp() > f.expires_at:
            raise InvalidStateError
        return f

    def _sign(self, p: str) -> str:
        return _b64url(hmac.new(self.key, b"sso-state:" + p.encode(), hashlib.sha256).digest())
