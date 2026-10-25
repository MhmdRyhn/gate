"""Extension points for single sign-on with external identity providers
(OpenID Connect, OAuth 2.0, SAML via a bridge).

No provider is integrated yet. To add one, implement ``Provider``
(typically with Authlib), choose a ``Policy`` and register both in
``gate.container.sso_registry``. The HTTP flow (state, nonce, PKCE,
callback) and account linking are already implemented.
"""

from dataclasses import dataclass
from typing import Protocol

from gate.auth.sso.flow import FLOW_TTL, FlowState, InvalidStateError, StateCodec, new_flow_state
from gate.domain import UserKind


@dataclass(frozen=True, slots=True, kw_only=True)
class Identity:
    """What a provider asserts about the signed-in user after its token has
    been fully verified."""

    provider: str
    subject: str  # stable, provider-unique user ID ("sub")
    email: str = ""
    email_verified: bool = False  # only trust email for linking when the IdP verified it
    name: str = ""


class Provider(Protocol):
    """One external identity provider using the authorization code flow."""

    @property
    def name(self) -> str:
        """URL-safe registry key, e.g. "google"."""
        ...

    def auth_code_url(self, state: str, nonce: str, code_challenge: str) -> str:
        """The provider's authorization URL. state and nonce must be passed
        through unchanged; code_challenge is the PKCE S256 challenge."""
        ...

    async def exchange(self, code: str, code_verifier: str, nonce: str) -> Identity:
        """Trades the code for tokens, verifies them (signature, issuer,
        audience, expiry, nonce) and returns the identity."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """Who may sign in through a provider and what happens on first sign-in.
    The defaults deny."""

    # A staff IdP (e.g. Entra ID) uses INTERNAL; a consumer IdP uses PUBLIC.
    kind: UserKind
    # Creates a new public user on first sign-in. Never applies to internal
    # users: staff accounts are provisioned by admins.
    allow_signup: bool = False
    # Public type given to users created by allow_signup; must allow self-registration.
    signup_public_type: str = ""
    # Links the identity to an existing account with the same email if the
    # IdP says it is verified. Only for IdPs authoritative for their emails.
    link_verified_email: bool = False


@dataclass(frozen=True, slots=True)
class Registration:
    provider: Provider
    policy: Policy


class UnknownProviderError(LookupError):
    pass


@dataclass(frozen=True, slots=True)
class Registry:
    """The enabled providers, by name."""

    entries: frozendict[str, Registration]

    @classmethod
    def of(cls, *regs: Registration) -> Registry:
        return cls(frozendict({r.provider.name: r for r in regs}))

    def get(self, name: str) -> Registration:
        try:
            return self.entries[name]
        except KeyError:
            raise UnknownProviderError(name) from None

    def names(self) -> list[str]:
        return sorted(self.entries)

    @property
    def empty(self) -> bool:
        return not self.entries


__all__ = [
    "FLOW_TTL",
    "FlowState",
    "Identity",
    "InvalidStateError",
    "Policy",
    "Provider",
    "Registration",
    "Registry",
    "StateCodec",
    "UnknownProviderError",
    "new_flow_state",
]
