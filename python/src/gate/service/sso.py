import contextlib
from datetime import UTC, datetime
from typing import Final

from gate import rbac
from gate.auth.sso import Identity, Policy, Registry, UnknownProviderError
from gate.domain import (
    ForbiddenError,
    InvalidCredentialsError,
    NotFoundError,
    User,
    UserDisabledError,
    UserIdentity,
    UserKind,
    UserStatus,
    ValidationError,
)
from gate.repository import CreateUserOptions, IdentityRepository, UserRepository
from gate.service.audit import AuditAction, Auditor
from gate.service.auth import AuthService, TokenPair, create_user
from gate.service.guard import clean_full_name, new_id, normalize_email


class SSOService:
    """Turns a verified external identity into a local session, following
    the provider's Policy."""

    __slots__ = ("_audit", "_auth", "_identities", "_registry", "_users")

    def __init__(
        self,
        *,
        registry: Registry,
        users: UserRepository,
        identities: IdentityRepository,
        auth: AuthService,
        audit: Auditor,
    ) -> None:
        self._registry: Final = registry
        self._users: Final = users
        self._identities: Final = identities
        self._auth: Final = auth
        self._audit: Final = audit

    async def sign_in(self, provider_name: str, identity: Identity) -> TokenPair:
        """Resolves the identity to a user, in this order:
          1. an existing link (provider, subject);
          2. if the policy allows, an existing account with the same verified
             email, which is then linked;
          3. if the policy allows, a new public user.
        Anything else is rejected: deny by default."""
        try:
            policy = self._registry.get(provider_name).policy
        except UnknownProviderError:
            raise NotFoundError from None
        if not identity.subject or identity.provider != provider_name:
            raise InvalidCredentialsError

        try:
            u = await self._identities.find_user(provider_name, identity.subject)
        except NotFoundError:
            u = await self._link_or_create(policy, identity)

        if u.kind != policy.kind:
            raise ForbiddenError(f"this provider is not enabled for {u.kind} users")
        if u.status != UserStatus.ACTIVE:
            raise UserDisabledError
        pair = await self._auth.start_session(u, f"sso:{provider_name}")
        await self._audit.record(
            AuditAction.SSO_LOGIN,
            actor=u.id,
            target_type="session",
            target_id=str(pair.session_id),
            details={"provider": provider_name},
        )
        return pair

    async def _link_or_create(self, policy: Policy, identity: Identity) -> User:
        email = ""
        if identity.email and identity.email_verified:
            with contextlib.suppress(ValidationError):
                email = normalize_email(identity.email)
        now = datetime.now(UTC)

        # Link to an existing account only when the IdP vouches for the email.
        if policy.link_verified_email and email:
            try:
                u = await self._users.get_by_email(email)
            except NotFoundError:
                pass
            else:
                if u.kind != policy.kind:
                    raise InvalidCredentialsError
                await self._identities.link(
                    UserIdentity(
                        id=new_id(),
                        user_id=u.id,
                        provider=identity.provider,
                        subject=identity.subject,
                        email=email,
                        created_at=now,
                    )
                )
                await self._audit.record(
                    AuditAction.SSO_LINKED,
                    actor=u.id,
                    target_type="user",
                    target_id=str(u.id),
                    details={"provider": identity.provider},
                )
                return u

        # Staff accounts are never created implicitly.
        if not policy.allow_signup or policy.kind != UserKind.PUBLIC:
            raise ForbiddenError("no account is linked to this identity")
        t = rbac.lookup_public_type(policy.signup_public_type)
        if t is None or not t.self_registration:
            raise RuntimeError(
                f"SSO policy for {identity.provider}: public type {policy.signup_public_type!r} cannot self-register"
            )
        if not email:
            # The schema requires an email or phone; unverified emails are
            # never stored as identifiers because they could block the owner.
            raise ValidationError("the identity provider did not supply a verified email")
        try:
            name = clean_full_name(identity.name)
        except ValidationError:
            name = ""
        user_id = new_id()
        u = User(
            id=user_id,
            email=email,
            phone=None,
            email_verified_at=now,
            full_name=name,
            password_hash="",
            kind=UserKind.PUBLIC,
            status=UserStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )
        link = UserIdentity(
            id=new_id(),
            user_id=user_id,
            provider=identity.provider,
            subject=identity.subject,
            email=email,
            created_at=now,
        )
        u = await create_user(self._users, u, CreateUserOptions(public_types=(t.name,), identity=link))
        await self._audit.record(
            AuditAction.REGISTERED,
            actor=u.id,
            target_type="user",
            target_id=str(u.id),
            details={"type": t.name, "provider": identity.provider},
        )
        return u
