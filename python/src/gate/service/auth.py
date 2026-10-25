from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from gate import rbac, requestctx
from gate.auth import (
    PasswordHasher,
    PasswordPolicyError,
    TokenError,
    TokenIssuer,
    hash_opaque_token,
    new_opaque_token,
    validate_password,
)
from gate.config import AuthConfig
from gate.domain import (
    ConflictError,
    ForbiddenError,
    InvalidCredentialsError,
    InvalidTokenError,
    NotFoundError,
    Principal,
    RefreshToken,
    Session,
    User,
    UserDisabledError,
    UserKind,
    UserStatus,
    ValidationError,
)
from gate.logs import Logger
from gate.repository import CreateUserOptions, SessionRepository, UserRepository
from gate.service.audit import AuditAction, Auditor
from gate.service.guard import clean_full_name, contact_input, new_id, normalize_email, normalize_phone, truncate


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True, kw_only=True)
class TokenPair:
    """The result of a successful sign-in or refresh."""

    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    refresh_token_expires_at: datetime
    session_id: UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class RegisterInput:
    """A public self-registration."""

    password: str
    email: str = ""
    phone: str = ""
    full_name: str = ""
    # Defaults to rbac.DEFAULT_PUBLIC_TYPE and must allow self-registration.
    type: str = ""


class AuthService:
    """Password sign-in, registration, sessions and access token
    verification."""

    __slots__ = ("_audit", "_cfg", "_hasher", "_log", "_now", "_sessions", "_tokens", "_users")

    def __init__(
        self,
        *,
        users: UserRepository,
        sessions: SessionRepository,
        hasher: PasswordHasher,
        tokens: TokenIssuer,
        audit: Auditor,
        cfg: AuthConfig,
        log: Logger,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self._users: Final = users
        self._sessions: Final = sessions
        self._hasher: Final = hasher
        self._tokens: Final = tokens
        self._audit: Final = audit
        self._cfg: Final = cfg
        self._log: Final = log
        self._now: Final = now

    @property
    def sessions(self) -> SessionRepository:
        return self._sessions

    async def authenticate(self, raw_token: str) -> Principal:
        """Verifies an access token and loads the principal. Fails if the
        token is invalid, its session was revoked or expired, or the user was
        disabled, so logout and disabling take effect immediately."""
        try:
            claims = self._tokens.parse(raw_token)
        except TokenError:
            raise InvalidTokenError from None
        try:
            p = await self._users.get_principal(claims.subject, claims.session_id)
        except NotFoundError:
            raise InvalidTokenError from None
        if p.kind != claims.kind:  # kind is immutable; a mismatch means a forged or corrupted token
            raise InvalidTokenError
        return p

    async def login(self, identifier: str, password: str) -> TokenPair:
        """Signs in with an email address or phone number and a password."""
        try:
            u = await self._find_by_identifier(identifier)
        except NotFoundError:
            await self._hasher.verify_dummy(password)
            await self._audit.record(AuditAction.LOGIN_FAILED, details={"reason": "unknown_identifier"})
            raise InvalidCredentialsError from None
        uid = str(u.id)
        if not u.has_password:  # SSO-only account
            await self._hasher.verify_dummy(password)
            await self._audit.record(
                AuditAction.LOGIN_FAILED, target_type="user", target_id=uid, details={"reason": "no_password"}
            )
            raise InvalidCredentialsError
        result = await self._hasher.verify(u.password_hash, password)
        if not result.match:
            await self._audit.record(
                AuditAction.LOGIN_FAILED, target_type="user", target_id=uid, details={"reason": "bad_password"}
            )
            raise InvalidCredentialsError
        if u.status != UserStatus.ACTIVE:
            await self._audit.record(
                AuditAction.LOGIN_FAILED, target_type="user", target_id=uid, details={"reason": "disabled"}
            )
            raise UserDisabledError
        if result.needs_rehash:
            await self._upgrade_hash(u.id, password)
        pair = await self.start_session(u, "password")
        await self._audit.record(
            AuditAction.LOGIN_SUCCEEDED, actor=u.id, target_type="session", target_id=str(pair.session_id)
        )
        return pair

    async def register(self, data: RegisterInput) -> TokenPair:
        """Creates a public user and signs them in."""
        if not self._cfg.public_registration_enabled:
            raise ForbiddenError("registration is disabled")
        type_name = data.type or rbac.DEFAULT_PUBLIC_TYPE
        t = rbac.lookup_public_type(type_name)
        if t is None:
            raise ValidationError(f"unknown type {type_name!r}")
        if not t.self_registration:
            raise ForbiddenError(f"type {type_name!r} cannot self-register")
        u = await self.new_user(data.email, data.phone, data.full_name, data.password, UserKind.PUBLIC)
        u = await create_user(self._users, u, CreateUserOptions(public_types=(t.name,)))
        await self._audit.record(
            AuditAction.REGISTERED, actor=u.id, target_type="user", target_id=str(u.id), details={"type": t.name}
        )
        return await self.start_session(u, "password")

    async def refresh(self, refresh_token: str) -> TokenPair:
        """Exchanges a refresh token for a new pair (rotation). Presenting an
        already-used token signals theft: the whole session is revoked,
        logging out both attacker and victim (RFC 6819 §5.2.2.3)."""
        try:
            rt, sess = await self._sessions.get_by_refresh_token(hash_opaque_token(refresh_token))
        except NotFoundError:
            raise InvalidTokenError from None
        now = self._now()
        if rt.used_at is not None:
            await self._sessions.revoke(sess.id)
            self._log.warning("refresh token reuse detected; session revoked", session_id=str(sess.id))
            await self._audit.record(
                AuditAction.REFRESH_REUSE, actor=sess.user_id, target_type="session", target_id=str(sess.id)
            )
            raise InvalidTokenError
        if not sess.active(now) or now > rt.expires_at:
            raise InvalidTokenError
        u = await self._users.get_by_id(sess.user_id)
        if u.status != UserStatus.ACTIVE:
            raise UserDisabledError

        opaque = new_opaque_token()
        nxt = RefreshToken(
            id=new_id(),
            session_id=sess.id,
            token_hash=opaque.hash,
            expires_at=self._refresh_expiry(now, sess),
            created_at=now,
        )
        await self._sessions.rotate(rt.id, nxt)
        access = self._tokens.issue(u.id, sess.id, u.kind)
        return TokenPair(
            access_token=access.token,
            access_token_expires_at=access.expires_at,
            refresh_token=opaque.plain,
            refresh_token_expires_at=nxt.expires_at,
            session_id=sess.id,
        )

    async def logout(self, refresh_token: str) -> None:
        """Revokes the session of a refresh token. Unknown tokens are ignored
        so the endpoint does not reveal token validity."""
        try:
            _, sess = await self._sessions.get_by_refresh_token(hash_opaque_token(refresh_token))
        except NotFoundError:
            return
        await self._sessions.revoke(sess.id)
        await self._audit.record(AuditAction.LOGOUT, actor=sess.user_id, target_type="session", target_id=str(sess.id))

    async def logout_all(self, p: Principal) -> None:
        """Revokes every session of the principal, including the current one."""
        await self._sessions.revoke_all_for_user(p.user_id)
        await self._audit.record(AuditAction.LOGOUT_ALL, actor=p.user_id, target_type="user", target_id=str(p.user_id))

    async def change_password(self, p: Principal, current: str, new: str) -> None:
        """Verifies the current password, stores the new one and signs out
        every other session."""
        u = await self._users.get_by_id(p.user_id)
        if not u.has_password:
            raise ValidationError("this account signs in with SSO and has no password")
        if not (await self._hasher.verify(u.password_hash, current)).match:
            raise InvalidCredentialsError
        try:
            validate_password(new)
        except PasswordPolicyError as e:
            raise ValidationError(str(e)) from None
        await self._users.update_password(u.id, await self._hasher.hash(new))
        await self._sessions.revoke_all_for_user(u.id, keep=p.session_id)
        await self._audit.record(AuditAction.PASSWORD_CHANGED, actor=u.id, target_type="user", target_id=str(u.id))

    async def purge_sessions(self, before: datetime) -> int:
        """Deletes sessions and refresh tokens that ended before ``before``."""
        return await self._sessions.purge(before)

    async def start_session(self, u: User, method: str) -> TokenPair:
        """Creates a session for u and returns its first token pair. method
        is "password" or "sso:<provider>"."""
        now = self._now()
        meta = requestctx.current()
        sess = Session(
            id=new_id(),
            user_id=u.id,
            auth_method=method,
            ip=meta.ip,
            user_agent=truncate(meta.user_agent, 512),
            created_at=now,
            last_refreshed_at=now,
            expires_at=now + self._cfg.session_max_lifetime,
        )
        opaque = new_opaque_token()
        rt = RefreshToken(
            id=new_id(),
            session_id=sess.id,
            token_hash=opaque.hash,
            expires_at=self._refresh_expiry(now, sess),
            created_at=now,
        )
        await self._sessions.create(sess, rt)
        access = self._tokens.issue(u.id, sess.id, u.kind)
        try:
            await self._users.touch_last_login(u.id)
        except Exception as e:
            self._log.warning("update last login", user_id=str(u.id), error=repr(e))
        return TokenPair(
            access_token=access.token,
            access_token_expires_at=access.expires_at,
            refresh_token=opaque.plain,
            refresh_token_expires_at=rt.expires_at,
            session_id=sess.id,
        )

    def _refresh_expiry(self, now: datetime, sess: Session) -> datetime:
        """The idle timeout, capped by the session's absolute lifetime."""
        return min(now + self._cfg.refresh_token_ttl, sess.expires_at)

    async def new_user(self, email: str, phone: str, full_name: str, password: str, kind: UserKind) -> User:
        """Validates the fields shared by every way of creating a user."""
        e, p = contact_input(email, phone)
        name = clean_full_name(full_name)
        try:
            validate_password(password)
        except PasswordPolicyError as err:
            raise ValidationError(str(err)) from None
        now = self._now()
        return User(
            id=new_id(),
            email=e,
            phone=p,
            full_name=name,
            password_hash=await self._hasher.hash(password),
            kind=kind,
            status=UserStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )

    async def _find_by_identifier(self, identifier: str) -> User:
        """Identifiers containing "@" are emails, anything else phones."""
        try:
            if "@" in identifier:
                return await self._users.get_by_email(normalize_email(identifier))
            return await self._users.get_by_phone(normalize_phone(identifier))
        except ValidationError:
            raise NotFoundError from None

    async def _upgrade_hash(self, id: UUID, password: str) -> None:
        try:
            await self._users.update_password(id, await self._hasher.hash(password))
        except Exception as e:
            self._log.warning("password rehash failed", user_id=str(id), error=repr(e))


async def create_user(users: UserRepository, u: User, opts: CreateUserOptions) -> User:
    try:
        return await users.create(u, opts)
    except ConflictError:
        raise ConflictError("email or phone already registered") from None
