"""The application's typed, immutable configuration.

Every setting is identified by a single flat key (e.g. "DATABASE_URL"),
whatever the source, and the keys match the Go service, so the same
environment or secret store configures either implementation. Keys that
only the Go server uses (e.g. HTTP_READ_TIMEOUT) are accepted and ignored.
"""

import dataclasses
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any, Final, get_type_hints

from gate.config.duration import format_duration, parse_duration
from gate.config.secret import Secret
from gate.config.sources import Source

type Network = IPv4Network | IPv6Network


def setting(key: str, default: str | None = None, *, required: bool = False) -> Any:
    """Declares a config field read from ``key``. ``default`` is a raw
    string, parsed like a value from any source."""
    return field(metadata={"key": key, "default": default, "required": required})


class ConfigError(Exception):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class AppConfig:
    # "production" or "development". Development relaxes nothing
    # security-related; it only switches the log format.
    env: str = setting("APP_ENV", "production")


@dataclass(frozen=True, slots=True, kw_only=True)
class HTTPConfig:
    addr: str = setting("HTTP_ADDR", ":8080")
    # Keep-alive timeout for idle client connections.
    idle_timeout: timedelta = setting("HTTP_IDLE_TIMEOUT", "60s")
    # How long a stopping worker drains in-flight requests.
    shutdown_timeout: timedelta = setting("HTTP_SHUTDOWN_TIMEOUT", "20s")
    max_body_bytes: int = setting("HTTP_MAX_BODY_BYTES", "1048576")
    # Proxy IPs/CIDRs whose X-Forwarded-For is trusted to determine the
    # client IP. Empty means trust none.
    trusted_proxies: tuple[str, ...] = setting("HTTP_TRUSTED_PROXIES")
    # Enables CORS for browser clients of the listed origins. Empty disables CORS.
    cors_allowed_origins: tuple[str, ...] = setting("HTTP_CORS_ALLOWED_ORIGINS")
    # Per-worker cap on concurrent connections+tasks; beyond it the server
    # answers 503 instead of queueing without bound. 0 disables the cap.
    max_concurrency: int = setting("HTTP_MAX_CONCURRENCY", "0")
    # Worker processes; 0 means one per CPU. Set it explicitly in containers
    # with a CPU limit, which the CPU count does not reflect.
    workers: int = setting("HTTP_WORKERS", "0")
    # Listen backlog (pending TCP connections) per worker.
    backlog: int = setting("HTTP_BACKLOG", "2048")

    @property
    def host(self) -> str:
        host, _, _ = self.addr.rpartition(":")
        return host.strip("[]") or "0.0.0.0"  # noqa: S104 - binding all interfaces is the intent of ":port"

    @property
    def port(self) -> int:
        return int(self.addr.rpartition(":")[2])

    @property
    def trusted_networks(self) -> tuple[Network, ...]:
        return tuple(ip_network(p, strict=False) for p in self.trusted_proxies)


@dataclass(frozen=True, slots=True, kw_only=True)
class DatabaseConfig:
    url: Secret = setting("DATABASE_URL", required=True)
    # Pool size PER WORKER PROCESS: total connections = workers x this.
    # Connections open lazily and then stay open (no churn under load).
    max_open_conns: int = setting("DB_MAX_OPEN_CONNS", "10")
    # Connections each worker opens at startup, so the first requests do
    # not pay for connecting.
    max_idle_conns: int = setting("DB_MAX_IDLE_CONNS", "2")
    # Connections older than this are replaced (failovers, load balancers).
    conn_max_lifetime: timedelta = setting("DB_CONN_MAX_LIFETIME", "30m")
    # How long a request waits for a free pooled connection.
    pool_timeout: timedelta = setting("DB_POOL_TIMEOUT", "10s")
    # Bounds how long startup keeps retrying an unreachable database.
    connect_timeout: timedelta = setting("DB_CONNECT_TIMEOUT", "60s")
    # Logs queries slower than this at warning level.
    slow_query_threshold: timedelta = setting("DB_SLOW_QUERY_THRESHOLD", "200ms")
    # Server-side statement timeout for every query.
    statement_timeout: timedelta = setting("DB_STATEMENT_TIMEOUT", "30s")
    # Prepared statement cache per connection. Set 0 behind PgBouncer in
    # transaction pooling mode.
    statement_cache_size: int = setting("DB_STATEMENT_CACHE_SIZE", "100")


@dataclass(frozen=True, slots=True, kw_only=True)
class LogConfig:
    level: str = setting("LOG_LEVEL", "info")  # debug|info|warn|error
    format: str = setting("LOG_FORMAT", "json")  # json|console


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthConfig:
    # Lifetime of a JWT access token.
    access_token_ttl: timedelta = setting("ACCESS_TOKEN_TTL", "15m")
    # Idle timeout of a session: a refresh token unused this long expires.
    refresh_token_ttl: timedelta = setting("REFRESH_TOKEN_TTL", "168h")
    # Absolute session lifetime.
    session_max_lifetime: timedelta = setting("SESSION_MAX_LIFETIME", "720h")
    public_registration_enabled: bool = setting("PUBLIC_REGISTRATION_ENABLED", "true")
    # Per-client-IP token bucket for login, register and refresh (per worker).
    rate_limit_per_minute: int = setting("AUTH_RATE_LIMIT_PER_MINUTE", "10")
    rate_limit_burst: int = setting("AUTH_RATE_LIMIT_BURST", "10")
    # Threads per worker that run Argon2id. Each hash holds ~19 MiB while
    # it runs, so this bounds memory under a burst of logins.
    password_hash_threads: int = setting("PASSWORD_HASH_THREADS", "2")
    # Signs the short-lived SSO state cookie. Required (>= 32 bytes) only
    # when at least one SSO provider is registered.
    sso_state_key: Secret = setting("SSO_STATE_KEY")


@dataclass(frozen=True, slots=True, kw_only=True)
class JWTConfig:
    # "iss": the public base URL of this service.
    issuer: str = setting("JWT_ISSUER", required=True)
    # "aud": identifies the APIs that accept the token.
    audience: str = setting("JWT_AUDIENCE", "rbac-service")
    # PKCS#8 PEM (or base64 of it) Ed25519 or RSA private key.
    signing_key: Secret = setting("JWT_SIGNING_KEY", required=True)
    # Extra PEM public keys still accepted for verification (key rotation).
    verification_keys: Secret = setting("JWT_VERIFICATION_KEYS")


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    app: AppConfig
    http: HTTPConfig
    database: DatabaseConfig
    log: LogConfig
    auth: AuthConfig
    jwt: JWTConfig

    def validate(self) -> None:
        """Checks cross-field rules; raises ConfigError listing every problem."""
        errs: list[str] = []
        if self.app.env not in ("production", "development"):
            errs.append("APP_ENV must be production or development")
        if self.log.level not in ("debug", "info", "warn", "error"):
            errs.append("LOG_LEVEL must be debug, info, warn or error")
        if self.log.format not in ("json", "console"):
            errs.append("LOG_FORMAT must be json or console")
        a = self.auth
        for name, d in (
            ("ACCESS_TOKEN_TTL", a.access_token_ttl),
            ("REFRESH_TOKEN_TTL", a.refresh_token_ttl),
            ("SESSION_MAX_LIFETIME", a.session_max_lifetime),
        ):
            if d <= timedelta(0):
                errs.append(f"{name} must be positive")
        if a.access_token_ttl > timedelta(hours=1):
            errs.append("ACCESS_TOKEN_TTL must be at most 1h: access tokens cannot be revoked by other services")
        if a.refresh_token_ttl > a.session_max_lifetime:
            errs.append("REFRESH_TOKEN_TTL must not exceed SESSION_MAX_LIFETIME")
        if a.rate_limit_per_minute <= 0 or a.rate_limit_burst <= 0:
            errs.append("AUTH_RATE_LIMIT_PER_MINUTE and AUTH_RATE_LIMIT_BURST must be positive")
        if a.password_hash_threads <= 0:
            errs.append("PASSWORD_HASH_THREADS must be positive")
        db = self.database
        if db.max_open_conns <= 0 or db.max_idle_conns < 0 or db.max_idle_conns > db.max_open_conns:
            errs.append("DB_MAX_OPEN_CONNS must be positive and >= DB_MAX_IDLE_CONNS")
        if self.http.workers < 0:
            errs.append("HTTP_WORKERS must not be negative")
        if self.http.max_body_bytes <= 0:
            errs.append("HTTP_MAX_BODY_BYTES must be positive")
        try:
            _ = self.http.port
        except ValueError:
            errs.append("HTTP_ADDR must be [host]:port")
        try:
            _ = self.http.trusted_networks
        except ValueError as e:
            errs.append(f"HTTP_TRUSTED_PROXIES: {e}")
        if errs:
            raise ConfigError("\n".join(errs))


_SECTIONS: Final = get_type_hints(Config)


async def load(sources: Iterable[Source]) -> Config:
    """Reads every source (later ones override earlier ones), decodes the
    merged values into Config and validates the result."""
    merged: dict[str, str] = {}
    for s in sources:
        try:
            merged |= await s.load()
        except Exception as e:
            raise ConfigError(f"config source {s.name}: {e}") from e
    return decode(merged)


def decode(values: Mapping[str, str]) -> Config:
    errs: list[str] = []
    sections = {name: _decode_fields(cls, values, errs) for name, cls in _SECTIONS.items()}
    if errs:
        raise ConfigError("\n".join(errs))
    cfg = Config(**{name: cls(**sections[name]) for name, cls in _SECTIONS.items()})
    cfg.validate()
    return cfg


def _decode_fields(cls: type, values: Mapping[str, str], errs: list[str]) -> dict[str, object]:
    hints = get_type_hints(cls)
    kwargs: dict[str, object] = {}
    for f in dataclasses.fields(cls):
        key, default, required = f.metadata["key"], f.metadata["default"], f.metadata["required"]
        raw = values.get(key)
        if raw is None or (raw == "" and default is not None):
            raw = default
        if raw is None or raw == "":
            if required:
                errs.append(f"{key} is required")
                continue
            raw = ""
        try:
            kwargs[f.name] = _convert(hints[f.name], raw)
        except ValueError as e:
            errs.append(f"{key}: {e}")
    return kwargs


def _convert(tp: object, raw: str) -> object:
    if tp is str:
        return raw
    if tp is int:
        return int(raw)
    if tp is bool:
        low = raw.strip().lower()
        if low in ("1", "t", "true", "yes", "on"):
            return True
        if low in ("0", "f", "false", "no", "off", ""):
            return False
        raise ValueError(f"invalid boolean {raw!r}")
    if tp is timedelta:
        return parse_duration(raw)
    if tp is Secret:
        return Secret(raw)
    if tp == tuple[str, ...]:
        return tuple(p.strip() for p in raw.split(",") if p.strip())
    raise TypeError(f"unsupported config type {tp!r}")


def redacted(cfg: Config) -> dict[str, dict[str, object]]:
    """The configuration as JSON-ready data, with secrets masked."""

    def plain(v: object) -> object:
        match v:
            case Secret():
                return v.masked()
            case timedelta():
                return format_duration(v)
            case tuple():
                return list(v)
            case _:
                return v

    return {
        name: {f.name: plain(getattr(section, f.name)) for f in dataclasses.fields(section)}
        for name, section in ((f.name, getattr(cfg, f.name)) for f in dataclasses.fields(cfg))
    }


def to_json(cfg: Config) -> str:
    return json.dumps(redacted(cfg), indent=2)
