"""Argon2id password hashing in the PHC string format
($argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>), identical to the Go
service, so hashes are interchangeable.

Hashing is CPU- and memory-bound. It runs on a small dedicated thread pool
(argon2's C code releases the GIL), so the event loop keeps serving other
requests and a burst of logins cannot exhaust memory.
"""

import asyncio
import base64
import hmac
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Final

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw

# Password policy, following NIST SP 800-63B: length matters, composition
# rules do not. The maximum bounds hashing cost per request.
MIN_PASSWORD_LENGTH: Final = 12
MAX_PASSWORD_LENGTH: Final = 128

_PHC: Final = re.compile(r"^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$")


class PasswordPolicyError(ValueError):
    pass


def validate_password(pw: str) -> None:
    """Enforces the length policy (in characters, not bytes)."""
    if len(pw) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(pw) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")


@dataclass(frozen=True, slots=True, kw_only=True)
class Argon2Params:
    memory_kib: int
    iterations: int
    parallelism: int
    salt_length: int = 16
    key_length: int = 32


# OWASP's recommended minimum for Argon2id (19 MiB, 2 iterations, 1 lane).
# Raise as hardware allows; existing hashes are upgraded on the next login.
DEFAULT_ARGON2_PARAMS: Final = Argon2Params(memory_kib=19 * 1024, iterations=2, parallelism=1)


@dataclass(frozen=True, slots=True)
class VerifyResult:
    match: bool
    needs_rehash: bool = False


_NO_MATCH: Final = VerifyResult(match=False)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _decode(encoded: str) -> tuple[Argon2Params, bytes, bytes] | None:
    """Parses a PHC string. Parameters are capped so a tampered hash in the
    database cannot make verification consume unbounded resources."""
    m = _PHC.match(encoded)
    if m is None or int(m[1]) != ARGON2_VERSION:
        return None
    mem, it, par = int(m[2]), int(m[3]), int(m[4])
    if mem > 1 << 20 or it > 20 or not 1 <= par <= 16:
        return None
    try:
        salt, key = _unb64(m[5]), _unb64(m[6])
    except ValueError:
        return None
    if len(salt) < 8 or len(key) < 16:
        return None
    return (
        Argon2Params(memory_kib=mem, iterations=it, parallelism=par, salt_length=len(salt), key_length=len(key)),
        salt,
        key,
    )


class PasswordHasher:
    """Hashes and verifies passwords with Argon2id off the event loop."""

    __slots__ = ("_dummy", "_executor", "_params")

    def __init__(self, params: Argon2Params = DEFAULT_ARGON2_PARAMS, *, threads: int = 2) -> None:
        self._params: Final = params
        self._executor: Final = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="argon2")
        # A real hash to verify against when no account matches, so timing
        # does not reveal which accounts exist.
        self._dummy: Final = self._hash_sync("timing-equaliser-password")

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _derive(self, pw: str, salt: bytes, p: Argon2Params) -> bytes:
        return hash_secret_raw(
            secret=pw.encode(),
            salt=salt,
            time_cost=p.iterations,
            memory_cost=p.memory_kib,
            parallelism=p.parallelism,
            hash_len=p.key_length,
            type=Type.ID,
            version=ARGON2_VERSION,
        )

    def _hash_sync(self, pw: str) -> str:
        p = self._params
        salt = secrets.token_bytes(p.salt_length)
        key = self._derive(pw, salt, p)
        return (
            f"$argon2id$v={ARGON2_VERSION}$m={p.memory_kib},t={p.iterations},p={p.parallelism}${_b64(salt)}${_b64(key)}"
        )

    def _verify_sync(self, encoded: str, pw: str) -> VerifyResult:
        decoded = _decode(encoded)
        if decoded is None:
            return _NO_MATCH
        params, salt, want = decoded
        if not hmac.compare_digest(self._derive(pw, salt, params), want):
            return _NO_MATCH
        return VerifyResult(match=True, needs_rehash=params != self._params)

    async def hash(self, pw: str) -> str:
        """Returns the PHC-encoded Argon2id hash of pw."""
        return await asyncio.get_running_loop().run_in_executor(self._executor, self._hash_sync, pw)

    async def verify(self, encoded: str, pw: str) -> VerifyResult:
        """Checks pw against the hash, and whether the hash should be
        recomputed because it uses weaker parameters than configured."""
        return await asyncio.get_running_loop().run_in_executor(self._executor, self._verify_sync, encoded, pw)

    async def verify_dummy(self, pw: str) -> None:
        """Spends the same time as a real verification."""
        await self.verify(self._dummy, pw)
