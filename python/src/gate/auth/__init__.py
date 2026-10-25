"""Credential primitives: password hashing, signed access tokens (JWT),
JWKS publication and opaque refresh tokens. No business rules."""

from gate.auth.keys import (
    ALG_EDDSA,
    ALG_RS256,
    InvalidKeyError,
    Key,
    KeySet,
    generate_key,
    load_key_set,
    public_key_pem,
)
from gate.auth.passwords import (
    DEFAULT_ARGON2_PARAMS,
    Argon2Params,
    PasswordHasher,
    PasswordPolicyError,
    VerifyResult,
    validate_password,
)
from gate.auth.tokens import (
    ACCESS_TOKEN_TYPE,
    AccessClaims,
    IssuedToken,
    OpaqueToken,
    TokenError,
    TokenIssuer,
    hash_opaque_token,
    new_opaque_token,
)

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "ALG_EDDSA",
    "ALG_RS256",
    "DEFAULT_ARGON2_PARAMS",
    "AccessClaims",
    "Argon2Params",
    "InvalidKeyError",
    "IssuedToken",
    "Key",
    "KeySet",
    "OpaqueToken",
    "PasswordHasher",
    "PasswordPolicyError",
    "TokenError",
    "TokenIssuer",
    "VerifyResult",
    "generate_key",
    "hash_opaque_token",
    "load_key_set",
    "new_opaque_token",
    "public_key_pem",
    "validate_password",
]
