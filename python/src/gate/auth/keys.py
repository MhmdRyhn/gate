"""JWT signing keys, JWKS publication and key generation.

EdDSA (Ed25519) is the default: small keys, fast, no parameter pitfalls.
RS256 is offered for consumers that lack EdDSA support. Key IDs are RFC
7638 JWK thumbprints, computed exactly as the Go service does, so either
implementation verifies the other's tokens.
"""

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

ALG_EDDSA: Final = "EdDSA"
ALG_RS256: Final = "RS256"
_MIN_RSA_BITS: Final = 2048

type PrivateKey = ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey
type PublicKey = ed25519.Ed25519PublicKey | rsa.RSAPublicKey
type JWK = frozendict[str, str]

_PEM_BLOCK: Final = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.+?-----END \1-----", re.DOTALL)


class InvalidKeyError(ValueError):
    """A key could not be parsed or is not acceptable."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Key:
    id: str  # RFC 7638 JWK thumbprint
    algorithm: str
    public: PublicKey
    private: PrivateKey | None = None  # None for verification-only keys


@dataclass(frozen=True, slots=True)
class KeySet:
    """The current signing key and every key accepted for verification
    (the signing key plus older keys kept during rotation)."""

    signing: Key
    verify: frozendict[str, Key]

    def lookup(self, kid: str) -> Key | None:
        return self.verify.get(kid)

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """The public half of every verification key, for /.well-known/jwks.json."""
        return {
            "keys": [
                dict(public_jwk(k.public)) | {"kid": k.id, "use": "sig", "alg": k.algorithm}
                for k in self.verify.values()
            ]
        }


def load_key_set(signing_key: str, verification_keys: str = "") -> KeySet:
    """Parses the PKCS#8 private signing key and an optional bundle of PEM
    public keys still accepted for verification. Both may be PEM text or
    base64-encoded PEM (easier to pass in environment variables)."""
    try:
        signing = _new_key(_load_private(_pem_blocks(signing_key, "PRIVATE KEY")[0]))
    except (InvalidKeyError, ValueError, TypeError) as e:
        raise InvalidKeyError(f"JWT signing key: {e}") from e
    keys = {signing.id: signing}
    if verification_keys.strip():
        for block in _pem_blocks(verification_keys, "PUBLIC KEY"):
            try:
                pub = serialization.load_pem_public_key(block)
                if not isinstance(pub, (ed25519.Ed25519PublicKey, rsa.RSAPublicKey)):
                    raise InvalidKeyError(f"unsupported key type {type(pub).__name__} (want Ed25519 or RSA)")
                k = _new_key_public(pub)
            except (InvalidKeyError, ValueError) as e:
                raise InvalidKeyError(f"JWT verification key: {e}") from e
            keys[k.id] = k
    return KeySet(signing=signing, verify=frozendict(keys))


def generate_key(kind: str = "ed25519", rsa_bits: int = 3072) -> tuple[str, str]:
    """Creates a PKCS#8 PEM private key; returns (pem, kid)."""
    priv: PrivateKey
    match kind:
        case "ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
        case "rsa":
            if rsa_bits < _MIN_RSA_BITS:
                raise InvalidKeyError(f"RSA keys must be at least {_MIN_RSA_BITS} bits")
            priv = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        case _:
            raise InvalidKeyError(f"unknown key type {kind!r} (want ed25519 or rsa)")
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return pem.decode(), _new_key(priv).id


def public_key_pem(private_key: str) -> str:
    """The PKIX PEM public key of a PKCS#8 private key, for publishing an old
    key in JWT_VERIFICATION_KEYS during rotation."""
    priv = _load_private(_pem_blocks(private_key, "PRIVATE KEY")[0])
    return (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def public_jwk(pub: PublicKey) -> JWK:
    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return frozendict({"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)})
    nums = pub.public_numbers()
    return frozendict({"kty": "RSA", "n": b64url(_int_bytes(nums.n)), "e": b64url(_int_bytes(nums.e))})


def thumbprint(jwk: JWK) -> str:
    """RFC 7638: SHA-256 over the required members in lexicographic order,
    without whitespace."""
    required = ("crv", "kty", "x") if jwk["kty"] == "OKP" else ("e", "kty", "n")
    canonical = json.dumps({k: jwk[k] for k in required}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode()).digest())


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _int_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")


def _load_private(block: bytes) -> PrivateKey:
    try:
        priv = serialization.load_pem_private_key(block, password=None)
    except ValueError as e:
        raise InvalidKeyError(f"expected PKCS#8: {e}") from e
    if not isinstance(priv, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
        raise InvalidKeyError(f"unsupported key type {type(priv).__name__} (want Ed25519 or RSA)")
    return priv


def _new_key(priv: PrivateKey) -> Key:
    return _new_key_public(priv.public_key(), priv)


def _new_key_public(pub: PublicKey, priv: PrivateKey | None = None) -> Key:
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < _MIN_RSA_BITS:
            raise InvalidKeyError(f"RSA key must be at least {_MIN_RSA_BITS} bits")
        alg = ALG_RS256
    else:
        alg = ALG_EDDSA
    return Key(id=thumbprint(public_jwk(pub)), algorithm=alg, public=pub, private=priv)


def _pem_blocks(text: str, want_type: str) -> list[bytes]:
    """Accepts PEM directly or base64-encoded PEM; every block must be of want_type."""
    s = text.strip()
    if not s:
        raise InvalidKeyError("empty")
    if "-----BEGIN" not in s:
        try:
            s = base64.b64decode(s, validate=True).decode()
        except ValueError as e:
            raise InvalidKeyError("expected PEM or base64-encoded PEM") from e
    blocks = []
    for m in _PEM_BLOCK.finditer(s):
        if m[1] != want_type:
            raise InvalidKeyError(f"unexpected PEM block {m[1]!r} (want {want_type!r})")
        blocks.append(m[0].encode())
    if not blocks:
        raise InvalidKeyError(f"no {want_type!r} PEM block found")
    return blocks
