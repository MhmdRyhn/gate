import base64
import json
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from gate.auth import (
    Argon2Params,
    InvalidKeyError,
    PasswordHasher,
    PasswordPolicyError,
    TokenError,
    TokenIssuer,
    generate_key,
    hash_opaque_token,
    load_key_set,
    new_opaque_token,
    public_key_pem,
    validate_password,
)
from gate.auth.keys import public_jwk, thumbprint
from gate.domain import UserKind


def new_issuer(kind: str = "ed25519") -> tuple[TokenIssuer, str]:
    pem, _ = generate_key(kind, 2048)
    return TokenIssuer(
        keys=load_key_set(pem), issuer="https://auth.test", audience="api", ttl=timedelta(minutes=1)
    ), pem


@pytest.mark.parametrize("kind", ["ed25519", "rsa"])
def test_token_round_trip(kind: str) -> None:
    iss, _ = new_issuer(kind)
    uid, sid = uuid.uuid4(), uuid.uuid4()
    c = iss.parse(iss.issue(uid, sid, UserKind.PUBLIC).token)
    assert (c.subject, c.session_id, c.kind) == (uid, sid, UserKind.PUBLIC)


def test_token_rejected() -> None:
    iss, _ = new_issuer()
    tok = iss.issue(uuid.uuid4(), uuid.uuid4(), UserKind.INTERNAL).token

    other, _ = new_issuer()
    with pytest.raises(TokenError):
        other.parse(tok)  # different key set
    with pytest.raises(TokenError):
        replace(iss, audience="other-api").parse(tok)
    with pytest.raises(TokenError):
        replace(iss, now=lambda: datetime.now(UTC) + timedelta(hours=1)).parse(tok)  # expired

    # A correctly signed JWT without typ=at+jwt (e.g. an ID token) is rejected.
    k = iss.keys.signing
    now = int(time.time())
    id_token = jwt.encode(
        {"iss": iss.issuer, "aud": iss.audience, "sub": str(uuid.uuid4()), "sid": str(uuid.uuid4()),
         "exp": now + 60, "iat": now},
        k.private, algorithm="EdDSA", headers={"kid": k.id},
    )  # fmt: skip
    with pytest.raises(TokenError):
        iss.parse(id_token)

    # alg=none and tampered payloads are rejected.
    payload = tok.split(".")[1]
    none = base64.urlsafe_b64encode(b'{"alg":"none","typ":"at+jwt"}').decode().rstrip("=")
    with pytest.raises(TokenError):
        iss.parse(f"{none}.{payload}.")


def test_key_rotation() -> None:
    old, old_pem = new_issuer()
    tok = old.issue(uuid.uuid4(), uuid.uuid4(), UserKind.INTERNAL).token
    new_pem, _ = generate_key()
    ks = load_key_set(new_pem, public_key_pem(old_pem))
    rotated = replace(old, keys=ks)
    rotated.parse(tok)  # token signed by the previous key is still accepted
    assert len(ks.jwks()["keys"]) == 2


def test_thumbprint_rfc8037() -> None:
    # RFC 8037 appendix A.3 test vector.
    x = base64.urlsafe_b64decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
    pub = ed25519.Ed25519PublicKey.from_public_bytes(x)
    assert thumbprint(public_jwk(pub)) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_load_key_set_rejects_weak_or_bad_keys() -> None:
    with pytest.raises(InvalidKeyError):
        load_key_set("not a key")
    with pytest.raises(InvalidKeyError):
        generate_key("rsa", 1024)
    pem, _ = generate_key()
    load_key_set(base64.b64encode(pem.encode()).decode())  # base64 PEM accepted


@pytest.mark.anyio
async def test_password_hasher() -> None:
    h = PasswordHasher(Argon2Params(memory_kib=1024, iterations=1, parallelism=1), threads=1)
    enc = await h.hash("correct horse battery")
    assert enc.startswith("$argon2id$v=19$m=1024,t=1,p=1$")
    r = await h.verify(enc, "correct horse battery")
    assert r.match and not r.needs_rehash
    assert not (await h.verify(enc, "wrong horse battery")).match

    stronger = PasswordHasher(Argon2Params(memory_kib=2048, iterations=1, parallelism=1), threads=1)
    r = await stronger.verify(enc, "correct horse battery")
    assert r.match and r.needs_rehash, "weaker hash should be flagged for rehash"

    absurd = "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
    assert not (await h.verify(absurd, "x")).match


GO = json.loads((Path(__file__).parent / "fixtures" / "go_compat.json").read_text())


@pytest.mark.anyio
async def test_go_password_hash_verifies() -> None:
    """Existing users keep their passwords when switching implementations."""
    h = PasswordHasher(Argon2Params(memory_kib=1024, iterations=1, parallelism=1), threads=1)
    assert (await h.verify(GO["password_hash"], "correct horse battery")).match
    assert not (await h.verify(GO["password_hash"], "wrong horse battery")).match


def test_go_access_token_and_key_id() -> None:
    """Same key -> same kid, and tokens issued by Go verify here."""
    ks = load_key_set(GO["signing_key"])
    assert ks.signing.id == GO["kid"]
    iss = TokenIssuer(keys=ks, issuer="https://auth.test", audience="api", ttl=timedelta(minutes=1))
    c = iss.parse(GO["access_token"])
    assert (str(c.subject), str(c.session_id), c.kind) == (GO["user_id"], GO["session_id"], UserKind.PUBLIC)


def test_validate_password() -> None:
    with pytest.raises(PasswordPolicyError):
        validate_password("short")
    with pytest.raises(PasswordPolicyError):
        validate_password("a" * 129)
    validate_password("১২৩৪৫৬৭৮৯০১২")  # 12 characters, multi-byte


def test_opaque_token() -> None:
    a, b = new_opaque_token(), new_opaque_token()
    assert a.plain != b.plain
    assert a.hash == hash_opaque_token(a.plain)
