from datetime import UTC, datetime, timedelta

import pytest

from gate.auth.sso import FLOW_TTL, FlowState, InvalidStateError, StateCodec, new_flow_state


def test_state_codec() -> None:
    c = StateCodec(b"k" * 32)
    now = datetime.now(UTC)
    f = new_flow_state("google", now)
    sealed = c.seal(f)

    assert c.open(sealed, now) == f
    with pytest.raises(InvalidStateError):
        c.open(sealed, now + FLOW_TTL + timedelta(seconds=1))  # expired
    with pytest.raises(InvalidStateError):
        c.open(sealed[:-2] + "xx", now)  # tampered
    with pytest.raises(InvalidStateError):
        StateCodec(b"o" * 32).open(sealed, now)  # another key
    with pytest.raises(ValueError, match="32 bytes"):
        StateCodec(b"short")


def test_pkce_challenge() -> None:
    # RFC 7636 appendix B.
    f = FlowState(
        provider="x", state="s", nonce="n", code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", expires_at=0
    )
    assert f.code_challenge() == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    g = new_flow_state("x", datetime.now(UTC))
    assert 43 <= len(g.code_verifier) <= 128
