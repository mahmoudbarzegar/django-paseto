from datetime import timedelta

import pytest
from freezegun import freeze_time

from authentication.paseto_utils import (
    TokenExpiredError,
    TokenInvalidError,
    decode_token,
    encode_token,
)


class TestEncodeDecodeToken:
    def test_encodes_a_paseto_v4_local_token_string(self):
        token = encode_token(subject="1", token_type="access", lifetime=timedelta(minutes=5))

        assert isinstance(token, str)
        assert token.startswith("v4.local.")

    def test_decodes_the_subject_and_type_back_out(self):
        token = encode_token(subject="42", token_type="access", lifetime=timedelta(minutes=5))

        decoded = decode_token(token)

        assert decoded.subject == "42"
        assert decoded.token_type == "access"

    def test_carries_extra_claims_through(self):
        token = encode_token(
            subject="1",
            token_type="password_reset",
            lifetime=timedelta(minutes=5),
            extra_claims={"pwd_fp": "abc123"},
        )

        decoded = decode_token(token)

        assert decoded.claims["pwd_fp"] == "abc123"

    def test_rejects_an_expired_token(self):
        with freeze_time("2026-01-01 00:00:00"):
            token = encode_token(subject="1", token_type="access", lifetime=timedelta(minutes=5))

        with freeze_time("2026-01-01 00:06:00"):
            with pytest.raises(TokenExpiredError):
                decode_token(token)

    def test_rejects_a_tampered_token(self):
        token = encode_token(subject="1", token_type="access", lifetime=timedelta(minutes=5))
        tampered = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")

        with pytest.raises(TokenInvalidError):
            decode_token(tampered)

    def test_rejects_garbage_input(self):
        with pytest.raises(TokenInvalidError):
            decode_token("not-a-real-token")

    def test_rejects_empty_token(self):
        with pytest.raises(TokenInvalidError):
            decode_token("")

    def test_enforces_expected_token_type(self):
        token = encode_token(subject="1", token_type="refresh", lifetime=timedelta(days=1))

        with pytest.raises(TokenInvalidError):
            decode_token(token, expected_type="access")

    def test_accepts_matching_expected_token_type(self):
        token = encode_token(subject="1", token_type="access", lifetime=timedelta(minutes=5))

        decoded = decode_token(token, expected_type="access")

        assert decoded.token_type == "access"

    def test_each_token_gets_a_unique_jti(self):
        token_a = encode_token(subject="1", token_type="access", lifetime=timedelta(minutes=5))
        token_b = encode_token(subject="1", token_type="access", lifetime=timedelta(minutes=5))

        assert decode_token(token_a).claims["jti"] != decode_token(token_b).claims["jti"]
