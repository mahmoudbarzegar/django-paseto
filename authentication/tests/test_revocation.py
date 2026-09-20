from datetime import datetime, timedelta, timezone

from authentication.revocation import is_token_revoked, revoke_token


class TestRevocation:
    def test_unrevoked_jti_is_not_revoked(self):
        assert is_token_revoked("some-jti-nobody-revoked") is False

    def test_revoked_jti_is_revoked(self):
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        revoke_token(jti="abc123", expires_at=expires_at)

        assert is_token_revoked("abc123") is True

    def test_revoking_one_jti_does_not_affect_another(self):
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        revoke_token(jti="jti-one", expires_at=expires_at)

        assert is_token_revoked("jti-two") is False

    def test_already_expired_token_can_still_be_recorded_without_error(self):
        expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        revoke_token(jti="already-expired", expires_at=expires_at)  # must not raise

        assert is_token_revoked("already-expired") is True
