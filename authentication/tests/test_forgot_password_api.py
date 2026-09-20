from datetime import timedelta

import pytest
from django.core import mail
from django.urls import reverse
from freezegun import freeze_time
from rest_framework import status

from ..paseto_utils import decode_token
from ..services import request_password_reset

pytestmark = pytest.mark.django_db


@pytest.fixture
def forgot_password_url():
    return reverse("authentication:forgot-password")


@pytest.fixture
def reset_password_url():
    return reverse("authentication:reset-password")


def _extract_reset_token(email_body: str) -> str:
    return email_body.split("token=")[1].split()[0].strip()


class TestForgotPasswordAPI:
    def test_sends_a_reset_email_for_an_existing_user(self, api_client, forgot_password_url, user):
        response = api_client.post(forgot_password_url, {"email": user.email})

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1
        assert mail.outbox[0].to == [user.email]

    def test_email_contains_a_valid_password_reset_token(self, api_client, forgot_password_url, user):
        api_client.post(forgot_password_url, {"email": user.email})

        token = _extract_reset_token(mail.outbox[0].body)
        decoded = decode_token(token, expected_type="password_reset")

        assert decoded.subject == str(user.pk)

    def test_returns_200_even_for_unknown_email_and_sends_nothing(self, api_client, forgot_password_url):
        response = api_client.post(forgot_password_url, {"email": "ghost@example.com"})

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 0

    def test_rejects_invalid_email_format(self, api_client, forgot_password_url):
        response = api_client.post(forgot_password_url, {"email": "not-an-email"})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_does_not_email_inactive_users(self, api_client, forgot_password_url, user):
        user.is_active = False
        user.save(update_fields=["is_active"])

        api_client.post(forgot_password_url, {"email": user.email})

        assert len(mail.outbox) == 0


class TestResetPasswordAPI:
    def test_resets_password_with_a_valid_token(self, api_client, reset_password_url, user):
        request_password_reset(email=user.email)
        token = _extract_reset_token(mail.outbox[0].body)

        response = api_client.post(
            reset_password_url,
            {"token": token, "new_password": "BrandNewPassw0rd!", "new_password_confirm": "BrandNewPassw0rd!"},
        )

        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.check_password("BrandNewPassw0rd!")

    def test_rejects_mismatched_new_passwords(self, api_client, reset_password_url, user):
        request_password_reset(email=user.email)
        token = _extract_reset_token(mail.outbox[0].body)

        response = api_client.post(
            reset_password_url,
            {"token": token, "new_password": "BrandNewPassw0rd!", "new_password_confirm": "Different!23"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_rejects_weak_new_password(self, api_client, reset_password_url, user):
        request_password_reset(email=user.email)
        token = _extract_reset_token(mail.outbox[0].body)

        response = api_client.post(
            reset_password_url,
            {"token": token, "new_password": "1234567", "new_password_confirm": "1234567"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_rejects_garbage_token(self, api_client, reset_password_url):
        response = api_client.post(
            reset_password_url,
            {"token": "not-a-real-token", "new_password": "BrandNewPassw0rd!", "new_password_confirm": "BrandNewPassw0rd!"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_rejects_expired_token(self, api_client, reset_password_url, user):
        with freeze_time("2026-01-01 00:00:00"):
            request_password_reset(email=user.email)
            token = _extract_reset_token(mail.outbox[0].body)

        with freeze_time("2026-01-01 01:00:00"):  # well past the 15-minute reset lifetime
            response = api_client.post(
                reset_password_url,
                {
                    "token": token,
                    "new_password": "BrandNewPassw0rd!",
                    "new_password_confirm": "BrandNewPassw0rd!",
                },
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_token_cannot_be_reused_after_a_successful_reset(self, api_client, reset_password_url, user):
        request_password_reset(email=user.email)
        token = _extract_reset_token(mail.outbox[0].body)
        payload = {"token": token, "new_password": "BrandNewPassw0rd!", "new_password_confirm": "BrandNewPassw0rd!"}

        first = api_client.post(reset_password_url, payload)
        second = api_client.post(
            reset_password_url,
            {"token": token, "new_password": "AnotherOne!234", "new_password_confirm": "AnotherOne!234"},
        )

        assert first.status_code == status.HTTP_200_OK
        assert second.status_code == status.HTTP_400_BAD_REQUEST

    def test_access_token_cannot_be_used_to_reset_password(self, api_client, reset_password_url, user):
        from authentication.services import issue_token_pair

        tokens = issue_token_pair(user)

        response = api_client.post(
            reset_password_url,
            {
                "token": tokens["access_token"],
                "new_password": "BrandNewPassw0rd!",
                "new_password_confirm": "BrandNewPassw0rd!",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
