from datetime import timedelta

import pytest
from django.urls import reverse
from freezegun import freeze_time
from rest_framework import status

from authentication.paseto_utils import decode_token

pytestmark = pytest.mark.django_db


@pytest.fixture
def login_url():
    return reverse("authentication:login")


@pytest.fixture
def me_url():
    return reverse("authentication:me")


class TestLoginAPI:
    def test_logs_in_with_correct_credentials(self, api_client, login_url, user):
        response = api_client.post(login_url, {"email": user.email, "password": "Str0ngPassw0rd!"})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["user"]["email"] == user.email
        assert decode_token(data["access_token"], expected_type="access").subject == str(user.pk)

    def test_rejects_wrong_password(self, api_client, login_url, user):
        response = api_client.post(login_url, {"email": user.email, "password": "WrongPassword!"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"]

    def test_rejects_unknown_email(self, api_client, login_url):
        response = api_client.post(login_url, {"email": "ghost@example.com", "password": "whatever123"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_rejects_inactive_user(self, api_client, login_url, user):
        user.is_active = False
        user.save(update_fields=["is_active"])

        response = api_client.post(login_url, {"email": user.email, "password": "Str0ngPassw0rd!"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_rejects_missing_fields(self, api_client, login_url):
        response = api_client.post(login_url, {"email": "jane@example.com"})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_does_not_leak_whether_the_error_was_email_or_password(self, api_client, login_url, user):
        wrong_password_response = api_client.post(login_url, {"email": user.email, "password": "WrongPassword!"})
        unknown_email_response = api_client.post(login_url, {"email": "ghost@example.com", "password": "x"})

        assert wrong_password_response.json()["detail"] == unknown_email_response.json()["detail"]

    def test_throttles_after_too_many_attempts_from_the_same_client(self, api_client, login_url, user):
        from django.conf import settings

        rate = settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]["login"]
        limit = int(rate.split("/")[0])

        for _ in range(limit):
            response = api_client.post(login_url, {"email": user.email, "password": "WrongPassword!"})
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

        throttled = api_client.post(login_url, {"email": user.email, "password": "WrongPassword!"})

        assert throttled.status_code == status.HTTP_429_TOO_MANY_REQUESTS


class TestAccessTokenAuthorizesProtectedEndpoint:
    def test_valid_access_token_can_reach_protected_endpoint(self, auth_client, me_url, user):
        response = auth_client.get(me_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["email"] == user.email

    def test_missing_token_is_rejected(self, api_client, me_url):
        response = api_client.get(me_url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_garbage_token_is_rejected(self, api_client, me_url):
        api_client.credentials(HTTP_AUTHORIZATION="Bearer not-a-real-token")

        response = api_client.get(me_url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_expired_token_is_rejected(self, api_client, me_url, user):
        from authentication.services import issue_token_pair

        with freeze_time("2026-01-01 00:00:00"):
            tokens = issue_token_pair(user)

        with freeze_time("2026-01-01 02:00:00"):  # well past the 15-minute access lifetime
            api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}")
            response = api_client.get(me_url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_token_cannot_be_used_as_an_access_token(self, api_client, me_url, user):
        from authentication.services import issue_token_pair

        tokens = issue_token_pair(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['refresh_token']}")

        response = api_client.get(me_url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
