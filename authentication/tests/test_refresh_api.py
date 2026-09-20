from datetime import timedelta

import pytest
from django.urls import reverse
from freezegun import freeze_time
from rest_framework import status

from authentication.paseto_utils import decode_token
from authentication.services import issue_token_pair

pytestmark = pytest.mark.django_db


@pytest.fixture
def refresh_url():
    return reverse("authentication:refresh")


class TestRefreshAPI:
    def test_returns_a_new_working_access_token(self, api_client, refresh_url, user):
        tokens = issue_token_pair(user)

        response = api_client.post(refresh_url, {"refresh_token": tokens["refresh_token"]})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert decode_token(data["access_token"], expected_type="access").subject == str(user.pk)

    def test_rotates_the_refresh_token_and_the_old_one_is_dead(self, api_client, refresh_url, user):
        tokens = issue_token_pair(user)

        first = api_client.post(refresh_url, {"refresh_token": tokens["refresh_token"]})
        reused = api_client.post(refresh_url, {"refresh_token": tokens["refresh_token"]})

        assert first.status_code == status.HTTP_200_OK
        assert reused.status_code == status.HTTP_401_UNAUTHORIZED
        assert first.json()["refresh_token"] != tokens["refresh_token"]

    def test_new_refresh_token_from_rotation_still_works(self, api_client, refresh_url, user):
        tokens = issue_token_pair(user)
        first = api_client.post(refresh_url, {"refresh_token": tokens["refresh_token"]})
        new_refresh = first.json()["refresh_token"]

        second = api_client.post(refresh_url, {"refresh_token": new_refresh})

        assert second.status_code == status.HTTP_200_OK

    def test_rejects_an_access_token_used_as_a_refresh_token(self, api_client, refresh_url, user):
        tokens = issue_token_pair(user)

        response = api_client.post(refresh_url, {"refresh_token": tokens["access_token"]})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_rejects_garbage_token(self, api_client, refresh_url):
        response = api_client.post(refresh_url, {"refresh_token": "not-a-real-token"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_rejects_expired_refresh_token(self, api_client, refresh_url, user):
        with freeze_time("2026-01-01 00:00:00"):
            tokens = issue_token_pair(user)

        with freeze_time("2026-01-09 00:00:00"):  # past the 7-day refresh lifetime
            response = api_client.post(refresh_url, {"refresh_token": tokens["refresh_token"]})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_rejects_missing_refresh_token(self, api_client, refresh_url):
        response = api_client.post(refresh_url, {})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_rejects_refresh_token_for_inactive_user(self, api_client, refresh_url, user):
        tokens = issue_token_pair(user)
        user.is_active = False
        user.save(update_fields=["is_active"])

        response = api_client.post(refresh_url, {"refresh_token": tokens["refresh_token"]})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
