import pytest
from django.urls import reverse
from rest_framework import status

from authentication.services import issue_token_pair

pytestmark = pytest.mark.django_db


@pytest.fixture
def logout_url():
    return reverse("authentication:logout")


@pytest.fixture
def me_url():
    return reverse("authentication:me")


@pytest.fixture
def refresh_url():
    return reverse("authentication:refresh")


class TestLogoutAPI:
    def test_logout_revokes_the_access_token_used_to_call_it(self, api_client, logout_url, me_url, user):
        tokens = issue_token_pair(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}")

        logout_response = api_client.post(logout_url, {})
        me_response = api_client.get(me_url)

        assert logout_response.status_code == status.HTTP_205_RESET_CONTENT
        assert me_response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_also_revokes_a_supplied_refresh_token(self, api_client, logout_url, refresh_url, user):
        tokens = issue_token_pair(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}")

        api_client.post(logout_url, {"refresh_token": tokens["refresh_token"]})
        refresh_response = api_client.post(refresh_url, {"refresh_token": tokens["refresh_token"]})

        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_without_a_refresh_token_still_succeeds(self, api_client, logout_url, user):
        tokens = issue_token_pair(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}")

        response = api_client.post(logout_url, {})

        assert response.status_code == status.HTTP_205_RESET_CONTENT

    def test_logout_requires_authentication(self, api_client, logout_url):
        response = api_client.post(logout_url, {})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
