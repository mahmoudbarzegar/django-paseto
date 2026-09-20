import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status

from authentication.paseto_utils import decode_token

User = get_user_model()

pytestmark = pytest.mark.django_db


@pytest.fixture
def register_url():
    return reverse("authentication:register")


@pytest.fixture
def valid_payload():
    return {
        "email": "newuser@example.com",
        "full_name": "New User",
        "password": "Str0ngPassw0rd!",
        "password_confirm": "Str0ngPassw0rd!",
    }


class TestRegisterAPI:
    def test_registers_a_new_user_and_returns_201(self, api_client, register_url, valid_payload):
        response = api_client.post(register_url, valid_payload)

        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(email="newuser@example.com").exists()

    def test_response_contains_a_usable_access_and_refresh_token(self, api_client, register_url, valid_payload):
        response = api_client.post(register_url, valid_payload)

        data = response.json()
        access_claims = decode_token(data["access_token"], expected_type="access")
        refresh_claims = decode_token(data["refresh_token"], expected_type="refresh")
        user = User.objects.get(email="newuser@example.com")

        assert access_claims.subject == str(user.pk)
        assert refresh_claims.subject == str(user.pk)
        assert data["token_type"] == "Bearer"

    def test_response_contains_the_created_user_and_never_the_raw_password(
        self, api_client, register_url, valid_payload
    ):
        response = api_client.post(register_url, valid_payload)

        data = response.json()
        assert data["user"]["email"] == "newuser@example.com"
        assert "password" not in data["user"]

    def test_stored_password_is_hashed_not_plaintext(self, api_client, register_url, valid_payload):
        api_client.post(register_url, valid_payload)

        user = User.objects.get(email="newuser@example.com")
        assert user.password != valid_payload["password"]
        assert user.check_password(valid_payload["password"])

    def test_rejects_duplicate_email(self, api_client, register_url, valid_payload, user):
        valid_payload["email"] = user.email

        response = api_client.post(register_url, valid_payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.json()["errors"]

    def test_rejects_mismatched_passwords(self, api_client, register_url, valid_payload):
        valid_payload["password_confirm"] = "SomethingElse!23"

        response = api_client.post(register_url, valid_payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "password_confirm" in response.json()["errors"]

    def test_rejects_weak_password(self, api_client, register_url, valid_payload):
        valid_payload["password"] = "1234567"
        valid_payload["password_confirm"] = "1234567"

        response = api_client.post(register_url, valid_payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "password" in response.json()["errors"]

    @pytest.mark.parametrize("missing_field", ["email", "password", "password_confirm"])
    def test_rejects_missing_required_fields(self, api_client, register_url, valid_payload, missing_field):
        del valid_payload[missing_field]

        response = api_client.post(register_url, valid_payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_rejects_invalid_email_format(self, api_client, register_url, valid_payload):
        valid_payload["email"] = "not-an-email"

        response = api_client.post(register_url, valid_payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
