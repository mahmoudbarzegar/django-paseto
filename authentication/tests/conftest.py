import pytest
from django.core.cache import cache
from model_bakery import baker
from rest_framework.test import APIClient

from authentication.services import issue_token_pair


@pytest.fixture(autouse=True)
def clear_cache():
    """
    Isolate tests from each other where the cache is used as shared state -
    the revocation blocklist and DRF's throttle counters both live there.
    Without this, throttle attempts from one test leak into the next.
    """
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def user(db):
    user = baker.make("authentication.User", email="jane@example.com", is_active=True)
    user.set_password("Str0ngPassw0rd!")
    user.save()
    return user


@pytest.fixture
def auth_client(api_client, user):
    tokens = issue_token_pair(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}")
    return api_client
