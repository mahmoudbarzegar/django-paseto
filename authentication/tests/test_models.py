import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError

User = get_user_model()

pytestmark = pytest.mark.django_db


class TestUserManager:
    def test_create_user_normalizes_email_and_sets_hashed_password(self):
        user = User.objects.create_user(email="Jane@Example.COM", password="Str0ngPassw0rd!")

        assert user.email == "Jane@example.com"
        assert user.check_password("Str0ngPassw0rd!")
        assert user.password != "Str0ngPassw0rd!"
        assert user.is_active is True
        assert user.is_staff is False

    def test_create_user_without_email_raises(self):
        with pytest.raises(ValueError):
            User.objects.create_user(email="", password="whatever123")

    def test_email_must_be_unique(self):
        User.objects.create_user(email="dupe@example.com", password="Str0ngPassw0rd!")

        with pytest.raises(IntegrityError):
            User.objects.create_user(email="dupe@example.com", password="An0therPassw0rd!")

    def test_create_superuser_sets_staff_and_superuser_flags(self):
        admin = User.objects.create_superuser(email="admin@example.com", password="Str0ngPassw0rd!")

        assert admin.is_staff is True
        assert admin.is_superuser is True

    def test_str_returns_email(self):
        user = User.objects.create_user(email="jane@example.com", password="Str0ngPassw0rd!")

        assert str(user) == "jane@example.com"
