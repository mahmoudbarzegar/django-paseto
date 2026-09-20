from __future__ import annotations

import hashlib
from datetime import datetime

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail

from .paseto_utils import TokenError, decode_token, encode_token
from .revocation import is_token_revoked, revoke_token

User = get_user_model()


class InvalidCredentialsError(Exception):
    """Raised when email/password don't match an active user."""


class InvalidResetTokenError(Exception):
    """Raised when a password-reset token is invalid, expired, or already used."""


class InvalidRefreshTokenError(Exception):
    """Raised when a refresh token is invalid, expired, revoked, or the wrong type."""


def _password_fingerprint(user) -> str:
    """
    A short, non-reversible fingerprint of the user's current password hash.

    Embedding this in a password-reset token means the token is
    automatically invalidated the moment the password changes - including
    by the very reset it was issued for - without needing a database
    table of "used" tokens.
    """
    return hashlib.sha256(user.password.encode()).hexdigest()[:16]


def issue_token_pair(user) -> dict:
    access_token = encode_token(
        subject=str(user.pk),
        token_type="access",
        lifetime=settings.PASETO_ACCESS_TOKEN_LIFETIME,
    )
    refresh_token = encode_token(
        subject=str(user.pk),
        token_type="refresh",
        lifetime=settings.PASETO_REFRESH_TOKEN_LIFETIME,
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer"}


def register_user(*, email: str, password: str, full_name: str = "") -> User:
    email = User.objects.normalize_email(email)
    return User.objects.create_user(email=email, password=password, full_name=full_name)


def authenticate_user(*, email: str, password: str) -> User:
    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist as exc:
        raise InvalidCredentialsError("Invalid email or password.") from exc

    if not user.is_active:
        raise InvalidCredentialsError("This account has been deactivated.")

    if not user.check_password(password):
        raise InvalidCredentialsError("Invalid email or password.")

    return user


def request_password_reset(*, email: str) -> None:
    """
    Always succeeds from the caller's point of view (no user enumeration):
    if the email matches an active account we email a reset link; if not,
    we silently do nothing.
    """
    try:
        user = User.objects.get(email__iexact=email, is_active=True)
    except User.DoesNotExist:
        return

    reset_token = encode_token(
        subject=str(user.pk),
        token_type="password_reset",
        lifetime=settings.PASETO_RESET_TOKEN_LIFETIME,
        extra_claims={"pwd_fp": _password_fingerprint(user)},
    )
    reset_url = f"{settings.FRONTEND_RESET_PASSWORD_URL}?token={reset_token}"

    send_mail(
        subject="Reset your password",
        message=(
            f"Hello {user.full_name or user.email},\n\n"
            f"Use the link below to reset your password. It expires in "
            f"{int(settings.PASETO_RESET_TOKEN_LIFETIME.total_seconds() // 60)} minutes.\n\n"
            f"{reset_url}\n\n"
            "If you didn't request this, you can safely ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
    )


def reset_password(*, token: str, new_password: str) -> User:
    try:
        decoded = decode_token(token, expected_type="password_reset")
    except TokenError as exc:
        raise InvalidResetTokenError("This reset link is invalid or has expired.") from exc

    try:
        user = User.objects.get(pk=decoded.subject, is_active=True)
    except (User.DoesNotExist, ValueError, TypeError) as exc:
        raise InvalidResetTokenError("This reset link is invalid or has expired.") from exc

    if decoded.claims.get("pwd_fp") != _password_fingerprint(user):
        # The password already changed since this token was issued
        # (e.g. it was already used once) - reject it.
        raise InvalidResetTokenError("This reset link is invalid or has expired.")

    user.set_password(new_password)
    user.save(update_fields=["password"])
    return user


def refresh_access_token(*, refresh_token: str) -> dict:
    """
    Exchange a valid refresh token for a brand-new access/refresh pair.

    The old refresh token is revoked as part of rotation, so a refresh
    token can only ever be used once - if someone else gets hold of a
    stolen one and uses it, the legitimate owner's next refresh attempt
    will fail, which is a signal something is wrong.
    """
    try:
        decoded = decode_token(refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise InvalidRefreshTokenError("This refresh token is invalid or has expired.") from exc

    if is_token_revoked(decoded.claims["jti"]):
        raise InvalidRefreshTokenError("This refresh token has already been used or revoked.")

    try:
        user = User.objects.get(pk=decoded.subject, is_active=True)
    except (User.DoesNotExist, ValueError, TypeError) as exc:
        raise InvalidRefreshTokenError("This refresh token is invalid or has expired.") from exc

    revoke_token(jti=decoded.claims["jti"], expires_at=datetime.fromisoformat(decoded.claims["exp"]))

    return issue_token_pair(user)


def logout(*, access_token: str | None = None, refresh_token: str | None = None) -> None:
    """Revoke whichever of the two tokens were supplied, so they can't be reused."""
    for token, expected_type in ((access_token, "access"), (refresh_token, "refresh")):
        if not token:
            continue
        try:
            decoded = decode_token(token, expected_type=expected_type)
        except TokenError:
            continue  # already invalid/expired - nothing to revoke
        revoke_token(jti=decoded.claims["jti"], expires_at=datetime.fromisoformat(decoded.claims["exp"]))
