from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions

from .paseto_utils import TokenError, TokenExpiredError, decode_token
from .revocation import is_token_revoked

User = get_user_model()


class PasetoAuthentication(authentication.BaseAuthentication):
    """
    Authenticates requests carrying:

        Authorization: Bearer <PASETO v4.local access token>

    On success returns (user, decoded_token_claims), same contract DRF
    expects from any authentication class.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode("utf-8")
        if not auth_header:
            return None  # let other authenticators / AnonymousUser handle it

        parts = auth_header.split()
        if parts[0].lower() != self.keyword.lower():
            return None
        if len(parts) == 1:
            raise exceptions.AuthenticationFailed("Invalid Authorization header. No token provided.")
        if len(parts) > 2:
            raise exceptions.AuthenticationFailed("Invalid Authorization header. Token contains spaces.")

        token = parts[1]

        try:
            decoded = decode_token(token, expected_type="access")
        except TokenExpiredError as exc:
            raise exceptions.AuthenticationFailed("Access token has expired.") from exc
        except TokenError as exc:
            raise exceptions.AuthenticationFailed("Invalid access token.") from exc

        if is_token_revoked(decoded.claims["jti"]):
            raise exceptions.AuthenticationFailed("This access token has been revoked.")

        try:
            user = User.objects.get(pk=decoded.subject)
        except (User.DoesNotExist, ValueError, TypeError) as exc:
            raise exceptions.AuthenticationFailed("User for this token no longer exists.") from exc

        if not user.is_active:
            raise exceptions.AuthenticationFailed("User account is disabled.")

        return (user, decoded.claims)

    def authenticate_header(self, request):
        return self.keyword
