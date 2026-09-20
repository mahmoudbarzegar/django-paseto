from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import authentication, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import services
from .serializers import (
    ForgotPasswordRequestSerializer,
    LoginSerializer,
    LogoutSerializer,
    RefreshTokenSerializer,
    RegisterSerializer,
    ResetPasswordConfirmSerializer,
    TokenPairSerializer,
    UserSerializer,
)
from .services import InvalidCredentialsError, InvalidRefreshTokenError, InvalidResetTokenError
from .throttles import ForgotPasswordRateThrottle, LoginRateThrottle


class RegisterAPIView(APIView):
    """Create a new user account and immediately log them in."""

    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Authentication"],
        request=RegisterSerializer,
        responses={201: TokenPairSerializer, 400: OpenApiResponse(description="Validation error")},
        summary="Register a new user",
        description="Creates a user account and returns a PASETO access/refresh token pair.",
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        tokens = services.issue_token_pair(user)
        payload = {**tokens, "user": UserSerializer(user).data}
        return Response(payload, status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    """Authenticate with email + password and receive a token pair."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = [LoginRateThrottle]

    @extend_schema(
        tags=["Authentication"],
        request=LoginSerializer,
        responses={200: TokenPairSerializer, 401: OpenApiResponse(description="Invalid credentials")},
        summary="Log in",
        description="Verifies credentials and returns a PASETO access/refresh token pair.",
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = services.authenticate_user(**serializer.validated_data)
        except InvalidCredentialsError as exc:
            return Response({"detail": str(exc), "errors": None}, status=status.HTTP_401_UNAUTHORIZED)

        tokens = services.issue_token_pair(user)
        payload = {**tokens, "user": UserSerializer(user).data}
        return Response(payload, status=status.HTTP_200_OK)


class ForgotPasswordAPIView(APIView):
    """Request a password-reset email."""

    permission_classes = [permissions.AllowAny]
    throttle_classes = [ForgotPasswordRateThrottle]

    @extend_schema(
        tags=["Authentication"],
        request=ForgotPasswordRequestSerializer,
        responses={200: OpenApiResponse(description="Reset email sent if the account exists")},
        summary="Request a password reset",
        description=(
            "Always returns 200 to avoid leaking whether an email is registered. "
            "If the account exists, a reset link containing a short-lived PASETO "
            "token is emailed to the user."
        ),
    )
    def post(self, request):
        serializer = ForgotPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        services.request_password_reset(**serializer.validated_data)

        return Response(
            {"detail": "If an account with that email exists, a reset link has been sent.", "errors": None},
            status=status.HTTP_200_OK,
        )


class ResetPasswordAPIView(APIView):
    """Confirm a password reset using the token from the email."""

    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Authentication"],
        request=ResetPasswordConfirmSerializer,
        responses={
            200: OpenApiResponse(description="Password updated"),
            400: OpenApiResponse(description="Invalid, expired, or already-used token"),
        },
        summary="Confirm a password reset",
        description="Exchanges a valid password-reset token for a new password.",
    )
    def post(self, request):
        serializer = ResetPasswordConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            services.reset_password(
                token=serializer.validated_data["token"],
                new_password=serializer.validated_data["new_password"],
            )
        except InvalidResetTokenError as exc:
            return Response({"detail": str(exc), "errors": None}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"detail": "Password has been reset successfully.", "errors": None}, status=status.HTTP_200_OK)


class MeAPIView(APIView):
    """Example protected endpoint - proves PASETO authorization is wired up."""

    @extend_schema(
        tags=["Authentication"],
        responses={200: UserSerializer},
        summary="Get the current authenticated user",
    )
    def get(self, request):
        return Response(UserSerializer(request.user).data, status=status.HTTP_200_OK)


class RefreshAPIView(APIView):
    """Exchange a refresh token for a new access/refresh pair (rotation)."""

    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Authentication"],
        request=RefreshTokenSerializer,
        responses={200: TokenPairSerializer, 401: OpenApiResponse(description="Invalid/expired/used refresh token")},
        summary="Refresh an access token",
        description="Rotates the refresh token: the one supplied is revoked and a new pair is issued.",
    )
    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tokens = services.refresh_access_token(**serializer.validated_data)
        except InvalidRefreshTokenError as exc:
            return Response({"detail": str(exc), "errors": None}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(tokens, status=status.HTTP_200_OK)


class LogoutAPIView(APIView):
    """Revoke the caller's current access token, and refresh token if supplied."""

    @extend_schema(
        tags=["Authentication"],
        request=LogoutSerializer,
        responses={205: OpenApiResponse(description="Tokens revoked")},
        summary="Log out",
        description="Revokes the access token used to authenticate this request, and the refresh token if provided.",
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        access_token = authentication.get_authorization_header(request).decode("utf-8").split(" ")[-1]
        services.logout(
            access_token=access_token,
            refresh_token=serializer.validated_data.get("refresh_token") or None,
        )

        return Response(status=status.HTTP_205_RESET_CONTENT)
