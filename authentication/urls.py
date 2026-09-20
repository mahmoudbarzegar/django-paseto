from django.urls import path

from .views import (
    ForgotPasswordAPIView,
    LoginAPIView,
    LogoutAPIView,
    MeAPIView,
    RefreshAPIView,
    RegisterAPIView,
    ResetPasswordAPIView,
)

app_name = "authentication"

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("refresh/", RefreshAPIView.as_view(), name="refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordAPIView.as_view(), name="forgot-password"),
    path("reset-password/", ResetPasswordAPIView.as_view(), name="reset-password"),
    path("me/", MeAPIView.as_view(), name="me"),
]
