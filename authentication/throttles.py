from rest_framework.throttling import AnonRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """Throttles login attempts per client IP to blunt brute-forcing passwords."""

    scope = "login"


class ForgotPasswordRateThrottle(AnonRateThrottle):
    """Throttles password-reset requests per client IP to blunt email-enumeration/spam."""

    scope = "forgot_password"
