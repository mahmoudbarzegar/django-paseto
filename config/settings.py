"""
Django settings for the PASETO auth demo project.
"""
import base64
from datetime import timedelta
from pathlib import Path

from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config("DJANGO_SECRET_KEY", default="dev-insecure-secret-key-change-me")

DEBUG = config("DEBUG", default=True, cast=bool)

ALLOWED_HOSTS = config(
    "ALLOWED_HOSTS", default="localhost,127.0.0.1", cast=lambda v: [s.strip() for s in v.split(",")]
)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # 3rd party
    "rest_framework",
    "drf_spectacular",
    # local
    "authentication",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_USER_MODEL = "authentication.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "authentication.backends.PasetoAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "authentication.exceptions.custom_exception_handler",
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
    "DEFAULT_THROTTLE_RATES": {
        "login": config("LOGIN_THROTTLE_RATE", default="10/min"),
        "forgot_password": config("FORGOT_PASSWORD_THROTTLE_RATE", default="5/min"),
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "PASETO Auth API",
    "DESCRIPTION": "Authentication & authorization API using PASETO tokens (login, register, forgot password).",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "SWAGGER_UI_SETTINGS": {"persistAuthorization": True},
}

# ---------------------------------------------------------------------------
# PASETO settings
# ---------------------------------------------------------------------------
# 32-byte symmetric key for PASETO v4.local tokens, base64-encoded in env.
# Generate one with: python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
_default_dev_key = base64.b64encode(b"dev-only-32-byte-symmetric-key!!").decode()
PASETO_SYMMETRIC_KEY_B64 = config("PASETO_SYMMETRIC_KEY", default=_default_dev_key)
PASETO_SYMMETRIC_KEY = base64.b64decode(PASETO_SYMMETRIC_KEY_B64)

PASETO_ACCESS_TOKEN_LIFETIME = timedelta(minutes=config("PASETO_ACCESS_MINUTES", default=15, cast=int))
PASETO_REFRESH_TOKEN_LIFETIME = timedelta(days=config("PASETO_REFRESH_DAYS", default=7, cast=int))
PASETO_RESET_TOKEN_LIFETIME = timedelta(minutes=config("PASETO_RESET_MINUTES", default=15, cast=int))
PASETO_ISSUER = config("PASETO_ISSUER", default="paseto-auth-demo")

# ---------------------------------------------------------------------------
# Email (console backend for dev; swap for SMTP in production)
# ---------------------------------------------------------------------------
EMAIL_BACKEND = config("EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend")
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="no-reply@paseto-auth-demo.local")
FRONTEND_RESET_PASSWORD_URL = config(
    "FRONTEND_RESET_PASSWORD_URL", default="http://localhost:3000/reset-password"
)
