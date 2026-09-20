from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "authentication"
    label = "authentication"
    verbose_name = "Authentication"

    def ready(self):
        # Registers the drf-spectacular security scheme for PasetoAuthentication.
        from . import schema  # noqa: F401
