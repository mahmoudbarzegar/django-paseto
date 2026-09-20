from drf_spectacular.extensions import OpenApiAuthenticationExtension


class PasetoAuthenticationScheme(OpenApiAuthenticationExtension):
    """
    Tells drf-spectacular how to describe PasetoAuthentication in the
    OpenAPI schema, so Swagger UI renders a working "Authorize" button
    for `Authorization: Bearer <token>`.
    """

    target_class = "authentication.backends.PasetoAuthentication"
    name = "pasetoAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "PASETO",
            "description": (
                "PASETO v4.local access token obtained from /login/ or /register/. "
                "Send as: Authorization: Bearer <token>"
            ),
        }
