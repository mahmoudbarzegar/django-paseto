from rest_framework.views import exception_handler as drf_exception_handler


def custom_exception_handler(exc, context):
    """
    Wraps DRF's default exception handler so every error response has the
    same shape:

        {"detail": "...", "errors": {...} | None}

    Field-level validation errors (from a serializer) land in "errors";
    everything else (auth failures, permission denials, 404s, throttling)
    only sets "detail".
    """
    response = drf_exception_handler(exc, context)
    if response is None:
        return None

    data = response.data
    if isinstance(data, dict) and any(k not in ("detail",) for k in data.keys()):
        response.data = {"detail": "Validation failed.", "errors": data}
    elif isinstance(data, dict) and "detail" in data:
        response.data = {"detail": data["detail"], "errors": None}
    else:
        response.data = {"detail": data, "errors": None}

    return response
