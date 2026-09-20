"""
Thin, well-tested wrapper around `pyseto` for issuing and verifying
PASETO v4.local (symmetric, encrypted) tokens.

We use `local` tokens because the server both issues and verifies them
(no third party needs to check the signature independently). If you need
tokens that other services can verify without sharing a secret, switch
to `v4.public` (Ed25519) tokens instead — the encode/decode call sites
below are the only thing that would need to change.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import pyseto
from django.conf import settings
from pyseto import Key


class TokenError(Exception):
    """Base class for all PASETO token problems."""


class TokenExpiredError(TokenError):
    pass


class TokenInvalidError(TokenError):
    pass


@dataclass(frozen=True)
class DecodedToken:
    claims: dict[str, Any]

    @property
    def subject(self) -> str:
        return self.claims["sub"]

    @property
    def token_type(self) -> str:
        return self.claims["type"]


def _get_key() -> Key:
    return Key.new(version=4, purpose="local", key=settings.PASETO_SYMMETRIC_KEY)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def encode_token(*, subject: str, token_type: str, lifetime: timedelta, extra_claims: dict | None = None) -> str:
    """Create a PASETO v4.local token string.

    Args:
        subject: the value placed in the `sub` claim (typically the user id, as a string).
        token_type: a short label ("access", "refresh", "password_reset", ...) used to
            make sure a token can only be used for the purpose it was minted for.
        lifetime: how long the token stays valid.
        extra_claims: any additional claims to embed (e.g. a password fingerprint).
    """
    now = _now()
    claims: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iss": settings.PASETO_ISSUER,
        "iat": now.isoformat(),
        "exp": (now + lifetime).isoformat(),
        "jti": uuid.uuid4().hex,
    }
    if extra_claims:
        claims.update(extra_claims)

    token = pyseto.encode(_get_key(), claims, serializer=json)
    return token.decode("utf-8") if isinstance(token, bytes) else token


def decode_token(token: str, *, expected_type: str | None = None) -> DecodedToken:
    """Verify and decode a PASETO token, returning its claims.

    Raises TokenExpiredError / TokenInvalidError on any problem so callers
    don't need to know anything about the underlying pyseto exceptions.
    """
    if not token:
        raise TokenInvalidError("Token is missing")

    try:
        decoded = pyseto.decode(_get_key(), token, deserializer=json)
    except pyseto.VerifyError as exc:
        # pyseto validates registered claims (like "exp") itself and raises
        # VerifyError for both "expired" and "not yet valid" tokens.
        if "expired" in str(exc).lower():
            raise TokenExpiredError("Token has expired") from exc
        raise TokenInvalidError(str(exc)) from exc
    except Exception as exc:  # any other malformed/tampered/wrong-key token
        raise TokenInvalidError("Token is malformed or has an invalid signature") from exc

    claims = decoded.payload
    if not isinstance(claims, dict):
        raise TokenInvalidError("Token payload is not a valid claim set")

    if not claims.get("exp"):
        raise TokenInvalidError("Token is missing an expiry claim")

    if expected_type is not None and claims.get("type") != expected_type:
        raise TokenInvalidError(f"Expected a '{expected_type}' token, got '{claims.get('type')}'")

    return DecodedToken(claims=claims)
