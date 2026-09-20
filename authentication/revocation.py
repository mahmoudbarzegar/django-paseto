"""
Token revocation ("blocklist") support.

PASETO v4.local tokens are self-contained and stateless by default - there's
nothing to look up server-side to verify them, which is great for
performance but means there's no built-in way to kill a token before it
naturally expires. This module adds that back in, for the two cases where
it matters: logout, and refresh-token rotation.

We only ever need to remember a revoked token until it would have expired
anyway, so entries are stored with a TTL equal to the token's remaining
lifetime - the blocklist never grows unboundedly.
"""
from __future__ import annotations

from datetime import datetime

from django.core.cache import cache

_CACHE_PREFIX = "paseto:revoked:"


def _cache_key(jti: str) -> str:
    return f"{_CACHE_PREFIX}{jti}"


def revoke_token(*, jti: str, expires_at: datetime) -> None:
    """Mark a token's jti as revoked until its natural expiry."""
    ttl_seconds = max(int((expires_at - datetime.now(expires_at.tzinfo)).total_seconds()), 1)
    cache.set(_cache_key(jti), True, timeout=ttl_seconds)


def is_token_revoked(jti: str) -> bool:
    return cache.get(_cache_key(jti)) is not None
