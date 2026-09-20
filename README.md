# PASETO Auth — Django + DRF

Email/password authentication for Django REST Framework using **PASETO**
(`v4.local`, symmetric/encrypted tokens) instead of JWT, built test-first.

## Why PASETO instead of JWT

JWT's `alg` header lets an attacker request `alg: none` or algorithm-confusion
attacks if a server is misconfigured; it also has a long tail of footguns
(unbounded claim types, ambiguous crypto agility). PASETO removes the
`alg` field entirely — the version+purpose in the token prefix
(`v4.local.`) fixes the algorithm, so there's nothing to confuse. `v4.local`
tokens are encrypted (XChaCha20-Poly1305), not just signed, so the payload
isn't just base64 — it's opaque to anyone without the server's key.

## Endpoints

| Method | Path                              | Auth      | Purpose                          |
|--------|-----------------------------------|-----------|-----------------------------------|
| POST   | `/api/v1/auth/register/`          | Public    | Create account, returns tokens    |
| POST   | `/api/v1/auth/login/`             | Public    | Exchange credentials for tokens (rate-limited) |
| POST   | `/api/v1/auth/refresh/`           | Public    | Exchange refresh token for a new pair (rotates it) |
| POST   | `/api/v1/auth/logout/`            | Bearer    | Revoke the current access token (and refresh token if supplied) |
| POST   | `/api/v1/auth/forgot-password/`   | Public    | Emails a password-reset link (rate-limited) |
| POST   | `/api/v1/auth/reset-password/`    | Public    | Exchanges reset token for new pw  |
| GET    | `/api/v1/auth/me/`                | Bearer    | Example protected endpoint        |

Swagger UI: `/api/docs/` · Redoc: `/api/redoc/` · Raw schema: `/api/schema/`

## Project layout

```
paseto_auth/
├── manage.py
├── requirements.txt
├── pytest.ini
├── .env.example
├── config/                    # Django project (settings, root urls)
│   ├── settings.py
│   └── urls.py
└── authentication/            # app lives at project root (see note below)
    ├── models.py          # custom User (email as USERNAME_FIELD)
    ├── managers.py        # UserManager (create_user/create_superuser)
    ├── paseto_utils.py    # encode_token/decode_token — the PASETO core
    ├── backends.py        # PasetoAuthentication (DRF auth class)
    ├── revocation.py      # cache-backed jti blocklist for logout/refresh rotation
    ├── throttles.py       # rate limiting for login & forgot-password
    ├── schema.py          # drf-spectacular security scheme for Swagger
    ├── serializers.py     # Register/Login/ForgotPassword/ResetPassword
    ├── services.py        # business logic (framework-agnostic)
    ├── exceptions.py      # uniform {"detail", "errors"} error envelope
    ├── views.py           # APIView per endpoint, documented w/ @extend_schema
    ├── urls.py
    └── tests/             # TDD suite — one file per unit under test
        ├── conftest.py
        ├── test_paseto_utils.py
        ├── test_revocation.py
        ├── test_models.py
        ├── test_register_api.py
        ├── test_login_api.py
        ├── test_refresh_api.py
        ├── test_logout_api.py
        └── test_forgot_password_api.py
```

> **Note on layout:** this app sits at the project root (`authentication/`,
> `INSTALLED_APPS = ["authentication", ...]`) rather than under an `apps/`
> subfolder. Both are common in real Django projects — root-level is what
> `django-admin startapp` gives you and what the official tutorial teaches;
> an `apps/` subfolder is a convention some larger codebases use (e.g.
> cookiecutter-django) to keep the project root uncluttered as the app
> count grows. Neither is enforced by the framework — pick whichever your
> team prefers and stay consistent.

`views.py` stays thin — it only translates HTTP ⇄ Python. All the actual
decision-making (hash a password, mint a token, decide whether a reset
token is still valid) lives in `services.py`, which is why it's testable
without spinning up a client for every case.

## Token revocation (logout & refresh rotation)

`v4.local` tokens are stateless by default, so there's normally nothing to
revoke server-side. `revocation.py` adds a thin blocklist on top using
Django's cache framework: revoking a token stores its `jti` with a TTL equal
to its remaining lifetime, so the blocklist never grows unboundedly.
`PasetoAuthentication` checks it on every request; `/refresh/` uses it to
make each refresh token single-use (rotation); `/logout/` uses it to kill
the caller's access token immediately instead of waiting out its 15-minute
lifetime.

## Rate limiting

`/login/` and `/forgot-password/` are throttled per-client-IP
(`throttles.py`, rates configurable via `LOGIN_THROTTLE_RATE` /
`FORGOT_PASSWORD_THROTTLE_RATE` in `.env`) to blunt brute-forcing and
email-enumeration/spam respectively.

## How password reset invalidation works (no extra DB table)

Each reset token embeds a short fingerprint of the user's *current*
password hash (`sha256(user.password)[:16]`). On redemption we recompute
that fingerprint and compare. The moment the password changes — including
by the very reset the token was issued for — the fingerprint no longer
matches, so the token is dead. That gives one-time-use tokens without a
"used tokens" table to maintain.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Generate a real signing key and put it in .env as PASETO_SYMMETRIC_KEY:
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"

python manage.py migrate
python manage.py createsuperuser   # optional
python manage.py runserver
```

Visit `http://localhost:8000/api/docs/` for Swagger UI — click **Authorize**
and paste an access token (from `/login/` or `/register/`) as `Bearer <token>`
to try the protected `/me/` endpoint from the browser.

## Running the tests (TDD workflow used to build this)

```bash
pytest apps/authentication/tests/ -v
pytest apps/authentication/tests/ --cov=apps.authentication --cov-report=term-missing
```

Each module here was built red→green: `test_paseto_utils.py` was written
before `paseto_utils.py` had a working `decode_token`; `test_register_api.py`
was written before `RegisterAPIView` existed (it 404'd, then failed
validation, then passed once the serializer + service were filled in), and
so on for login and forgot-password. Re-run the suite after any change —
the fixtures in `conftest.py` (`user`, `auth_client`) are the shared
scaffolding every test file builds on.

## Extending this

- **Rate limiting** is already applied to `/login/` and `/forgot-password/`;
  extend the same pattern (a scoped `AnonRateThrottle` subclass) to other
  endpoints if needed.
- **Token revocation** is already in place via `revocation.py` — the
  blocklist is cache-backed (Django's default `LocMemCache` locally). In a
  multi-process deployment, point `CACHES` at Redis/Memcached so all
  workers see the same revocation state.
- **Email verification**: add an `is_verified` field to `User` and a
  verify-email endpoint following the same PASETO-token-with-a-purpose
  pattern used for password reset.
