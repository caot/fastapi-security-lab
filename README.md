# FastAPI Security Lab

Educational example: password authentication, HS256 JWT access tokens, rotating opaque refresh tokens, SQLite session revocation, OAuth2 scopes, and resource ownership.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
export JWT_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(48))')
# PowerShell: $env:JWT_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs .

## Try it

```bash
curl -X POST http://127.0.0.1:8000/register -H 'Content-Type: application/json' -d '{"username":"alice","password":"very-secure-password-123"}'
curl -X POST http://127.0.0.1:8000/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"very-secure-password-123"}'
```

Copy the returned `access_token` to `TOKEN`:

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/me
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"title":"example"}' http://127.0.0.1:8000/items
```

Refresh with `POST /refresh` and `{"refresh_token":"..."}`. Logout with `POST /logout` and a bearer token.

## Tests

```bash
export PYTHONPATH=.
pytest -q
```

## Deliberate limitations

- Demonstration only: no TLS termination, rate limiting, password-reset/email verification, MFA, account lockout, audit trail, or CSRF/browser cookie strategy.
- No OAuth2 authorization-code or client-credentials flow; this is first-party password login, not a full OAuth authorization server. `/docs` OAuth2 password-form login is not wired because `/login` accepts JSON.
- The demo grants both scopes to every authenticated user. Scopes are checked but there is no permission provisioning. Implement trusted scope assignment before production.
- HS256 symmetric signing is appropriate only for a tightly controlled single service. For microservices, use OIDC provider-issued asymmetric tokens, JWKS, issuer/audience validation, and key rotation.
- A session database lookup occurs on every protected request, enabling immediate revocation but adding latency and a shared-state dependency.
- Refresh rotation rejects reused tokens, but does not detect/revoke the entire token family on replay. A real system should add family-level reuse detection, atomic rotation, device tracking, and absolute/idle session lifetimes.
- SQLite is for local study. PostgreSQL plus migrations and transactional concurrency tests are recommended for production.
- Password registration is open, without abuse protection. Protect public sign-up with verification, throttling, and monitoring.


## CI/CD, Docker, and extended tests

Install developer tools and run the full test suite:

```bash
python -m pip install -r requirements-dev.txt
ruff check app tests
pytest -q --cov=app --cov-report=term-missing
```

GitHub Actions (`.github/workflows/ci.yml`) runs lint, pytest and coverage on Python 3.11–3.13, then builds and smoke-tests the Docker image. Jenkins (`Jenkinsfile`) runs equivalent stages; configure a Jenkins **Secret text** credential with ID `fastapi-ci-jwt-secret`, and provide Python 3, Docker and curl on the agent. These pipelines test and build; neither automatically publishes or deploys the image. Configure branch protection and deployment approval separately.

For local Docker Compose:

```bash
export JWT_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(48))')
docker compose up --build -d
curl http://127.0.0.1:8000/health
docker compose down
```

On PowerShell, set `$env:JWT_SECRET` instead of `export`. Compose binds only to localhost, uses a named volume for the SQLite database, and runs the app as a non-root user. Do not expose this educational app directly to the Internet. Use TLS, a real identity provider, PostgreSQL, rate limiting, refresh-token reuse detection, and production secrets management for production.
