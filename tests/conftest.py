
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.src.routes.deps import configure_auth_runtime
from app.auth.src.schemas.user import UserOutWithPermissions


class DummySessionManager:
    async def __aenter__(self):
        return SimpleNamespace()

    async def __aexit__(self, exc_type, exc, tb):
        return False


class DummyDB:
    def session(self):
        return DummySessionManager()


@pytest.fixture
def fake_env(tmp_path) -> dict:
    private_key = tmp_path / "test_private.pem"
    public_key = tmp_path / "test_public.pem"
    private_key.write_text("dummy-private-key")
    public_key.write_text("dummy-public-key")
    return {
        "ENCRYPTION_KEY": "V3nv_IG7l-v5_xcTf-qDzXtEIlpeYtSx0hWWtk8xP2E=",
        "JWT_PRIVATE_KEY": str(private_key),
        "JWT_PUBLIC_KEY": str(public_key),
        "JWT_ALGORITHM": "RS256",
        "ACCESS_TOKEN_TTL": "900",
        "REFRESH_TOKEN_TTL": "2592000",
        "PWNED_CHECK_ENABLED": "false",
        "APP_BASE_URL": "http://testserver",
        "GOOGLE_CLIENT_ID": "google-test-client",
        "GOOGLE_CLIENT_SECRET": "google-test-secret",
        "GITHUB_CLIENT_ID": "github-test-client",
        "GITHUB_CLIENT_SECRET": "github-test-secret",
    }


@pytest.fixture
def fake_cache():
    class CacheStub:
        async def get(self, *_args, **_kwargs):
            return None

        async def set(self, *_args, **_kwargs):
            return True

        async def delete(self, *_args, **_kwargs):
            return True

    return CacheStub()


@pytest.fixture
def fake_db() -> DummyDB:
    return DummyDB()


@pytest.fixture
def simulated_user() -> UserOutWithPermissions:
    now = datetime.now(UTC)
    return UserOutWithPermissions.model_construct(
        id=uuid4(),
        email="simulated.user@example.com",
        first_name="Simulated",
        last_name="User",
        is_active=True,
        is_verified=True,
        mfa_enabled=False,
        last_login_at=None,
        oauth_accounts=[],
        roles=["standard"],
        permissions=["users:read"],
        created_at=now,
        updated_at=now,
        model_extra={"session_id": str(uuid4())},
    )


@pytest.fixture
def make_client(fake_env, fake_cache):
    def _make(router, *, prefix: str = "/app/auth") -> TestClient:
        configure_auth_runtime(env=fake_env, cache=fake_cache)
        app = FastAPI()
        app.state.xcore_env = fake_env
        app.state.xcore_cache = fake_cache
        app.include_router(router, prefix=prefix)
        return TestClient(app)

    return _make
