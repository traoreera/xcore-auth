
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from app.auth.src.routes.auth import auth_router
from app.auth.src.routes.deps import get_current_user
from app.auth.src.routes.oauth import oauth_router
from app.auth.src.routes.users import users_router
from app.auth.src.schemas.auth import LoginResponse, RegisterResponse
from app.auth.src.services.audit import AuditService
from app.auth.src.services.auth import AuthService
from app.auth.src.services.oauth import OAuthService
from app.auth.src.repositories.user import UserRepository


def test_register_route_with_fake_user_data(monkeypatch, make_client, fake_db, fake_cache, fake_env):
    fake_user_id = uuid4()

    async def fake_register(self, body, request):
        assert body.email.endswith("@example.com")
        return RegisterResponse(
            message="Compte créé. Vérifiez votre email.",
            user_id=fake_user_id,
            email_verification_sent=True,
        )

    monkeypatch.setattr(AuthService, "register", fake_register)

    client = make_client(auth_router(fake_db, fake_cache, fake_env))
    response = client.post(
        "/app/auth/register",
        json={
            "email": "qa.user@example.com",
            "password": "StrongPass123!",
            "first_name": "QA",
            "last_name": "User",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["user_id"] == str(fake_user_id)
    assert payload["email_verification_sent"] is True


def test_me_route_with_simulated_authenticated_user(
    monkeypatch, make_client, fake_db, fake_cache, fake_env, simulated_user
):
    now = datetime.now(UTC)
    db_user = SimpleNamespace(
        id=simulated_user.id,
        email=simulated_user.email,
        first_name=simulated_user.first_name,
        last_name=simulated_user.last_name,
        is_active=True,
        is_verified=True,
        mfa_enabled=False,
        last_login_at=None,
        oauth_accounts=[],
        created_at=now,
        updated_at=now,
    )

    async def fake_get_by_id(self, user_id):
        assert user_id == simulated_user.id
        return db_user

    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_by_id)

    client = make_client(users_router(fake_db, fake_cache, fake_env))
    client.app.dependency_overrides[get_current_user] = lambda: simulated_user

    response = client.get("/app/auth/me")

    assert response.status_code == 200
    assert response.json()["email"] == "simulated.user@example.com"


def test_google_oauth_callback_without_real_google_account(
    monkeypatch, make_client, fake_db, fake_cache, fake_env
):
    fake_user = SimpleNamespace(
        id=uuid4(),
        email="google.user@example.com",
        first_name="Google",
        last_name="User",
        is_active=True,
        is_verified=True,
    )

    async def fake_exchange_code(self, provider, code, state, redirect_uri):
        assert provider == "google"
        return {
            "provider": "google",
            "provider_uid": "google-user-123",
            "email": fake_user.email,
            "first_name": fake_user.first_name,
            "last_name": fake_user.last_name,
            "access_token": "enc-access",
            "refresh_token": "enc-refresh",
        }

    async def fake_get_oauth_account(self, provider, provider_uid):
        return None

    async def fake_get_by_email(self, email):
        return None

    async def fake_create(self, **kwargs):
        return fake_user

    async def fake_add_oauth_account(self, user, **kwargs):
        assert user.id == fake_user.id
        assert kwargs["provider"] == "google"
        assert kwargs["provider_uid"] == "google-user-123"
        return None

    async def fake_issue_tokens(self, user, remember_me, request, response):
        assert user.id == fake_user.id
        return LoginResponse(
            status="authenticated",
            access_token="test-access-token",
            refresh_token="test-refresh-token",
            expires_in=900,
        )

    async def fake_audit_log(self, action, success, request, user_id=None, metadata=None):
        assert action == "user.oauth_login.google"
        assert success is True
        assert user_id == fake_user.id
        return None

    monkeypatch.setattr(OAuthService, "exchange_code", fake_exchange_code)
    monkeypatch.setattr(UserRepository, "get_oauth_account", fake_get_oauth_account)
    monkeypatch.setattr(UserRepository, "get_by_email", fake_get_by_email)
    monkeypatch.setattr(UserRepository, "create", fake_create)
    monkeypatch.setattr(UserRepository, "add_oauth_account", fake_add_oauth_account)
    monkeypatch.setattr(AuthService, "_issue_tokens", fake_issue_tokens)
    monkeypatch.setattr(AuditService, "log", fake_audit_log)

    client = make_client(oauth_router(fake_db, fake_cache, fake_env), prefix="/app/auth/oauth")
    response = client.get("/app/auth/oauth/google/callback?code=test-code&state=test-state")

    assert response.status_code == 200
    payload = response.json()
    assert payload["access_token"] == "test-access-token"
    assert payload["refresh_token"] == "test-refresh-token"


def test_github_oauth_link_without_real_github_account(
    monkeypatch, make_client, fake_db, fake_cache, fake_env, simulated_user
):
    db_user = SimpleNamespace(id=simulated_user.id)

    async def fake_exchange_code(self, provider, code, state, redirect_uri):
        assert provider == "github"
        return {
            "provider": "github",
            "provider_uid": "github-user-999",
            "email": "github.user@example.com",
            "first_name": "GitHub",
            "last_name": "User",
            "access_token": "enc-gh-access",
            "refresh_token": "enc-gh-refresh",
        }

    async def fake_get_oauth_account(self, provider, provider_uid):
        return None

    async def fake_get_by_id(self, user_id):
        assert user_id == simulated_user.id
        return db_user

    async def fake_add_oauth_account(self, user, **kwargs):
        assert user.id == simulated_user.id
        assert kwargs["provider"] == "github"
        return None

    async def fake_audit_log(self, action, success, request, user_id=None, metadata=None):
        assert action == "user.oauth_linked.github"
        assert success is True
        assert user_id == simulated_user.id
        return None

    monkeypatch.setattr(OAuthService, "exchange_code", fake_exchange_code)
    monkeypatch.setattr(UserRepository, "get_oauth_account", fake_get_oauth_account)
    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_by_id)
    monkeypatch.setattr(UserRepository, "add_oauth_account", fake_add_oauth_account)
    monkeypatch.setattr(AuditService, "log", fake_audit_log)

    client = make_client(oauth_router(fake_db, fake_cache, fake_env), prefix="/app/auth/oauth")
    client.app.dependency_overrides[get_current_user] = lambda: simulated_user

    response = client.post(
        "/app/auth/oauth/github/link",
        json={"code": "github-code", "state": "github-state"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Compte github lié avec succès."
