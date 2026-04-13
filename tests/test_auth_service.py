import pytest
from datetime import datetime, UTC, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock
from fastapi import Request
from app.auth.src.services.auth import AuthService
from app.auth.src.schemas.auth import RegisterRequest, LoginRequest
from app.auth.src.schemas.user import UserOutWithPermissions

@pytest.fixture
def mock_db():
    db = MagicMock()
    db.session.return_value.__aenter__.return_value = AsyncMock()
    return db

@pytest.fixture
def mock_cache():
    return AsyncMock()

@pytest.fixture
def env():
    return {
        "ENCRYPTION_KEY": "V3nv_IG7l-v5_xcTf-qDzXtEIlpeYtSx0hWWtk8xP2E=",
        "JWT_PRIVATE_KEY": "test_private.pem",
        "JWT_PUBLIC_KEY": "test_public.pem",
        "JWT_ALGORITHM": "RS256",
        "ACCESS_TOKEN_TTL": "900",
        "REFRESH_TOKEN_TTL": "2592000",
        "PWNED_CHECK_ENABLED": "false",
        "APP_BASE_URL": "http://localhost",
    }

@pytest.mark.asyncio
async def test_register_success(mock_db, mock_cache, env, tmp_path):
    # Mock TokenService dependencies
    priv = tmp_path / "test_private.pem"
    pub = tmp_path / "test_public.pem"
    priv.write_text("dummy")
    pub.write_text("dummy")

    env["JWT_PRIVATE_KEY"] = str(priv)
    env["JWT_PUBLIC_KEY"] = str(pub)

    from unittest.mock import patch
    with patch("app.auth.src.services.token.TokenService.__init__", return_value=None):
        from app.auth.src.services.auth import AuthService

        auth_service = AuthService(mock_db, mock_cache, env)
        auth_service._token_svc = MagicMock()
        auth_service._email_svc = AsyncMock()

        # Mock UserRepository
        mock_user_repo = AsyncMock()
        mock_user_repo.get_by_email.return_value = None
        user_id = uuid4()
        mock_user_repo.create.return_value = MagicMock(id=user_id, email="test@example.com", first_name="Test")
        auth_service._user_repo = MagicMock(return_value=mock_user_repo)

        # Mock EmailTokenRepository
        mock_email_token_repo = AsyncMock()
        auth_service._email_token_repo = MagicMock(return_value=mock_email_token_repo)

        # Mock RBAC
        auth_service._rbac_svc = MagicMock()
        auth_service._rbac_svc._repos.return_value = (AsyncMock(), AsyncMock())

        body = RegisterRequest(
            email="test@example.com",
            password="Password123!@#",
            first_name="Test",
            last_name="User"
        )
        request = MagicMock(spec=Request)

        response = await auth_service.register(body, request)

        assert response.user_id == user_id
        assert response.email_verification_sent is True
        mock_user_repo.create.assert_called_once()
