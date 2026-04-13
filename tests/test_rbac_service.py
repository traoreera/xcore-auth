import pytest
from unittest.mock import AsyncMock, MagicMock
from app.auth.src.services.rbac import RBACService
from uuid import uuid4
import json

@pytest.fixture
def mock_db():
    db = MagicMock()
    db.session.return_value.__aenter__.return_value = AsyncMock()
    return db

@pytest.fixture
def mock_cache():
    return AsyncMock()

@pytest.mark.asyncio
async def test_get_user_permissions_cached(mock_db, mock_cache):
    user_id = str(uuid4())
    mock_cache.get.return_value = json.dumps(["users:read", "users:write"])

    rbac_svc = RBACService(mock_db, mock_cache)
    perms = await rbac_svc.get_user_permissions(user_id)

    assert perms == {"users:read", "users:write"}
    mock_cache.get.assert_called_with(f"au:user:{user_id}:perms")
    mock_db.session.assert_not_called()

@pytest.mark.asyncio
async def test_get_user_permissions_not_cached(mock_db, mock_cache):
    user_id = str(uuid4())
    mock_cache.get.return_value = None

    # Mock repositories
    mock_role = MagicMock()
    mock_role.name = "standard"
    mock_perm = MagicMock()
    mock_perm.name = "users:read"
    mock_role.permissions = [mock_perm]

    mock_role_repo = AsyncMock()
    mock_role_repo.get_user_roles.return_value = [mock_role]

    rbac_svc = RBACService(mock_db, mock_cache)
    rbac_svc._repos = MagicMock(return_value=(mock_role_repo, AsyncMock()))

    perms = await rbac_svc.get_user_permissions(user_id)

    assert perms == {"users:read"}
    mock_cache.set.assert_called()
