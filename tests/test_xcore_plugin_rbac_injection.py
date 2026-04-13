from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from xcore.kernel.api.auth import (
    AuthPayload,
    register_auth_backend,
    unregister_auth_backend,
)
from xcore.sdk import RoutedPlugin, route


class DummyAuthBackend:
    async def decode_token(self, token: str) -> AuthPayload | None:
        if token == "valid-token":
            return AuthPayload(
                sub="user-1",
                roles=["member"],
                permissions=["orders:read"],
            )
        if token == "forbidden-token":
            return AuthPayload(
                sub="user-2",
                roles=["member"],
                permissions=["profile:read"],
            )
        return None

    async def extract_token(self, request) -> str | None:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return request.cookies.get("access_token")

    async def has_permission(self, payload: AuthPayload, permission: str) -> bool:
        if "superadmin" in payload.get("roles", []):
            return True
        return permission in payload.get("permissions", [])


class DemoPlugin(RoutedPlugin):
    @route("/secure", method="GET", permissions=["orders:read"])
    async def secure_endpoint(self, request: Request):
        return {
            "ok": True,
            "sub": request.state.user.get("sub"),
        }


@pytest.fixture
def client_with_rbac_backend() -> TestClient:
    register_auth_backend(DummyAuthBackend())

    app = FastAPI()
    router = DemoPlugin().RouterIn()
    assert router is not None
    app.include_router(router, prefix="/plugins/demo")

    client = TestClient(app)
    try:
        yield client
    finally:
        unregister_auth_backend()


def test_plugin_route_requires_token(client_with_rbac_backend: TestClient):
    response = client_with_rbac_backend.get("/plugins/demo/secure")
    assert response.status_code == 401
    assert response.json()["detail"] == "Token manquant"


def test_plugin_route_rejects_missing_permission(client_with_rbac_backend: TestClient):
    response = client_with_rbac_backend.get(
        "/plugins/demo/secure",
        headers={"Authorization": "Bearer forbidden-token"},
    )
    assert response.status_code == 403
    assert "Permissions manquantes" in response.json()["detail"]


def test_plugin_route_accepts_valid_permission(client_with_rbac_backend: TestClient):
    response = client_with_rbac_backend.get(
        "/plugins/demo/secure",
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "sub": "user-1"}
