from __future__ import annotations
import secrets
import json
import httpx
from urllib.parse import urlencode
from .security import SecurityService


PROVIDERS = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        "scopes": ["openid", "email", "profile"],
        "extra_auth_params": {"access_type": "offline", "prompt": "consent"},
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "scopes": ["read:user", "user:email"],
    },
    "microsoft": {
        "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scopes": ["openid", "email", "profile"],
    },
}


class OAuthService:
    def __init__(self, cache, env: dict, security: SecurityService):
        self.cache = cache
        self.env = env
        self.security = security

    def _get_credentials(self, provider: str) -> tuple[str, str]:
        p = provider.upper()
        return (
            self.env.get(f"{p}_CLIENT_ID", ""),
            self.env.get(f"{p}_CLIENT_SECRET", ""),
        )

    async def get_authorization_url(self, provider: str) -> dict:
        if provider not in PROVIDERS:
            raise ValueError(f"Provider inconnu : {provider}")

        cfg = PROVIDERS[provider]
        client_id, _ = self._get_credentials(provider)
        url = f"{self.env.get("REDIRECTION_URL")}/{provider}/callback"

        print('url for redirection =>', url)
        state = secrets.token_urlsafe(32)

        await self.cache.set(
            f"au:oauth:state:{state}",
            json.dumps({"provider": provider}),
            ttl=600,
        )

        params = {
            "client_id": client_id,
            "redirect_uri": url,
            "response_type": "code",
            "scope": " ".join(cfg["scopes"]),
            "state": state,
        }

        # Params spécifiques provider
        params.update(cfg.get("extra_auth_params", {}))

        auth_url = f"{cfg['auth_url']}?{urlencode(params)}"

        return {"authorization_url": auth_url, "state": state}

    async def exchange_code(
        self,
        provider: str,
        code: str,
        state: str,
    ) -> dict:

        if provider not in PROVIDERS:
            raise ValueError(f"Provider inconnu : {provider}")

        cached = await self.cache.get(f"au:oauth:state:{state}")
        if not cached:
            raise ValueError("State OAuth invalide ou expiré.")

        await self.cache.delete(f"au:oauth:state:{state}")

        cfg = PROVIDERS[provider]
        url = f"{self.env.get("REDIRECTION_URL")}/{provider}/callback"
        client_id, client_secret = self._get_credentials(provider)

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:

                # 🔁 Token exchange
                token_data = {
                    "code": code,
                    "redirect_uri": url,
                    "client_id": client_id,
                    "client_secret": client_secret,
                }

                # OAuth standard (Google/Microsoft)
                if provider != "github":
                    token_data["grant_type"] = "authorization_code"

                token_resp = await client.post(
                    cfg["token_url"],
                    data=token_data,
                    headers={"Accept": "application/json"},
                )
                token_resp.raise_for_status()
                tokens = token_resp.json()

                access_token = tokens.get("access_token")
                if not access_token:
                    raise ValueError(f"Token invalide: {tokens}")

                # 👤 User info
                userinfo_resp = await client.get(
                    cfg["userinfo_url"],
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                userinfo_resp.raise_for_status()
                userinfo = userinfo_resp.json()

                # 📧 GitHub email fix
                email = userinfo.get("email")

                if provider == "github" and not email:
                    email_resp = await client.get(
                        cfg["emails_url"],
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
                    email_resp.raise_for_status()
                    emails = email_resp.json()
                    email = next((e["email"] for e in emails if e.get("primary")), None)

        except httpx.RequestError as e:
            raise ValueError(f"Network error: {str(e)}")from e

        # 🧠 Normalisation user
        name = userinfo.get("name") or ""
        parts = name.split()

        return {
            "provider": provider,
            "provider_uid": str(userinfo.get("sub") or userinfo.get("id")),
            "email": email,
            "first_name": userinfo.get("given_name") or (parts[0] if parts else ""),
            "last_name": userinfo.get("family_name") or (" ".join(parts[1:]) if len(parts) > 1 else ""),
            "access_token": self.security.encrypt(access_token),
            "refresh_token": self.security.encrypt(tokens.get("refresh_token") or ""),
        }