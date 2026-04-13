# Plugin Auth - Documentation

Plugin d'authentification et d'autorisation pour Xcore fournissant une solution IAM (Identity and Access Management) complète.

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Intégration Xcore](#intégration-xcore)
- [API Reference](#api-reference)
- [Protection des routes](#protection-des-routes)
- [Communication inter-plugins](#communication-inter-plugins)
- [Tests](#tests)

## Vue d'ensemble

Le plugin `auth` fournit un système d'authentification JWT complet avec support MFA, RBAC (Role-Based Access Control), gestion de sessions, OAuth2 et audit logging. Il s'intègre nativement avec le kernel Xcore pour fournir une authentification globale à tous les plugins.

```
app/auth/
├── plugin.yaml          # Manifest plugin (permissions, ressources, env)
├── plugin.sig           # Signature HMAC pour l'exécution trustée
├── data/migrations/     # Migrations Alembic
├── src/
│   ├── main.py          # Point d'entrée (classe Plugin)
│   ├── backend.py       # XcoreAuthBackend (auth global)
│   ├── routes/          # Routeurs FastAPI
│   ├── services/        # Logique métier
│   ├── models/          # Modèles SQLAlchemy
│   ├── repositories/    # Couche d'accès données
│   └── schemas/         # Modèles Pydantic
└── tests/               # Tests unitaires et d'intégration
```

## Fonctionnalités

### Authentification
- **JWT tokens** : Access token (courte durée) + Refresh token (longue durée)
- **MFA TOTP** : Compatible Google Authenticator, avec codes de secours
- **Magic Links** : Connexion sans mot de passe par email
- **Vérification email** : Confirmation d'email avec tokens sécurisés
- **Réinitialisation mot de passe** : Flow sécurisé avec tokens à usage unique

### Autorisation (RBAC)
- **Rôles** : superadmin, admin, standard (+ rôles personnalisables)
- **Permissions** : Format `resource:action` (ex: `users:read`, `roles:write`)
- **Héritage** : Les superadmin ont toutes les permissions implicitement
- **Cache Redis** : Permissions mises en cache pour performance

### Sécurité
- **Hashage Argon2** : Pour les mots de passe
- **Vérification HIBP** : HaveIBeenPwned pour détecter les mots de passe compromis
- **Chiffrement AES-GCM** : Pour les secrets MFA et tokens sensibles
- **Rate limiting** : Limitation des tentatives de connexion
- **Fingerprints** : Détection de device/IP/géolocalisation

### OAuth2
- **Providers supportés** : Google, GitHub, Microsoft
- **Linking de comptes** : Associer OAuth à un compte existant

### Audit
- **Logging complet** : Actions d'authentification, modifications utilisateurs
- **Métriques Prometheus** : Counter pour logins, MFA, tokens, etc.

## Architecture

### Services principaux

| Service | Description |
|---------|-------------|
| `AuthService` | Inscription, login, logout, refresh, mot de passe |
| `TokenService` | Création, vérification, révocation des JWT |
| `RBACService` | Gestion des rôles et permissions |
| `MFAService` | TOTP et codes de secours |
| `SessionService` | Gestion des sessions utilisateur |
| `AuditService` | Logging des événements de sécurité |
| `PasswordService` | Hashage Argon2 + vérification HIBP |
| `SecurityService` | Chiffrement AES-GCM, tokens sécurisés |

### Modèles de données

```
User
├── id, email, password_hash, first_name, last_name
├── is_active, is_verified, mfa_enabled
├── mfa_secret (chiffré), mfa_backup_codes (hashés)
└── roles[], sessions[], audit_logs[]

Role
├── id, name, description, is_system
└── permissions[]

Permission
├── id, name, resource, action
└── roles[]

Session
├── id, user_id, refresh_token_hash, expires_at
├── device_fingerprint, ip_address, geo_location
└── is_active

AuditLog
├── id, user_id, action, resource, success
├── ip_address, user_agent, metadata
└── timestamp
```

## Installation

### 1. Prérequis

- Python 3.12+
- PostgreSQL (production) ou SQLite (dev)
- Redis (pour cache et blacklists)
- Docker (optionnel, pour services locaux)

### 2. Démarrer les services

```bash
# PostgreSQL
docker run -d -p 5432:5432 \
  -e POSTGRES_USER=auth \
  -e POSTGRES_PASSWORD=auth \
  -e POSTGRES_DB=auth \
  postgres:16-alpine

# Redis
docker run -d -p 6379:6379 redis:7-alpine
```

### 3. Configuration environnement

Créer `conf/.env` :

```bash
# Base de données
DATABASE_URL=postgresql+asyncpg://auth:auth@localhost:5432/auth

# Cache
CACHE_DB_REDIS=redis://localhost:6379/0

# JWT (RS256 - générer des clés ou utiliser celles fournies)
JWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----

JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

JWT_ALGORITHM=RS256
ACCESS_TOKEN_TTL=900          # 15 minutes
REFRESH_TOKEN_TTL=604800      # 7 jours

# Chiffrement (32 bytes pour AES-256-GCM)
ENCRYPTION_KEY=votre-cle-de-32-caracteres!

# OAuth (optionnel)
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...

# SMTP (pour emails)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=votre-email@gmail.com
SMTP_PASSWORD=votre-mot-de-passe-app
FROM_EMAIL=noreply@votreapp.com

# Sécurité
PWNED_CHECK_ENABLED=true
APP_BASE_URL=http://localhost:8000
```

### 4. Générer les clés JWT

```bash
# Clés RSA pour JWT
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Mettre le contenu dans JWT_PRIVATE_KEY et JWT_PUBLIC_KEY
```

## Configuration

### plugin.yaml

Le fichier `plugin.yaml` définit les métadonnées et permissions du plugin :

```yaml
name: auth
version: 0.1.0
author: team
description: "IAM centralisé — auth, users, RBAC, sessions, audit"
execution_mode: trusted
framework_version: "==2.0.0"
entry_point: src/main.py

permissions:
  - resource: "db.*"
    actions: ["read", "write"]
    effect: allow
  - resource: "cache.*"
    actions: ["read", "write"]
    effect: allow

env:
  DATABASE_URL: ${DATABASE_URL}
  JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY}
  # ... autres variables
```

### Integration Xcore

Dans `conf/integration.yaml` :

```yaml
kernel:
  services:
    db:
      driver: xcore.services.database
      config:
        url: ${DATABASE_URL}
    cache:
      driver: xcore.services.cache
      config:
        backend: redis
        url: ${CACHE_DB_REDIS}

plugins:
  - name: auth
    path: app/auth
    enabled: true
```

## Intégration Xcore

### 1. Démarrage automatique

Le plugin s'enregistre automatiquement au boot via `on_load()` :

```python
async def on_load(self):
    # 1. Création des tables
    async with self.db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # 2. Seed des rôles système
    await RBACService(self.db, self.cache).seed_system_roles()
    
    # 3. Enregistrement du backend d'auth global
    from .backend import XcoreAuthBackend
    register_auth_backend(XcoreAuthBackend(self.db, self.cache, env))
    
    # 4. Job de nettoyage des sessions
    @self.sched.cron("0 * * * *")
    async def cleanup_sessions():
        ...
```

### 2. Utilisation dans d'autres plugins

#### Protection avec `@require_permission`

Une fois le plugin auth chargé, tous les plugins peuvent utiliser le décorateur `@require_permission` de Xcore :

```python
from xcore.sdk import TrustedBase
from xcore.decorators import require_permission
from fastapi import APIRouter

class MonPlugin(TrustedBase):
    async def on_load(self):
        pass
    
    def get_router(self):
        router = APIRouter()
        
        @router.get("/admin-only")
        @require_permission("users:read")  # Protection RBAC
        async def admin_endpoint():
            return {"message": "Accès autorisé"}
        
        return router
```

#### Vérification manuelle des permissions

```python
from xcore.kernel.api.auth import get_auth_backend

async def ma_fonction():
    backend = get_auth_backend()
    
    # Vérifier un token
    payload = await backend.decode_token(token)
    if payload:
        user_id = payload.sub
        roles = payload.roles
        permissions = payload.permissions
    
    # Vérifier une permission
    has_access = await backend.has_permission(payload, "users:write")
```

#### Appel IPC au plugin auth

```python
# Vérifier un token depuis un autre plugin
result = await self.ctx.ipc.call("auth", "verify_token", {
    "token": "eyJhbGciOiJSUzI1NiIs..."
})
# → {valid: true, user: {...}}

# Vérifier une permission
result = await self.ctx.ipc.call("auth", "has_permission", {
    "user_id": "uuid-de-l-utilisateur",
    "permission": "roles:write"
})
# → {allowed: true}

# Récupérer un utilisateur
result = await self.ctx.ipc.call("auth", "get_user", {
    "user_id": "uuid-de-l-utilisateur"
})
# → {id: ..., email: ..., roles: [...]}
```

## API Reference

### Routes d'authentification

| Méthode | Route | Description | Auth requise |
|---------|-------|-------------|--------------|
| POST | `/register` | Créer un compte | Non |
| POST | `/login` | Connexion | Non |
| POST | `/logout` | Déconnexion | Oui |
| POST | `/refresh` | Rafraîchir tokens | Non (refresh token) |
| POST | `/forgot-password` | Demander reset | Non |
| POST | `/reset-password` | Réinitialiser mot de passe | Non (token) |
| POST | `/verify-email` | Vérifier email | Non (token) |
| POST | `/resend-verification` | Renvoyer email | Non |
| POST | `/magic-link` | Demander magic link | Non |
| GET | `/magic-login` | Connexion via magic link | Non (token) |

### Routes MFA

| Méthode | Route | Description | Auth requise |
|---------|-------|-------------|--------------|
| POST | `/mfa/enable` | Activer MFA | Oui |
| POST | `/mfa/verify` | Vérifier code MFA | Oui (ou mfa_token) |
| POST | `/mfa/disable` | Désactiver MFA | Oui |
| GET | `/mfa/backup-codes` | Voir codes de secours | Oui |

### Routes utilisateurs

| Méthode | Route | Description | Permission |
|---------|-------|-------------|------------|
| GET | `/me` | Profil courant | Auth |
| PATCH | `/me` | Modifier profil | Auth |
| PATCH | `/me/password` | Changer mot de passe | Auth |
| DELETE | `/me` | Supprimer compte | Auth |
| GET | `/users/` | Liste utilisateurs | users:list |
| POST | `/users/` | Créer utilisateur | users:write |
| GET | `/users/{id}` | Détail utilisateur | users:read |
| PATCH | `/users/{id}` | Modifier utilisateur | users:write |
| DELETE | `/users/{id}` | Supprimer utilisateur | users:delete |
| POST | `/users/{id}/roles` | Assigner rôle | users:write |
| DELETE | `/users/{id}/roles/{role_id}` | Retirer rôle | users:write |

### Routes RBAC

| Méthode | Route | Description | Permission |
|---------|-------|-------------|------------|
| GET | `/roles` | Liste rôles | roles:read |
| POST | `/roles` | Créer rôle | roles:write |
| GET | `/roles/{id}` | Détail rôle | roles:read |
| PATCH | `/roles/{id}` | Modifier rôle | roles:write |
| DELETE | `/roles/{id}` | Supprimer rôle | roles:write |
| POST | `/roles/{id}/permissions` | Ajouter permission | roles:write |
| DELETE | `/roles/{id}/permissions/{perm_id}` | Retirer permission | roles:write |
| GET | `/permissions` | Liste permissions | roles:read |
| POST | `/permissions` | Créer permission | roles:write |
| DELETE | `/permissions/{id}` | Supprimer permission | roles:write |

### Routes sessions

| Méthode | Route | Description | Auth |
|---------|-------|-------------|------|
| GET | `/sessions` | Mes sessions | Oui |
| DELETE | `/sessions/{id}` | Révoquer session | Oui |
| DELETE | `/sessions` | Révoquer toutes sessions | Oui |

### Routes OAuth

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/oauth/{provider}/authorize` | URL d'autorisation |
| GET | `/oauth/{provider}/callback` | Callback OAuth |
| POST | `/oauth/{provider}/link` | Lier à compte existant |

### Routes audit

| Méthode | Route | Description | Permission |
|---------|-------|-------------|------------|
| GET | `/audit-logs` | Logs d'audit | audit:read |
| GET | `/audit-logs/me` | Mes actions | Auth |

## Protection des routes

### Dans le plugin auth

Utiliser les dépendances FastAPI :

```python
from fastapi import Depends
from .routes.deps import get_current_user, require_permission

@router.get("/admin-only")
async def admin_only(
    user=Depends(require_permission("roles:write"))
):
    return {"message": "Admin only"}

@router.get("/me")
async def get_profile(user=Depends(get_current_user)):
    return {"id": user.id, "email": user.email}
```

### Dans d'autres plugins (via Xcore)

```python
from xcore.decorators import require_permission
from xcore.kernel.api.auth import get_auth_backend

# Méthode 1: Décorateur
@router.get("/sensitive")
@require_permission("users:read")
async def sensitive_data():
    return {"data": "sensible"}

# Méthode 2: Vérification manuelle
@router.get("/check")
async def check_access(request: Request):
    backend = get_auth_backend()
    token = await backend.extract_token(request)
    payload = await backend.decode_token(token)
    
    if await backend.has_permission(payload, "users:write"):
        return {"access": "granted"}
    return {"access": "denied"}
```

## Communication inter-plugins

Le plugin auth expose 3 actions IPC :

### Actions disponibles

| Action | Payload | Retour |
|--------|---------|--------|
| `verify_token` | `{token: string}` | `{valid: bool, user: object}` |
| `has_permission` | `{user_id: uuid, permission: string}` | `{allowed: bool}` |
| `get_user` | `{user_id: uuid}` | `{id, email, roles, ...}` |

### Exemples d'utilisation

```python
# Depuis un autre plugin

class MonPlugin(TrustedBase):
    async def on_load(self):
        # S'abonner aux événements auth
        self.ctx.events.on("auth_user.loaded", self._on_auth_ready)
    
    async def _on_auth_ready(self, data):
        print(f"Auth plugin chargé: {data}")
    
    async def protected_operation(self, user_token: str):
        # Vérifier le token
        result = await self.ctx.ipc.call("auth", "verify_token", {
            "token": user_token
        })
        
        if not result.get("valid"):
            raise Exception("Token invalide")
        
        user = result.get("user")
        
        # Vérifier une permission
        perm_check = await self.ctx.ipc.call("auth", "has_permission", {
            "user_id": user["id"],
            "permission": "monplugin:action"
        })
        
        if perm_check.get("allowed"):
            # Exécuter l'action protégée
            pass
```

## Tests

### Configuration des tests

```bash
# Installer les dépendances de test
uv add --dev pytest pytest-asyncio httpx

# Exécuter les tests
uv run pytest app/auth/tests/ -v
```

### Structure des tests

```
tests/
├── conftest.py              # Fixtures pytest
├── test_auth_service.py     # Tests unitaires services
├── test_auth_route_flows.py # Tests d'intégration routes
└── test_xcore_plugin_rbac_injection.py  # Tests Xcore
```

### Exemple de test

```python
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_register_login_flow(client: AsyncClient):
    # Register
    resp = await client.post("/register", json={
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User"
    })
    assert resp.status_code == 201
    
    # Login
    resp = await client.post("/login", json={
        "email": "test@example.com",
        "password": "SecurePass123!"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
```

## Sécurité

### Bonnes pratiques

1. **JWT** : Utiliser RS256 en production (asymétrique), ne pas commit les clés privées
2. **MFA** : Toujours activer MFA pour les comptes admin
3. **Mots de passe** : Vérification HIBP activée par défaut
4. **Rate limiting** : Configuré à 200 req/min par défaut
5. **Sessions** : Nettoyage automatique des sessions expirées toutes les heures
6. **Audit** : Toutes les actions sensibles sont loguées

### Variables sensibles

```env
# ── Base de données ───────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/xcore_db

# ── JWT RS256 ────────────────────────────────────────────────
# Générer : openssl genrsa -out private.pem 2048
#           openssl rsa -in private.pem -pubout -out public.pem
JWT_PRIVATE_KEY= ./conf/private.pem
JWT_PUBLIC_KEY=  ./conf/public.pem
JWT_ALGORITHM=RS256
ACCESS_TOKEN_TTL=900        # 15 minutes
REFRESH_TOKEN_TTL=2592000   # 30 jours

# ── Chiffrement AES-256 (Fernet) ─────────────────────────────
# Générer : python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=pMg_xD933bfmPHxs0lSx2B1k7xHN4kFXdTxBi-gw6ps=

# ── OAuth2 ───────────────────────────────────────────────────
REDIRECTION_URL=http://localhost:8000/app/auth/oauth # URL de redirection après authentification OAuth2 http://localhost:8000/app/auth/oauth/{provider}/callback
GOOGLE_CLIENT_ID= ...
GOOGLE_CLIENT_SECRET= ...


GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...

# ── SMTP ─────────────────────────────────────────────────────
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=noreply@example.com
SMTP_PASSWORD=

# ── Application ───────────────────────────────────────────────
APP_BASE_URL=https://yourapp.com
PWNED_CHECK_ENABLED=true

```

Ne jamais commit dans git :
- `JWT_PRIVATE_KEY`
- `ENCRYPTION_KEY`
- `SMTP_PASSWORD`
- Clés OAuth (`*_CLIENT_SECRET`)

Utiliser des variables d'environnement ou un vault.

---

**Version** : 0.1.0  
**Auteur** : Team  
**License** : Proprietary
