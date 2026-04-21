# Intégration XFlow — Plugin Auth

Ce plugin gère l'identité, les permissions et la gestion des sessions utilisateur au sein de l'écosystème XCore.

## ⚡ Actions IPC

| Action | Qualified Name | Entrée (Payload) | Sortie |
| :--- | :--- | :--- | :--- |
| **Verify Token** | `auth.verify.user.token` | `{"token": string}` | `{"valid": bool, "user": UserOutWithPermissions}` |
| **Verify Permission** | `auth.user.permission.verify` | `{"user_id": uuid, "permission": string}` | `{"allowed": bool}` |
| **Search User** | `auth.search.user` | `{"user_id": uuid}` | `UserOut` |
| **Register User** | `auth.register_user` | `RegisterRequest` | `RegisterResponse` |
| **Forgot Password** | `auth.user.forgot.password` | `{"email": string}` | `{"msg": string}` |
| **Verify Email** | `auth.verify.user.email` | `{"token": string}` | `{"msg": string}` |

---

## 📦 Détail des Objets (Schemas)

### `UserOutWithPermissions`
C'est l'objet retourné lors de la vérification d'un token.
- `id`: (uuid) Identifiant unique.
- `email`: (string) Email de l'utilisateur.
- `first_name`: (string) Prénom.
- `last_name`: (string) Nom.
- `is_active`: (bool) Si le compte est activé.
- `roles`: (array[string]) Liste des noms de rôles (ex: `["admin", "standard"]`).
- `permissions`: (array[string]) Liste des permissions dénormalisées (ex: `["users:read", "task:create"]`).

### `RegisterRequest`
- `email`: (string, requis) Email valide.
- `password`: (string, requis) Min 12 caractères, 1 majuscule, 1 chiffre, 1 spécial.
- `first_name`: (string, requis) Prénom.
- `last_name`: (string, requis) Nom.

### `SessionOutAdmin`
- `id`: (uuid) ID de la session.
- `user_id`: (uuid) Propriétaire.
- `ip_address`: (string) Adresse IP de connexion.
- `user_agent`: (string) Navigateur/App utilisé.
- `geo_country`: (string) Code pays (ISO).
- `is_active`: (bool) Si la session est toujours valide.
- `created_at`: (datetime) Date de création.
- `expires_at`: (datetime) Date d'expiration.

## 📡 Événements (Event Bus)

- `auth.get.user.ids` (Écouté) : Retourne une liste de tous les UUIDs utilisateurs.
- `auth_user.loaded` (Émis) : `{ "plugin": "auth_user", "version": "0.1.0" }`.
- `auth.sessions.expired` (Émis) : `{ "count": integer }` Nombre de sessions nettoyées.
