from __future__ import annotations
import hashlib
import hmac
import secrets
from cryptography.fernet import Fernet


class SecurityService:
    """Utilitaires cryptographiques partagés entre les services."""

    def __init__(self, encryption_key: str):
        self._fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)

    # ── Hachage sécurisé (tokens, refresh tokens) ─────────────

    def hash_token(self, token: str) -> str:
        """SHA-256 d'un token — pour stockage en base."""
        return hashlib.sha256(token.encode()).hexdigest()

    def verify_token_hash(self, token: str, token_hash: str) -> bool:
        return hmac.compare_digest(self.hash_token(token), token_hash)

    # ── Génération de tokens aléatoires ───────────────────────

    def generate_token(self, nbytes: int = 32) -> str:
        """Token URL-safe aléatoire (utilisé pour email tokens, etc.)."""
        return secrets.token_urlsafe(nbytes)

    def generate_otp(self, length: int = 6) -> str:
        """Code OTP numérique."""
        return "".join([str(secrets.randbelow(10)) for _ in range(length)])

    # ── Chiffrement symétrique AES-256 (Fernet) ───────────────

    def encrypt(self, plaintext: str) -> str:
        """Chiffre une chaîne — pour MFA secrets, OAuth tokens."""
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Déchiffre une chaîne."""
        return self._fernet.decrypt(ciphertext.encode()).decode()

    # ── Device fingerprint ────────────────────────────────────

    def fingerprint(self, ip: str, user_agent: str) -> str:
        data = f"{ip}:{user_agent}"
        return hashlib.sha256(data.encode()).hexdigest()[:64]
