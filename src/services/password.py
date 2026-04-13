from __future__ import annotations
import hashlib
import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


class PasswordService:
    def __init__(self, pwned_check_enabled: bool = True):
        self._pwned = pwned_check_enabled

    def hash(self, password: str) -> str:
        return _ph.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        try:
            return _ph.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        return _ph.check_needs_rehash(password_hash)

    async def is_pwned(self, password: str) -> bool:
        """Vérifie le mot de passe contre HaveIBeenPwned (k-anonymity)."""
        if not self._pwned:
            return False
        try:
            sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"Add-Padding": "true"},
                )
                resp.raise_for_status()
            for line in resp.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count) > 0
        except Exception:
            pass  # Ne jamais bloquer l'inscription pour une erreur réseau
        return False
