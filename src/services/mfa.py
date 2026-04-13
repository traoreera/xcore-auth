from __future__ import annotations
import base64
import io
import secrets
import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .security import SecurityService

_ph = PasswordHasher()
_BACKUP_COUNT = 10
_BACKUP_LEN = 8


class MFAService:
    def __init__(self, security: SecurityService):
        self.security = security

    # ── TOTP ──────────────────────────────────────────────────

    def generate_totp_setup(self, email: str, issuer: str = "XCore") -> dict:
        """Génère secret + QR code pour l'activation TOTP."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=email, issuer_name=issuer)

        # QR code en base64
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        # Backup codes en clair
        backup_codes = self._generate_backup_codes()

        return {
            "secret": secret,
            "provisioning_uri": uri,
            "qr_code_base64": qr_b64,
            "backup_codes": backup_codes,
            "backup_codes_hashed": [_ph.hash(c) for c in backup_codes],
        }

    def verify_totp(self, secret_encrypted: str, code: str) -> bool:
        """Vérifie un code TOTP (déchiffre le secret avant)."""
        try:
            secret = self.security.decrypt(secret_encrypted)
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=1)
        except Exception:
            return False

    # ── Backup codes ──────────────────────────────────────────

    def _generate_backup_codes(self) -> list[str]:
        return [secrets.token_hex(4).upper() for _ in range(_BACKUP_COUNT)]

    def verify_backup_code(self, code: str, hashed_codes: list[str]) -> int | None:
        """Retourne l'index du code utilisé, ou None si invalide."""
        for idx, hashed in enumerate(hashed_codes):
            try:
                if _ph.verify(hashed, code):
                    return idx
            except (VerifyMismatchError, Exception):
                continue
        return None

    def invalidate_backup_code(self, hashed_codes: list[str], idx: int) -> list[str]:
        """Remplace le code utilisé par une valeur invalide."""
        codes = list(hashed_codes)
        codes[idx] = "USED"
        return codes

    def count_remaining_backup_codes(self, hashed_codes: list[str]) -> int:
        return sum(1 for c in hashed_codes if c != "USED")

    # ── Encrypt/decrypt secret pour DB ────────────────────────

    def encrypt_secret(self, secret: str) -> str:
        return self.security.encrypt(secret)

    def decrypt_secret(self, encrypted: str) -> str:
        return self.security.decrypt(encrypted)
