from __future__ import annotations
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EmailService:
    """
    Service email qui utilise soit l'extension Xcore (ext.email) si disponible,
    soit un envoi SMTP direct en fallback.
    """

    def __init__(self, env: dict, xcore_email_service=None):
        self._env = env
        self._xcore_email = xcore_email_service
        self._base_url = env.get("APP_BASE_URL", "http://localhost")

        # Config SMTP pour le fallback
        self._host = env.get("SMTP_HOST", "localhost")
        self._port = int(env.get("SMTP_PORT", 587))
        self._user = env.get("SMTP_USER", "")
        self._password = env.get("SMTP_PASSWORD", "")

    async def send_verification_email(self, email: str, token: str, first_name: str) -> None:
        link = f"{self._base_url}/verify-email?token={token}"
        subject = "Vérifiez votre adresse email"
        html = f"""
        <h2>Bonjour {first_name},</h2>
        <p>Cliquez sur le lien ci-dessous pour vérifier votre adresse email :</p>
        <p><a href="{link}">{link}</a></p>
        <p>Ce lien expire dans 1 heure.</p>
        """

        if self._xcore_email:
            await self._xcore_email.send(to=email, subject=subject, body=html, is_html=True)
        else:
            await self._send_smtp(email, subject, html)

    async def send_reset_password_email(self, email: str, token: str, first_name: str) -> None:
        link = f"{self._base_url}/reset-password?token={token}"
        subject = "Réinitialisation de votre mot de passe"
        html = f"""
        <h2>Bonjour {first_name},</h2>
        <p>Cliquez sur le lien ci-dessous pour réinitialiser votre mot de passe :</p>
        <p><a href="{link}">{link}</a></p>
        <p>Ce lien expire dans 1 heure. Si vous n'avez pas demandé cela, ignorez cet email.</p>
        """

        if self._xcore_email:
            await self._xcore_email.send(to=email, subject=subject, body=html, is_html=True)
        else:
            await self._send_smtp(email, subject, html)

    async def send_magic_link_email(self, email: str, token: str, redirect_url: str | None = None) -> None:
        dest = redirect_url or self._base_url
        link = f"{self._base_url}/magic-login?token={token}&redirect={dest}"
        subject = "Votre lien de connexion"
        html = f"""
        <h2>Connexion sans mot de passe</h2>
        <p>Cliquez sur le lien ci-dessous pour vous connecter :</p>
        <p><a href="{link}">{link}</a></p>
        <p>Ce lien expire dans 15 minutes et ne peut être utilisé qu'une seule fois.</p>
        """

        if self._xcore_email:
            await self._xcore_email.send(to=email, subject=subject, body=html, is_html=True)
        else:
            await self._send_smtp(email, subject, html)

    async def send_welcome_email(self, email: str, first_name: str, temp_password: str | None = None) -> None:
        subject = "Bienvenue !"
        body = f"<h2>Bienvenue {first_name} !</h2><p>Votre compte a été créé.</p>"
        if temp_password:
            body += f"<p>Mot de passe temporaire : <strong>{temp_password}</strong></p>"
            body += "<p>Veuillez le changer à votre première connexion.</p>"

        if self._xcore_email:
            await self._xcore_email.send(to=email, subject=subject, body=body, is_html=True)
        else:
            await self._send_smtp(email, subject, body)

    async def send_email_otp(self, email: str, code: str, first_name: str) -> None:
        subject = "Votre code de vérification"
        html = f"""
        <h2>Bonjour {first_name},</h2>
        <p>Votre code de vérification est : <strong style="font-size:24px">{code}</strong></p>
        <p>Ce code expire dans 10 minutes.</p>
        """

        if self._xcore_email:
            await self._xcore_email.send(to=email, subject=subject, body=html, is_html=True)
        else:
            await self._send_smtp(email, subject, html)

    # ── Fallback SMTP direct ─────────────────────────────────────────

    async def _send_smtp(self, to: str, subject: str, html: str) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._user
        msg["To"] = to
        msg.attach(MIMEText(html, "html"))
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(self._host, self._port) as server:
                server.ehlo()
                server.starttls(context=context)
                if self._user and self._password:
                    server.login(self._user, self._password)
                server.sendmail(self._user, to, msg.as_string())
        except Exception as exc:
            import logging
            logging.getLogger("auth_user.email").error(f"Erreur envoi email à {to}: {exc}")
