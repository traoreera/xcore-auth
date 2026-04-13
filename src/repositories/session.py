from __future__ import annotations
from datetime import datetime, UTC
from uuid import UUID
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from ..models import Session, EmailToken


class SessionRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        user_id: UUID,
        refresh_token_hash: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_fingerprint: str | None = None,
        geo_country: str | None = None,
        geo_city: str | None = None,
    ) -> Session:
        now = datetime.now(UTC)
        session = Session(
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            geo_country=geo_country,
            geo_city=geo_city,
            created_at=now,
            last_used_at=now,
        )
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        return session

    async def get_by_id(self, session_id: UUID) -> Session | None:
        result = await self.db.execute(
            select(Session).where(Session.id == session_id)
        )
        return result.scalar_one_or_none()

    async def get_by_token_hash(self, token_hash: str) -> Session | None:
        result = await self.db.execute(
            select(Session).where(
                Session.refresh_token_hash == token_hash,
                Session.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    async def list_user_sessions(self, user_id: UUID) -> list[Session]:
        result = await self.db.execute(
            select(Session).where(
                Session.user_id == user_id,
                Session.is_active == True,
            ).order_by(Session.last_used_at.desc())
        )
        return list(result.scalars().all())

    async def list_all_sessions(self, page: int = 1, per_page: int = 50) -> list[Session]:
        result = await self.db.execute(
            select(Session)
            .order_by(Session.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
        return list(result.scalars().all())

    async def revoke(self, session: Session, reason: str | None = None) -> None:
        session.is_active = False
        session.revoked_at = datetime.now(UTC)
        session.revoked_reason = reason
        await self.db.commit()

    async def revoke_all_user_sessions(self, user_id: UUID, except_session_id: UUID | None = None) -> int:
        q = select(Session).where(
            Session.user_id == user_id,
            Session.is_active == True,
        )
        if except_session_id:
            q = q.where(Session.id != except_session_id)

        sessions = (await self.db.execute(q)).scalars().all()
        now = datetime.now(UTC)
        count = 0
        for s in sessions:
            s.is_active = False
            s.revoked_at = now
            s.revoked_reason = "logout_all"
            count += 1
        await self.db.commit()
        return count

    async def touch(self, session: Session) -> None:
        session.last_used_at = datetime.now(UTC)
        await self.db.commit()

    async def expire_old(self) -> int:
        now = datetime.now(UTC)

        result = await self.db.execute(
            select(Session).where(
                Session.is_active == True,
                Session.expires_at < now,
            )
        )
        sessions = result.scalars().all()
        for s in sessions:
            s.is_active = False
            s.revoked_at = now
            s.revoked_reason = "expired"
        await self.db.commit()

        return len(sessions)


class EmailTokenRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        user_id: UUID,
        token_hash: str,
        type: str,
        expires_at: datetime,
    ) -> EmailToken:
        token = EmailToken(
            user_id=user_id,
            token_hash=token_hash,
            type=type,
            expires_at=expires_at,
        )
        self.db.add(token)
        await self.db.commit()
        await self.db.refresh(token)
        return token

    async def get_valid(self, token_hash: str, type: str) -> EmailToken | None:
        now = datetime.now(UTC)
        result = await self.db.execute(
            select(EmailToken).where(
                EmailToken.token_hash == token_hash,
                EmailToken.type == type,
                EmailToken.expires_at > now,
                EmailToken.used_at is None,
            )
        )
        return result.scalar_one_or_none()

    async def mark_used(self, token: EmailToken) -> None:
        token.used_at = datetime.now(UTC)
        await self.db.commit()

    async def delete_user_tokens(self, user_id: UUID, type: str) -> None:
        await self.db.execute(
            delete(EmailToken).where(
                EmailToken.user_id == user_id,
                EmailToken.type == type,
            )
        )
        await self.db.commit()
