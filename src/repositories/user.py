from __future__ import annotations
from uuid import UUID
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from ..models import User, OAuthAccount


class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, user_id: UUID) -> User | None:
        result = await self.db.execute(
            select(User)
            .where(User.id == user_id)
            .options(
                selectinload(User.oauth_accounts),
                selectinload(User.user_roles),
            )
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        result = await self.db.execute(
            select(User)
            .where(User.email == email.lower())
            .options(
                selectinload(User.oauth_accounts),
                selectinload(User.user_roles),
            )
        )
        return result.scalar_one_or_none()

    async def create(self, **kwargs) -> User:
        if "email" in kwargs:
            kwargs["email"] = kwargs["email"].lower()
        user = User(**kwargs)
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def update(self, user: User, **kwargs) -> User:
        for k, v in kwargs.items():
            setattr(user, k, v)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def delete(self, user: User) -> None:
        await self.db.delete(user)
        await self.db.commit()

    async def list_paginated(
        self,
        page: int = 1,
        per_page: int = 50,
        search: str | None = None,
    ) -> tuple[list[User], int]:
        q = select(User).options(
            selectinload(User.oauth_accounts),
            selectinload(User.user_roles),
        )
        if search:
            term = f"%{search}%"
            q = q.where(
                or_(
                    User.email.ilike(term),
                    User.first_name.ilike(term),
                    User.last_name.ilike(term),
                )
            )
        count_q = select(func.count()).select_from(q.subquery())

        q = q.offset((page - 1) * per_page).limit(per_page)

        rows = (await self.db.execute(q)).scalars().all()
        total = (await self.db.execute(count_q)).scalar_one()
        return list(rows), total

    async def get_oauth_account(self, provider: str, provider_uid: str) -> OAuthAccount | None:
        result = await self.db.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_uid == provider_uid,
            )
        )
        return result.scalar_one_or_none()

    async def add_oauth_account(self, user: User, **kwargs) -> OAuthAccount:
        account = OAuthAccount(user_id=user.id, **kwargs)
        self.db.add(account)
        await self.db.commit()
        return account

    async def increment_failed_login(self, user: User) -> None:
        user.failed_login_count += 1
        await self.db.commit()

    async def reset_failed_login(self, user: User) -> None:
        user.failed_login_count = 0
        user.locked_until = None
        await self.db.commit()
