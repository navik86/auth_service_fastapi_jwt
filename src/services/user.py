from functools import lru_cache

from passlib.hash import bcrypt
from fastapi import Depends
from sqlmodel import Session
from src.api.v1.schemas import UserCreate
from src.db import get_session, AbstractCache, get_cache
from src.services import ServiceMixin

from src.models import User


__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    def __init__(self, cache: AbstractCache, session: Session):
        super().__init__(cache=cache, session=session)

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    def create_user(self, user: UserCreate) -> dict:
        password_hash = self.hash_password(user.password)
        new_user = User(
            username=user.username,
            password_hash=password_hash,
            email=user.email
        )
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        return new_user.dict()


@lru_cache()
def get_user_service(
        cache: AbstractCache = Depends(get_cache),
        session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache,
                       session=session)