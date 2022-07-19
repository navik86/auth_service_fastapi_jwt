from datetime import datetime, timedelta
import uuid
from functools import lru_cache
from jose import jwt

from passlib.hash import bcrypt
from fastapi import Depends
from sqlmodel import Session
from src.api.v1.schemas import UserCreate
from src.db import get_session, AbstractCache, get_cache
from src.services import ServiceMixin

from src.models import User

from src.core.config import JWT_SECRET_KEY, JWT_EXPIRATION, JWT_ALGORITHM


__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def create_access_token(cls, data: dict, refresh_uuid: str):
        jti = str(uuid.uuid4())
        payload = data.copy()
        now = datetime.utcnow()
        payload.update({"iat": now,
                        "jti": jti,
                        "type": "access",
                        "nbf": now,
                        "exp": now + timedelta(seconds=JWT_EXPIRATION),
                        "refresh_uuid": refresh_uuid})
        access_token = jwt.encode(payload, JWT_SECRET_KEY, JWT_ALGORITHM)
        return access_token

    @classmethod
    def create_refresh_token(cls, user_uuid: str):
        now = datetime.utcnow()
        jti = str(uuid.uuid4())
        exp = now + timedelta(days=30)
        payload = {
            "iat": now,
            "jti": jti,
            "type": "refresh",
            "uuid": user_uuid,
            "nbf": now,
            "exp": exp
        }
        refresh_token = jwt.encode(payload, JWT_SECRET_KEY, JWT_ALGORITHM)
        return refresh_token

    @classmethod
    def get_uuid(cls, token: str) -> str:
        payload = jwt.decode(token, JWT_SECRET_KEY, JWT_ALGORITHM)
        return payload["uuid"]

    # ----------

    def __init__(self, cache: AbstractCache, session: Session):
        super().__init__(cache=cache, session=session)

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

    def get_user_by_name(self, username: str):
        return self.session.query(User).filter(User.username == username).first()

    def authenticate_user(self, username: str, password: str):
        user = self.get_user_by_name(username)
        if not user:
            return None
        if not self.verify_password(password, user.password_hash):
            return None
        return user


@lru_cache()
def get_user_service(
        cache: AbstractCache = Depends(get_cache),
        session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache,
                       session=session)