import uuid
from datetime import datetime, timedelta
from functools import lru_cache

from fastapi import Depends, HTTPException
from jose import JWTError, jwt
from passlib.hash import bcrypt
from sqlmodel import Session, select
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from src.api.v1.schemas import UserCreate, UserModel, UserUpdate
from src.core.config import JWT_ALGORITHM, JWT_EXPIRATION, JWT_SECRET_KEY
from src.db import (AbstractCache, CacheRefreshToken, get_access_cache,
                    get_cache, get_refresh_cache, get_session)
from src.models import User
from src.services import ServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    def __init__(self,
                 cache: AbstractCache,
                 access_cache: AbstractCache,
                 refresh_cash: CacheRefreshToken,
                 session: Session):
        super().__init__(cache=cache, session=session)

        self.blocked_access_tokens = access_cache
        self.active_refresh_tokens = refresh_cash

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
    def create_refresh_token(cls, user_uuid: str, jti: str):
        now = datetime.utcnow()
        payload = {
            "iat": now,
            "jti": jti,
            "type": "refresh",
            "uuid": user_uuid,
            "nbf": now,
            "exp": now + timedelta(days=30)
        }
        refresh_token = jwt.encode(payload, JWT_SECRET_KEY, JWT_ALGORITHM)
        return refresh_token

    @classmethod
    def get_uuid(cls, token: str) -> str:
        payload = jwt.decode(token, JWT_SECRET_KEY, JWT_ALGORITHM)
        return payload["uuid"]

    # ----------

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

    def get_user_by_uuid(self, user_uuid: str):
        return self.session.query(User).filter(User.uuid == user_uuid).first()

    def get_user_by_token(self, token: str):
        id_token = self.get_id_token(token)

        if self.blocked_access_tokens.get(id_token):
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Token was blocked"
            )

        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            user_data = UserModel(**payload)
        except JWTError:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
            )

        user = self.get_user_by_name(user_data.username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user.dict()

    def update_user_info(self, user: dict, data: UserUpdate) -> dict:
        statement = select(User).where(User.username == user["username"])
        results = self.session.exec(statement)
        selected_user = results.one()
        if data.username is not None:
            selected_user.username = data.username
        if data.email is not None:
            selected_user.email = data.email

        self.session.add(selected_user)
        self.session.commit()
        self.session.refresh(selected_user)
        return selected_user.dict()

    @staticmethod
    def get_id_token(token: str):
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload["jti"]

    @staticmethod
    def get_refresh_uuid_from_access_token(token: str):
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload["refresh_uuid"]

    def add_refresh_token(self, user_uuid: str, id_token: str):
        self.active_refresh_tokens.add(user_uuid, id_token)

    def block_access_token(self, id_token: str):
        self.blocked_access_tokens.set(id_token, "протух))")

    def remove_refresh_token(self, user_uuid: str, jti: str):
        current_tokens = self.active_refresh_tokens.get(user_uuid)
        current_tokens.pop(current_tokens.index(jti))
        self.active_refresh_tokens.clean(user_uuid)
        if current_tokens:
            self.active_refresh_tokens.add(user_uuid, *current_tokens)

    def remove_all_refresh_tokens(self, user_uuid):
        self.active_refresh_tokens.clean(user_uuid)

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
        access_cache: AbstractCache = Depends(get_access_cache),
        refresh_cache: CacheRefreshToken = Depends(get_refresh_cache),
        session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache,
                       access_cache=access_cache,
                       refresh_cash=refresh_cache,
                       session=session)