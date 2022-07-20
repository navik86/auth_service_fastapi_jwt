from datetime import datetime, timedelta
import uuid
from functools import lru_cache
from jose import jwt, JWTError

from passlib.hash import bcrypt
from fastapi import Depends, HTTPException
from sqlmodel import Session, select
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from src.api.v1.schemas import UserCreate, UserModel, UserUpdate
from src.db import (AbstractCache,
                    CacheRefreshToken,
                    get_cache,
                    get_session,
                    get_access_cache,
                    get_refresh_cache)
from src.services import ServiceMixin

from src.models import User

from src.core.config import JWT_SECRET_KEY, JWT_EXPIRATION, JWT_ALGORITHM


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
    def create_refresh_token(cls, user_uuid: str):
        now = datetime.utcnow()
        jti = str(uuid.uuid4())
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
        uuid = self.get_uuid(token)

        if self.blocked_access_tokens.get(uuid):
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

    def add_refresh_token(self, token: str):
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        self.active_refresh_tokens.add(payload["uuid"], payload["jti"])

    def block_access_token(self, uuid: str):
        self.blocked_access_tokens.set(uuid, "blocked")

    def remove_refresh_token(self, uuid: str, jti: str):
        current_token = self.active_refresh_tokens.get(uuid)
        current_token.pop(current_token.index(jti))
        self.active_refresh_tokens.clean(uuid)
        if current_token:
            self.active_refresh_tokens.add(uuid, *current_token)

    def remove_all_refresh_tokens(self, uuid):
        self.active_refresh_tokens.clean(uuid)

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