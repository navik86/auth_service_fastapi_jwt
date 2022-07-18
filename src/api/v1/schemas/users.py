import uuid as uuid_pkg

from datetime import datetime

from pydantic import BaseModel


__all__ = (
    "UserCreate",
    "UserModel",
)


class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    password: str


class UserModel(UserBase):
    uuid: uuid_pkg.UUID
    created_at: datetime
    is_superuser: bool
    is_active: bool
#
#
# class UserUpdate(BaseModel):
#     username: str = None
#     email: EmailStr = None
#
#
# class Token(BaseModel):
#     access_token: str
#     refresh_token: str