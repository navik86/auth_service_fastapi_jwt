from datetime import datetime

from pydantic import BaseModel

from typing import List

__all__ = (
    "UserModel",
    "UserCreate",
)


class UserBase(BaseModel):
    username: str
    email: str
    password: str


class UserCreate(UserBase):
    ...


class UserModel(UserBase):
    id: int
    created_at: datetime
