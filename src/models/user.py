import uuid as uuid_pkg
from datetime import datetime

from sqlalchemy import Column, String
from sqlmodel import Field, SQLModel

__all__ = ("User",)


class User(SQLModel, table=True):

    uuid:  uuid_pkg.UUID = Field(
        default_factory=uuid_pkg.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    username: str = Field(sa_column=Column("username", String, unique=True))
    email: str = Field(sa_column=Column("email", String, unique=True))
    password_hash: str = Field(nullable=False)
    is_superuser: bool = Field(nullable=False)
    is_active: bool = Field(nullable=False)
    created_at: datetime = Field(default=datetime.utcnow(), nullable=False)