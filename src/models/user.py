import uuid
from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel

__all__ = ("User",)


class User(SQLModel, table=True):

    uuid:  uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    username: Optional[int] = Field(nullable=False)
    email: str = Field(nullable=False)
    password_hash: str = Field(nullable=False)
    is_superuser: bool = Field(nullable=False)
    is_active: bool = Field(nullable=False)
    created_at: datetime = Field(default=datetime.utcnow(), nullable=False)