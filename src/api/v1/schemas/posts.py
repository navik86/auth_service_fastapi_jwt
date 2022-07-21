from datetime import datetime

from pydantic import BaseModel

__all__ = (
    "PostModel",
    "PostCreate",
    "PostListResponse",
)

from typing import List

# from pydantic.validators import UUID


class PostBase(BaseModel):
    title: str
    description: str


class PostCreate(PostBase):
    ...


class PostModel(PostBase):
    id: int
    created_at: datetime
    # user_id: UUID


class PostListResponse(BaseModel):
    posts: List[PostModel] = []
