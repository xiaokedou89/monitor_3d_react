from typing import Any, Literal

from pydantic import BaseModel, Field


class Page(BaseModel):
    total: int
    page: int
    page_size: int = Field(alias="pageSize")
    items: list[dict[str, Any]]


class ConfigPayload(BaseModel):
    payload: dict[str, Any]


class NoticeIn(BaseModel):
    kind: Literal["notice", "ticket"] = "notice"
    category: Literal["attack", "violation", "blocked", "system"] = "system"
    title: str = Field(min_length=1, max_length=200)
    detail: str = Field(default="", max_length=4000)
