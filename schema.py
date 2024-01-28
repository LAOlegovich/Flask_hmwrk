from abc import ABC
from typing import Optional

import pydantic


class AbstractUser(pydantic.BaseModel, ABC):
    name: str
    password: str

    @classmethod
    def secure_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError(f"Minimal length of password is 8")
        return v


class CreateUser(pydantic.BaseModel):
    name: str
    password: str


class UpdateUser(pydantic.BaseModel):
    name: Optional[str]= None
    password: Optional[str]=None


class CreateSticker(pydantic.BaseModel):
    name: str
    description: str
    owner: int

class UpdateSticker(pydantic.BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[int] = None




