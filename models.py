import atexit
import datetime
import os
import sqlalchemy as sq
from sqlalchemy import DateTime, String, Integer, create_engine, func, Column
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, relationship
from typing import List

POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "secret")
POSTGRES_USER = os.getenv("POSTGRES_USER", "app")
POSTGRES_DB = os.getenv("POSTGRES_DB", "app")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5431")

PG_DSN = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

engine = create_engine(PG_DSN)
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False
    )
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    registration_time: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    sticker: Mapped[List["Sticker"]] = relationship(back_populates= "user")

    @property
    def json(self):
        return {
            "name": self.name,
            "registration_time": self.registration_time.isoformat(),
        }



class Sticker(Base):

    __tablename__ = "app_sticker"

    id: Mapped[int] = mapped_column(primary_key= True)
    name: Mapped[str] = mapped_column(String(50), unique= True, index= True, nullable= False)
    description: Mapped[str] = mapped_column (String(300), nullable= False)
    create_at: Mapped[datetime.datetime] = mapped_column(DateTime,server_default= func.now(), server_onupdate= func.now())
    owner: Mapped[int] = mapped_column(sq.ForeignKey("app_users.id"), nullable= False)
    user: Mapped["User"] = relationship(back_populates= "sticker")

    @property
    def json(self):
        return {
            "id":self.id,
            "name":self.name,
            "description":self.description,
            "owner_user": self.user.json
        }



Base.metadata.create_all(bind=engine)

atexit.register(engine.dispose)
