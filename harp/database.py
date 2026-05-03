from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import SQLModel, text

from .config import settings

engine = create_async_engine(settings.database_url, echo=False)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def create_db_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        try:
            await conn.execute(text(
                "ALTER TABLE collection ADD COLUMN blocking_enabled BOOLEAN NOT NULL DEFAULT 1"
            ))
        except Exception:
            pass  # column already exists


async def get_db():
    async with async_session_factory() as session:
        yield session
