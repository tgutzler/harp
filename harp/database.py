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
        try:
            await conn.execute(text(
                "ALTER TABLE collection ADD COLUMN block_as_nxdomain BOOLEAN NOT NULL DEFAULT 1"
            ))
        except Exception:
            pass  # column already exists
        # Normalize stored MACs to lowercase colon format (aa:bb:cc:dd:ee:ff)
        result = await conn.execute(text("SELECT id, mac_address FROM host"))
        rows = result.fetchall()
        for row_id, mac in rows:
            if mac:
                clean = mac.strip().lower().replace("-", "").replace(":", "").replace(".", "")
                normalized = ":".join(clean[i : i + 2] for i in range(0, 12, 2))
                if normalized != mac:
                    await conn.execute(
                        text("UPDATE host SET mac_address = :mac WHERE id = :id"),
                        {"mac": normalized, "id": row_id},
                    )


async def get_db():
    async with async_session_factory() as session:
        yield session
