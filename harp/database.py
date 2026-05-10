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
        try:
            await conn.execute(text(
                "ALTER TABLE globalsettings ADD COLUMN verify_ssl BOOLEAN NOT NULL DEFAULT 1"
            ))
        except Exception:
            pass  # column already exists
        try:
            await conn.execute(text(
                "ALTER TABLE globalsettings ADD COLUMN technitium_token_encrypted TEXT"
            ))
        except Exception:
            pass  # column already exists
        try:
            await conn.execute(text(
                "ALTER TABLE globalsettings ADD COLUMN log_retention_days INTEGER NOT NULL DEFAULT 7"
            ))
        except Exception:
            pass  # column already exists
        # Migrate token from user table to globalsettings
        try:
            row = (await conn.execute(text(
                "SELECT technitium_token_encrypted FROM user WHERE technitium_token_encrypted IS NOT NULL LIMIT 1"
            ))).fetchone()
            if row and row[0]:
                await conn.execute(text(
                    "UPDATE globalsettings SET technitium_token_encrypted = :token"
                    " WHERE id = 1 AND technitium_token_encrypted IS NULL"
                ), {"token": row[0]})
        except Exception:
            pass
        # Seed primary LogSource from GlobalSettings if not yet present
        try:
            primary_exists = (await conn.execute(
                text("SELECT 1 FROM logsource WHERE is_primary = 1")
            )).fetchone()
            if not primary_exists:
                gs_row = (await conn.execute(
                    text("SELECT technitium_url, technitium_token_encrypted, verify_ssl FROM globalsettings WHERE id = 1")
                )).fetchone()
                if gs_row:
                    await conn.execute(text(
                        "INSERT INTO logsource (name, url, token_encrypted, verify_ssl, enabled, is_primary, created_at)"
                        " VALUES ('Primary', :url, :token, :ssl, 1, 1, CURRENT_TIMESTAMP)"
                    ), {"url": gs_row[0], "token": gs_row[1], "ssl": 1 if gs_row[2] else 0})
        except Exception:
            pass
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
