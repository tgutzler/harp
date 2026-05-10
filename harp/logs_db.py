from pathlib import Path

import aiosqlite

from .config import settings


def _logs_db_path() -> str:
    url = settings.database_url
    if "///" in url:
        main = url.split("///")[1]
        return str(Path(main).parent / "logs.db")
    return "./logs.db"


LOGS_DB_PATH = _logs_db_path()


async def init_logs_db() -> None:
    async with aiosqlite.connect(LOGS_DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS query_log_entries (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id     INTEGER NOT NULL,
                ts            INTEGER NOT NULL,
                qname         TEXT,
                client_ip     TEXT,
                client_name   TEXT,
                protocol      TEXT,
                response_type TEXT,
                rcode         TEXT,
                qtype         TEXT,
                answer        TEXT,
                entry_hash    TEXT NOT NULL,
                UNIQUE(source_id, entry_hash)
            );

            CREATE INDEX IF NOT EXISTS idx_ql_ts
                ON query_log_entries(ts);
            CREATE INDEX IF NOT EXISTS idx_ql_source_ts
                ON query_log_entries(source_id, ts);
            CREATE INDEX IF NOT EXISTS idx_ql_qname_ts
                ON query_log_entries(lower(qname), ts);
            CREATE INDEX IF NOT EXISTS idx_ql_client_ts
                ON query_log_entries(lower(client_ip), ts);
            CREATE INDEX IF NOT EXISTS idx_ql_response_ts
                ON query_log_entries(response_type, ts);

            CREATE TABLE IF NOT EXISTS poll_cursors (
                source_id INTEGER PRIMARY KEY,
                last_ts   INTEGER NOT NULL DEFAULT 0
            );
        """)
        await db.commit()
