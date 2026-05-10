import asyncio
import hashlib
import logging
from datetime import datetime, timezone

import aiosqlite
import httpx

from .client.base import TechnitiumClient
from .client.logs import fetch_query_logs, _resolve_query_logger
from .config import settings as app_settings
from .crypto import decrypt_token
from .database import async_session_factory
from .logs_db import LOGS_DB_PATH
from .models import LogSource

logger = logging.getLogger(__name__)

POLL_INTERVAL = 60       # seconds between poll cycles
OVERLAP_SECONDS = 60     # re-fetch overlap to tolerate clock skew
MAX_PAGES_PER_POLL = 20  # cap per source per cycle (20 × 1000 = 20 k entries)
PER_PAGE = 1000


def _entry_hash(entry: dict) -> str:
    key = "|".join([
        entry.get("timestamp") or "",
        entry.get("qname") or "",
        entry.get("qtype") or "",
        entry.get("protocol") or "",
        entry.get("clientIpAddress") or "",
        entry.get("responseType") or "",
        entry.get("rcode") or "",
        entry.get("answer") or "",
    ])
    return hashlib.sha1(key.encode()).hexdigest()


async def _poll_source(
    source: LogSource,
    http_client: httpx.AsyncClient,
    logs_db: aiosqlite.Connection,
    retention_days: int = 7,
) -> None:
    if not source.token_encrypted:
        return

    try:
        token = decrypt_token(source.token_encrypted, app_settings.secret_key)
    except ValueError:
        logger.warning("Log poller: invalid token for source '%s'", source.name)
        return

    cursor_row = await (await logs_db.execute(
        "SELECT last_ts FROM poll_cursors WHERE source_id = ?", (source.id,)
    )).fetchone()
    last_ts: int = cursor_row[0] if cursor_row else 0

    now = datetime.now(timezone.utc)
    now_ms = int(now.timestamp() * 1000)
    retention_ms = retention_days * 24 * 3600 * 1000

    if last_ts == 0:
        # First poll: start from 24 h ago to avoid a huge initial backfill
        start_ms = now_ms - 24 * 3600 * 1000
    else:
        start_ms = max(now_ms - retention_ms, last_ts - OVERLAP_SECONDS * 1000)

    start_dt = datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc)
    client = TechnitiumClient(base_url=source.url, token=token, http_client=http_client)

    try:
        app_name, class_path = await _resolve_query_logger(client)
    except Exception as exc:
        logger.warning("Log poller: cannot resolve query logger for '%s': %s", source.name, exc)
        return

    newest_ts = last_ts
    inserted = 0

    for page in range(1, MAX_PAGES_PER_POLL + 1):
        try:
            result = await fetch_query_logs(
                client, start_dt, now,
                page=page, per_page=PER_PAGE,
                name=app_name, class_path=class_path,
            )
        except Exception as exc:
            logger.warning("Log poller: fetch failed for '%s' page %d: %s", source.name, page, exc)
            break

        entries = result.get("entries", [])
        if not entries:
            break

        rows = []
        for entry in entries:
            ts_str = entry.get("timestamp", "")
            try:
                ts = int(datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp() * 1000)
            except Exception:
                continue

            rows.append((
                source.id, ts,
                entry.get("qname") or None,
                entry.get("clientIpAddress") or None,
                entry.get("clientName") or None,
                entry.get("protocol") or None,
                entry.get("responseType") or None,
                entry.get("rcode") or None,
                entry.get("qtype") or None,
                entry.get("answer") or None,
                _entry_hash(entry),
            ))
            if ts > newest_ts:
                newest_ts = ts

        if rows:
            await logs_db.executemany(
                """INSERT OR IGNORE INTO query_log_entries (
                    source_id, ts,
                    qname, client_ip, client_name,
                    protocol, response_type, rcode, qtype, answer,
                    entry_hash
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
            inserted += len(rows)

        if page >= result.get("totalPages", 1):
            break

    if newest_ts > last_ts:
        await logs_db.execute(
            """INSERT INTO poll_cursors (source_id, last_ts) VALUES (?, ?)
               ON CONFLICT(source_id) DO UPDATE SET last_ts = excluded.last_ts
               WHERE excluded.last_ts > last_ts""",
            (source.id, newest_ts),
        )

    await logs_db.commit()

    # Retention cleanup
    cutoff_ms = now_ms - retention_ms
    await logs_db.execute(
        "DELETE FROM query_log_entries WHERE source_id = ? AND ts < ?",
        (source.id, cutoff_ms),
    )
    await logs_db.commit()

    if inserted:
        logger.debug("Log poller: '%s' +%d entries", source.name, inserted)


async def poll_all(http_client: httpx.AsyncClient) -> None:
    from sqlmodel import select
    from .models import GlobalSettings
    async with async_session_factory() as db:
        result = await db.exec(select(LogSource).where(LogSource.enabled == True))  # noqa: E712
        sources = result.all()
        gs = await db.get(GlobalSettings, 1)
        retention_days = gs.log_retention_days if gs else 7

    if not sources:
        return

    async with aiosqlite.connect(LOGS_DB_PATH) as logs_db:
        for source in sources:
            try:
                await _poll_source(source, http_client, logs_db, retention_days=retention_days)
            except Exception as exc:
                logger.warning("Log poller: error on '%s': %s", source.name, exc)


async def run_log_poller(app) -> None:
    logger.info("Log poller started (interval=%ds)", POLL_INTERVAL)
    while True:
        try:
            await poll_all(app.state.http_client)
        except Exception as exc:
            logger.warning("Log poller cycle error: %s", exc)
        await asyncio.sleep(POLL_INTERVAL)
