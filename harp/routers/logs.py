import json
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from ..database import get_db
from ..dependencies import base_context, require_auth
from ..logs_db import LOGS_DB_PATH
from ..models import Collection, GlobalSettings, Host, LogSource, User
from ..sync import build_fqdn

router = APIRouter(prefix="/logs")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

_HOUR_OPTIONS = [
    (1,   "1h"),
    (6,   "6h"),
    (24,  "24h"),
    (48,  "2d"),
    (168, "7d"),
]


def _window(hours: int) -> tuple[int, int]:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    return now_ms - hours * 3_600_000, now_ms


def _row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()}


@router.get("")
async def dashboard(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    hours: int = 24,
):
    ctx = await base_context(request, db)
    hours = max(1, min(hours, 168))
    start_ms, now_ms = _window(hours)

    sources = (await db.exec(select(LogSource))).all()

    stats: dict = {}
    async with aiosqlite.connect(LOGS_DB_PATH) as ldb:
        ldb.row_factory = aiosqlite.Row

        async def scalar(sql, params=()):
            row = await (await ldb.execute(sql, params)).fetchone()
            return row[0] if row else 0

        async def fetchall(sql, params=()):
            rows = await (await ldb.execute(sql, params)).fetchall()
            return [_row_to_dict(r) for r in rows]

        stats["total"]   = await scalar("SELECT COUNT(*) FROM query_log_entries WHERE ts BETWEEN ? AND ?", (start_ms, now_ms))
        stats["blocked"] = await scalar(
            "SELECT COUNT(*) FROM query_log_entries WHERE ts BETWEEN ? AND ? AND response_type IN ('Blocked','BlockedEDNS')",
            (start_ms, now_ms),
        )
        stats["blocked_pct"] = round(stats["blocked"] / stats["total"] * 100, 1) if stats["total"] else 0.0
        stats["clients"] = await scalar("SELECT COUNT(DISTINCT lower(client_ip)) FROM query_log_entries WHERE ts BETWEEN ? AND ?", (start_ms, now_ms))
        stats["domains"] = await scalar("SELECT COUNT(DISTINCT lower(qname)) FROM query_log_entries WHERE ts BETWEEN ? AND ? AND qname IS NOT NULL", (start_ms, now_ms))

        stats["top_domains"] = await fetchall(
            "SELECT qname, COUNT(*) cnt FROM query_log_entries WHERE ts BETWEEN ? AND ? AND qname IS NOT NULL"
            " GROUP BY lower(qname) ORDER BY cnt DESC LIMIT 10",
            (start_ms, now_ms),
        )
        stats["top_blocked"] = await fetchall(
            "SELECT qname, COUNT(*) cnt FROM query_log_entries WHERE ts BETWEEN ? AND ? AND qname IS NOT NULL"
            " AND response_type IN ('Blocked','BlockedEDNS') GROUP BY lower(qname) ORDER BY cnt DESC LIMIT 10",
            (start_ms, now_ms),
        )
        stats["top_clients"] = await fetchall(
            "SELECT client_ip, MAX(client_name) client_name, COUNT(*) cnt"
            " FROM query_log_entries WHERE ts BETWEEN ? AND ? AND client_ip IS NOT NULL"
            " GROUP BY lower(client_ip) ORDER BY cnt DESC LIMIT 10",
            (start_ms, now_ms),
        )

        if hours <= 1:
            bucket_ms = 300_000
        elif hours <= 6:
            bucket_ms = 900_000
        elif hours <= 48:
            bucket_ms = 3_600_000
        else:
            bucket_ms = 86_400_000
        raw_tl = await fetchall(
            "SELECT source_id, (ts/?) * ? bucket, COUNT(*) total,"
            " SUM(CASE WHEN response_type IN ('Blocked','BlockedEDNS') THEN 1 ELSE 0 END) blocked"
            " FROM query_log_entries WHERE ts BETWEEN ? AND ?"
            " GROUP BY source_id, bucket ORDER BY source_id, bucket",
            (bucket_ms, bucket_ms, start_ms, now_ms),
        )
        all_buckets = sorted({r["bucket"] for r in raw_tl})
        total_by = {(r["source_id"], r["bucket"]): r["total"] for r in raw_tl}
        blocked_by = {(r["source_id"], r["bucket"]): r["blocked"] for r in raw_tl}
        seen_sids = sorted({r["source_id"] for r in raw_tl})
        source_by_id_map = {s.id: s for s in sources}
        stats["timeline"] = {
            "buckets": all_buckets,
            "series": [
                {
                    "name": source_by_id_map[sid].name if sid in source_by_id_map else f"Source {sid}",
                    "allowed": [total_by.get((sid, b), 0) - blocked_by.get((sid, b), 0) for b in all_buckets],
                    "blocked": [blocked_by.get((sid, b), 0) for b in all_buckets],
                }
                for sid in seen_sids
            ],
        }
        stats["qtypes"] = await fetchall(
            "SELECT qtype, COUNT(*) cnt FROM query_log_entries WHERE ts BETWEEN ? AND ? AND qtype IS NOT NULL"
            " GROUP BY qtype ORDER BY cnt DESC LIMIT 8",
            (start_ms, now_ms),
        )
        stats["response_types"] = await fetchall(
            "SELECT response_type, COUNT(*) cnt FROM query_log_entries WHERE ts BETWEEN ? AND ? AND response_type IS NOT NULL"
            " GROUP BY response_type ORDER BY cnt DESC",
            (start_ms, now_ms),
        )

    # Resolve client IPs to FQDNs: prefer HARP hosts table, fall back to Technitium-recorded name
    client_ips = [r["client_ip"] for r in stats["top_clients"] if r.get("client_ip")]
    if client_ips:
        gs = await db.get(GlobalSettings, 1)
        zone = gs.zone if gs else ""
        hosts = (await db.exec(select(Host).where(Host.ip_address.in_(client_ips)))).all()
        col_ids = {h.collection_id for h in hosts}
        cols = {c.id: c for c in (await db.exec(select(Collection).where(Collection.id.in_(col_ids)))).all()}
        hosts_by_ip = {
            h.ip_address: build_fqdn(h.hostname, cols[h.collection_id].subdomain if h.collection_id in cols else None, zone)
            for h in hosts
        }
    else:
        hosts_by_ip = {}
    for row in stats["top_clients"]:
        ip = row.get("client_ip", "")
        row["resolved_name"] = hosts_by_ip.get(ip) or row.get("client_name") or None

    ctx.update({
        "stats": stats,
        "sources": sources,
        "hours": hours,
        "hour_options": _HOUR_OPTIONS,
        "timeline_json": json.dumps(stats["timeline"]),
        "qtypes_json": json.dumps(stats["qtypes"]),
        "response_types_json": json.dumps(stats["response_types"]),
    })
    return templates.TemplateResponse(request, "logs/dashboard.html", ctx)


async def _resolve_client_names(ips: list[str], db: AsyncSession) -> dict[str, str]:
    if not ips:
        return {}
    gs = await db.get(GlobalSettings, 1)
    zone = gs.zone if gs else ""
    hosts = (await db.exec(select(Host).where(Host.ip_address.in_(ips)))).all()
    col_ids = {h.collection_id for h in hosts if h.collection_id}
    cols = {c.id: c for c in (await db.exec(select(Collection).where(Collection.id.in_(col_ids)))).all()} if col_ids else {}
    return {
        h.ip_address: build_fqdn(h.hostname, cols[h.collection_id].subdomain if h.collection_id in cols else None, zone)
        for h in hosts
    }


@router.get("/analysis")
async def analysis(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    hours: int = 24,
    qname: str = "",
    client: str = "",
    blocked: int = 0,
):
    ctx = await base_context(request, db)
    hours = max(1, min(hours, 168))
    start_ms, now_ms = _window(hours)
    mode = "domain" if qname else "client"

    resolved_client_name: str | None = None
    if mode == "client":
        names = await _resolve_client_names([client], db)
        resolved_client_name = names.get(client)
        if not resolved_client_name:
            async with aiosqlite.connect(LOGS_DB_PATH) as ldb:
                ldb.row_factory = aiosqlite.Row
                row = await (await ldb.execute(
                    "SELECT MAX(client_name) FROM query_log_entries"
                    " WHERE lower(client_ip) = ? AND client_name IS NOT NULL LIMIT 1",
                    (client.lower(),),
                )).fetchone()
                if row and row[0]:
                    resolved_client_name = row[0]

    async with aiosqlite.connect(LOGS_DB_PATH) as ldb:
        ldb.row_factory = aiosqlite.Row

        async def fetchall(sql, params=()):
            rows = await (await ldb.execute(sql, params)).fetchall()
            return [_row_to_dict(r) for r in rows]

        if mode == "domain":
            qname_lc = qname.lower()
            blocked_clause = "AND response_type IN ('Blocked','BlockedEDNS')" if blocked else ""

            pie_data = await fetchall(
                f"SELECT response_type label, COUNT(*) cnt FROM query_log_entries"
                f" WHERE ts BETWEEN ? AND ? AND lower(qname) = ? {blocked_clause}"
                f" AND response_type IS NOT NULL GROUP BY response_type ORDER BY cnt DESC",
                (start_ms, now_ms, qname_lc),
            )
            top_list = await fetchall(
                f"SELECT client_ip, MAX(client_name) client_name, COUNT(*) cnt,"
                f" SUM(CASE WHEN response_type IN ('Blocked','BlockedEDNS') THEN 1 ELSE 0 END) blocked"
                f" FROM query_log_entries WHERE ts BETWEEN ? AND ? AND lower(qname) = ? {blocked_clause}"
                f" AND client_ip IS NOT NULL GROUP BY lower(client_ip) ORDER BY cnt DESC LIMIT 10",
                (start_ms, now_ms, qname_lc),
            )
            names = await _resolve_client_names([r["client_ip"] for r in top_list if r.get("client_ip")], db)
            for row in top_list:
                row["resolved_name"] = names.get(row.get("client_ip", "")) or row.get("client_name") or None

            entries = await fetchall(
                f"SELECT source_id, ts, datetime(ts/1000,'unixepoch') timestamp, qname, client_ip, client_name,"
                f" protocol, response_type, rcode, qtype, answer"
                f" FROM query_log_entries WHERE ts BETWEEN ? AND ? AND lower(qname) = ? {blocked_clause}"
                f" ORDER BY ts DESC LIMIT 50",
                (start_ms, now_ms, qname_lc),
            )

        else:  # client
            client_lc = client.lower()

            pie_data = await fetchall(
                "SELECT CASE WHEN response_type IN ('Blocked','BlockedEDNS') THEN 'Blocked' ELSE 'Allowed' END label,"
                " COUNT(*) cnt FROM query_log_entries"
                " WHERE ts BETWEEN ? AND ? AND lower(client_ip) = ?"
                " GROUP BY label ORDER BY cnt DESC",
                (start_ms, now_ms, client_lc),
            )
            top_list = await fetchall(
                "SELECT qname, COUNT(*) cnt,"
                " SUM(CASE WHEN response_type IN ('Blocked','BlockedEDNS') THEN 1 ELSE 0 END) blocked"
                " FROM query_log_entries WHERE ts BETWEEN ? AND ? AND lower(client_ip) = ? AND qname IS NOT NULL"
                " GROUP BY lower(qname) ORDER BY cnt DESC LIMIT 10",
                (start_ms, now_ms, client_lc),
            )
            entries = await fetchall(
                "SELECT source_id, ts, datetime(ts/1000,'unixepoch') timestamp, qname, client_ip, client_name,"
                " protocol, response_type, rcode, qtype, answer"
                " FROM query_log_entries WHERE ts BETWEEN ? AND ? AND lower(client_ip) = ?"
                " ORDER BY ts DESC LIMIT 50",
                (start_ms, now_ms, client_lc),
            )

    sources = (await db.exec(select(LogSource))).all()
    source_by_id = {s.id: s for s in sources}

    ctx.update({
        "mode": mode,
        "qname": qname,
        "client": client,
        "blocked": blocked,
        "resolved_client_name": resolved_client_name,
        "pie_data": pie_data,
        "pie_json": json.dumps(pie_data),
        "top_list": top_list,
        "entries": entries,
        "hours": hours,
        "hour_options": _HOUR_OPTIONS,
        "sources": sources,
        "source_by_id": source_by_id,
    })
    return templates.TemplateResponse(request, "logs/analysis.html", ctx)


@router.get("/queries")
async def query_log(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    hours: int = 24,
    source_id: int = 0,
    status: str = "",
    qname: str = "",
    client: str = "",
):
    ctx = await base_context(request, db)
    hours = max(1, min(hours, 168))
    page  = max(1, page)
    start_ms, now_ms = _window(hours)
    per_page = 50

    sources = (await db.exec(select(LogSource))).all()
    source_by_id = {s.id: s for s in sources}

    clauses = ["ts BETWEEN ? AND ?"]
    params: list = [start_ms, now_ms]

    if source_id:
        clauses.append("source_id = ?")
        params.append(source_id)
    if status == "blocked":
        clauses.append("response_type IN ('Blocked','BlockedEDNS')")
    elif status:
        clauses.append("response_type = ?")
        params.append(status)
    if qname:
        clauses.append("qname LIKE ?")
        params.append(f"%{qname}%")
    if client:
        clauses.append("(client_ip LIKE ? OR client_name LIKE ?)")
        params += [f"%{client}%", f"%{client}%"]

    where = "WHERE " + " AND ".join(clauses)

    async with aiosqlite.connect(LOGS_DB_PATH) as ldb:
        ldb.row_factory = aiosqlite.Row

        total_row = await (await ldb.execute(
            f"SELECT COUNT(*) FROM query_log_entries {where}", params
        )).fetchone()
        total = total_row[0] if total_row else 0

        rows = await (await ldb.execute(
            f"SELECT source_id, ts, datetime(ts/1000,'unixepoch') timestamp, qname, client_ip, client_name,"
            f" protocol, response_type, rcode, qtype, answer"
            f" FROM query_log_entries {where}"
            f" ORDER BY ts DESC LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page],
        )).fetchall()
        entries = [_row_to_dict(r) for r in rows]

    total_pages = max(1, (total + per_page - 1) // per_page)

    ctx.update({
        "entries": entries,
        "sources": sources,
        "source_by_id": source_by_id,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "hours": hours,
        "hour_options": _HOUR_OPTIONS,
        "source_id": source_id,
        "status": status,
        "qname": qname,
        "client": client,
    })
    return templates.TemplateResponse(request, "logs/queries.html", ctx)
