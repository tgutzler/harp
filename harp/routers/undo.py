from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from ..client.base import TechnitiumClient
from ..config import settings as app_settings
from ..crypto import decrypt_token
from ..database import get_db
from ..dependencies import require_auth, get_global_settings
from ..models import ChangeLog, Collection, CollectionSubnet, GlobalSettings, Host, User
from ..sync import build_fqdn, sync_host, unsync_host

router = APIRouter(prefix="/undo")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _get_http_client(request: Request) -> httpx.AsyncClient:
    try:
        return request.app.state.http_client
    except AttributeError:
        return httpx.AsyncClient(timeout=10.0)


async def _try_client(request: Request, gs: GlobalSettings) -> Optional[TechnitiumClient]:
    if not gs.technitium_token_encrypted:
        return None
    try:
        token = decrypt_token(gs.technitium_token_encrypted, app_settings.secret_key)
        return TechnitiumClient(
            base_url=gs.technitium_url,
            token=token,
            http_client=_get_http_client(request),
        )
    except ValueError:
        return None


async def _undo_host(db: AsyncSession, entry: ChangeLog, client: Optional[TechnitiumClient], zone: str) -> None:
    if entry.operation == "create":
        host = await db.get(Host, entry.entity_id)
        if not host:
            return
        collection = await db.get(Collection, host.collection_id)
        if client and collection:
            try:
                await unsync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, zone)
            except Exception:
                pass
        await db.delete(host)

    elif entry.operation == "update":
        host = await db.get(Host, entry.entity_id)
        if not host or not entry.before_state:
            return
        old = entry.before_state
        collection = await db.get(Collection, host.collection_id)
        if client and collection:
            try:
                await unsync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, zone)
            except Exception:
                pass
        host.hostname = old["hostname"]
        host.ip_address = old["ip_address"]
        host.mac_address = old["mac_address"]
        if client and collection:
            try:
                warning = await sync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, zone)
                host.sync_status = "error" if warning else "synced"
                host.last_error = warning
            except Exception as e:
                host.sync_status = "error"
                host.last_error = str(e)
        else:
            host.sync_status = "pending"
            host.last_error = "No API token configured"
        db.add(host)

    elif entry.operation == "delete":
        if not entry.before_state:
            return
        old = entry.before_state
        collection = await db.get(Collection, old["collection_id"])
        host = Host(
            collection_id=old["collection_id"],
            hostname=old["hostname"],
            ip_address=old["ip_address"],
            mac_address=old["mac_address"],
            sync_status="pending",
        )
        db.add(host)
        await db.flush()
        if client and collection:
            try:
                warning = await sync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, zone)
                host.sync_status = "error" if warning else "synced"
                host.last_error = warning
            except Exception as e:
                host.sync_status = "error"
                host.last_error = str(e)
        db.add(host)


async def _undo_collection(db: AsyncSession, entry: ChangeLog, client: Optional[TechnitiumClient], zone: str) -> None:
    if entry.operation == "create":
        collection = await db.get(Collection, entry.entity_id)
        if not collection:
            return
        hosts_result = await db.exec(select(Host).where(Host.collection_id == collection.id))
        for host in hosts_result.all():
            if client:
                try:
                    await unsync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, zone)
                except Exception:
                    pass
            await db.delete(host)
        subnets_result = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == collection.id))
        for sn in subnets_result.all():
            await db.delete(sn)
        await db.delete(collection)

    elif entry.operation == "update":
        collection = await db.get(Collection, entry.entity_id)
        if not collection or not entry.before_state:
            return
        old = entry.before_state
        old_subdomain = collection.subdomain
        collection.name = old["name"]
        collection.description = old["description"]
        collection.subdomain = old["subdomain"]
        subnets_result = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == collection.id))
        for sn in subnets_result.all():
            await db.delete(sn)
        for cidr in old.get("subnets", []):
            db.add(CollectionSubnet(collection_id=collection.id, cidr=cidr))
        db.add(collection)
        if old_subdomain != collection.subdomain and client:
            hosts_result = await db.exec(select(Host).where(Host.collection_id == collection.id))
            for host in hosts_result.all():
                try:
                    await unsync_host(client, host.hostname, host.ip_address, host.mac_address, old_subdomain, zone)
                except Exception:
                    pass
                try:
                    warning = await sync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, zone)
                    host.sync_status = "error" if warning else "synced"
                    host.last_error = warning
                except Exception as e:
                    host.sync_status = "error"
                    host.last_error = str(e)
                db.add(host)

    elif entry.operation == "delete":
        if not entry.before_state:
            return
        old = entry.before_state
        collection = Collection(
            name=old["name"],
            description=old["description"],
            subdomain=old["subdomain"],
        )
        db.add(collection)
        await db.flush()
        for cidr in old.get("subnets", []):
            db.add(CollectionSubnet(collection_id=collection.id, cidr=cidr))


def _entry_label(entry: ChangeLog) -> tuple[str, str]:
    """Returns (button_label, tooltip) for the undo button."""
    state = entry.after_state if entry.operation == "create" else entry.before_state
    name = (state or {}).get("hostname") or (state or {}).get("name") or "unknown"
    verb = {"create": "add", "update": "edit", "delete": "delete"}.get(entry.operation, entry.operation)
    noun = "host" if entry.entity_type == "host" else "collection"
    return f"{verb} {noun}", f'{verb} {noun} "{name}"'


@router.get("/count", response_class=HTMLResponse)
async def undo_count(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    session_id = request.session.get("session_id")
    entry = None
    count = 0
    if session_id:
        count_result = await db.exec(
            select(func.count(ChangeLog.id))
            .where(ChangeLog.session_id == session_id)
            .where(ChangeLog.undone == False)  # noqa: E712
        )
        count = count_result.one()
        if count > 0:
            latest = await db.exec(
                select(ChangeLog)
                .where(ChangeLog.session_id == session_id)
                .where(ChangeLog.undone == False)  # noqa: E712
                .order_by(ChangeLog.id.desc())
                .limit(1)
            )
            entry = latest.one_or_none()

    inner = ""
    if entry:
        label, tooltip = _entry_label(entry)
        inner = f"""<button hx-post="/undo" hx-target="body" hx-swap="outerHTML" class="undo-btn" title="{tooltip}">↩ {label}</button>"""
    return HTMLResponse(
        f'<div id="undo-bar" hx-get="/undo/count" hx-trigger="undoUpdated from:body" hx-swap="outerHTML">{inner}</div>'
    )


@router.post("")
async def undo_last(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
):
    session_id = request.session.get("session_id")
    if not session_id:
        return HTMLResponse("", headers={"HX-Redirect": "/collections"})

    result = await db.exec(
        select(ChangeLog)
        .where(ChangeLog.session_id == session_id)
        .where(ChangeLog.undone == False)  # noqa: E712
        .order_by(ChangeLog.id.desc())
        .limit(1)
    )
    entry = result.one_or_none()
    if not entry:
        return HTMLResponse("", headers={"HX-Redirect": str(request.headers.get("HX-Current-URL", "/collections"))})

    client = await _try_client(request, gs)

    if entry.entity_type == "host":
        await _undo_host(db, entry, client, gs.zone)
    elif entry.entity_type == "collection":
        await _undo_collection(db, entry, client, gs.zone)

    entry.undone = True
    db.add(entry)
    await db.commit()

    redirect_to = request.headers.get("HX-Current-URL", "/collections")
    return HTMLResponse("", headers={"HX-Redirect": redirect_to})
