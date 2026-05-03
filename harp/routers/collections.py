from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from ..client.base import TechnitiumClient
from ..client.dhcp import normalize_mac
from ..config import settings as app_settings
from ..crypto import decrypt_token
from ..database import get_db
from ..dependencies import base_context, get_global_settings, require_auth
from ..exceptions import TechnitiumAPIError, TechnitiumInvalidToken, TechnitiumUnavailable
from ..changelog import collection_snapshot, host_snapshot, log_change
from ..models import Collection, CollectionSubnet, GlobalSettings, Host, User
from ..sync import build_fqdn, sync_host, unsync_host

router = APIRouter(prefix="/collections")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _parse_subnets(text: str) -> list[str]:
    return [s.strip() for s in text.replace(",", "\n").splitlines() if s.strip()]


def _get_http_client(request: Request) -> httpx.AsyncClient:
    try:
        return request.app.state.http_client
    except AttributeError:
        return httpx.AsyncClient(timeout=10.0)


async def _try_client(
    request: Request,
    user: User,
    gs: GlobalSettings,
) -> Optional[TechnitiumClient]:
    if not user.technitium_token_encrypted:
        return None
    try:
        token = decrypt_token(user.technitium_token_encrypted, app_settings.secret_key)
        return TechnitiumClient(
            base_url=gs.technitium_url,
            token=token,
            http_client=_get_http_client(request),
        )
    except ValueError:
        return None


async def _do_sync(client, host: Host, collection: Collection, zone: str) -> tuple[str, Optional[str]]:
    """Returns (sync_status, last_error)."""
    try:
        warning = await sync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, zone)
        return ("error", warning) if warning else ("synced", None)
    except TechnitiumUnavailable as e:
        return "error", f"Cannot reach Technitium: {e}"
    except TechnitiumInvalidToken:
        return "error", "Invalid API token"
    except TechnitiumAPIError as e:
        return "error", e.message
    except Exception as e:
        return "error", str(e)


# ── Collections list ──────────────────────────────────────────────────────────

@router.get("")
async def collections_index(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
):
    ctx = await base_context(request, db)
    result = await db.exec(select(Collection).order_by(Collection.name))
    collections = result.all()

    coll_data = []
    for c in collections:
        sn = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == c.id))
        hosts = await db.exec(select(Host).where(Host.collection_id == c.id))
        host_list = hosts.all()
        statuses = {h.sync_status for h in host_list}
        if "error" in statuses:
            status = "error"
        elif "pending" in statuses:
            status = "pending"
        elif host_list:
            status = "synced"
        else:
            status = "no hosts"
        coll_data.append({"collection": c, "subnets": sn.all(), "host_count": len(host_list), "status": status})

    ctx["coll_data"] = coll_data
    ctx["zone"] = gs.zone
    return templates.TemplateResponse(request, "collections/index.html", ctx)


@router.get("/new")
async def new_collection_page(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx = await base_context(request, db)
    return templates.TemplateResponse(request, "collections/form.html", ctx)


@router.post("")
async def create_collection(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    name: str = Form(...),
    description: str = Form(""),
    subdomain: str = Form(""),
    subnets_text: str = Form(""),
):
    collection = Collection(
        name=name.strip(),
        description=description.strip() or None,
        subdomain=subdomain.strip().lower() or None,
    )
    db.add(collection)
    await db.flush()

    subnets = _parse_subnets(subnets_text)
    for cidr in subnets:
        db.add(CollectionSubnet(collection_id=collection.id, cidr=cidr))

    session_id = request.session.get("session_id")
    if session_id:
        await log_change(db, session_id, "collection", collection.id, "create",
                         after_state={"name": collection.name, "description": collection.description,
                                      "subdomain": collection.subdomain, "subnets": subnets})
    await db.commit()
    return RedirectResponse(f"/collections/{collection.id}", 303)


# ── Collection detail ─────────────────────────────────────────────────────────

@router.get("/{collection_id}")
async def collection_detail(
    request: Request,
    collection_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
):
    collection = await db.get(Collection, collection_id)
    if not collection:
        return RedirectResponse("/collections", 303)

    ctx = await base_context(request, db)
    sn = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == collection_id))
    hosts = await db.exec(select(Host).where(Host.collection_id == collection_id).order_by(Host.hostname))

    ctx["collection"] = collection
    ctx["subnets"] = sn.all()
    ctx["hosts"] = hosts.all()
    ctx["zone"] = gs.zone
    return templates.TemplateResponse(request, "collections/detail.html", ctx)


@router.get("/{collection_id}/edit")
async def edit_collection_page(
    request: Request,
    collection_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    collection = await db.get(Collection, collection_id)
    if not collection:
        return RedirectResponse("/collections", 303)

    ctx = await base_context(request, db)
    sn = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == collection_id))
    ctx["collection"] = collection
    ctx["subnets"] = sn.all()
    return templates.TemplateResponse(request, "collections/form.html", ctx)


@router.post("/{collection_id}/edit")
async def update_collection(
    request: Request,
    collection_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    name: str = Form(...),
    description: str = Form(""),
    subdomain: str = Form(""),
    subnets_text: str = Form(""),
):
    collection = await db.get(Collection, collection_id)
    if not collection:
        return RedirectResponse("/collections", 303)

    existing_subnets = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == collection_id))
    before = collection_snapshot(collection, existing_subnets.all())

    old_subdomain = collection.subdomain
    collection.name = name.strip()
    collection.description = description.strip() or None
    collection.subdomain = subdomain.strip().lower() or None

    new_subnets = _parse_subnets(subnets_text)
    existing = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == collection_id))
    for sn in existing.all():
        await db.delete(sn)
    for cidr in new_subnets:
        db.add(CollectionSubnet(collection_id=collection_id, cidr=cidr))

    session_id = request.session.get("session_id")
    if session_id:
        after = {"name": collection.name, "description": collection.description,
                 "subdomain": collection.subdomain, "subnets": new_subnets}
        await log_change(db, session_id, "collection", collection.id, "update",
                         before_state=before, after_state=after)
    db.add(collection)
    await db.commit()

    # Resync all hosts if subdomain changed
    if old_subdomain != collection.subdomain:
        client = await _try_client(request, user, gs)
        if client:
            hosts = await db.exec(select(Host).where(Host.collection_id == collection_id))
            for host in hosts.all():
                await unsync_host(client, host.hostname, host.ip_address, host.mac_address, old_subdomain, gs.zone)
                status, error = await _do_sync(client, host, collection, gs.zone)
                host.sync_status = status
                host.last_error = error
                db.add(host)
            await db.commit()

    return RedirectResponse(f"/collections/{collection_id}", 303)


@router.delete("/{collection_id}", response_class=HTMLResponse)
async def delete_collection(
    request: Request,
    collection_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
):
    collection = await db.get(Collection, collection_id)
    if not collection:
        return HTMLResponse("")

    subnets_result = await db.exec(select(CollectionSubnet).where(CollectionSubnet.collection_id == collection_id))
    subnets = subnets_result.all()
    before = collection_snapshot(collection, subnets)

    client = await _try_client(request, user, gs)
    hosts = await db.exec(select(Host).where(Host.collection_id == collection_id))
    for host in hosts.all():
        if client:
            await unsync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, gs.zone)
        await db.delete(host)

    for sn in subnets:
        await db.delete(sn)

    session_id = request.session.get("session_id")
    if session_id:
        await log_change(db, session_id, "collection", collection.id, "delete", before_state=before)
    await db.delete(collection)
    await db.commit()
    return HTMLResponse("", headers={"HX-Trigger": "undoUpdated"})


# ── Quick-add host (collection picker) ───────────────────────────────────────

@router.get("/hosts/new")
async def new_host_page(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    collection_id: Optional[int] = None,
):
    ctx = await base_context(request, db)
    result = await db.exec(select(Collection).order_by(Collection.name))
    ctx["collections"] = result.all()
    ctx["selected_collection_id"] = collection_id
    ctx["zone"] = gs.zone
    return templates.TemplateResponse(request, "collections/host_form.html", ctx)


@router.post("/hosts/new")
async def create_host_global(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    collection_id: int = Form(...),
    hostname: str = Form(...),
    ip_address: str = Form(...),
    mac_address: str = Form(...),
):
    collection = await db.get(Collection, collection_id)
    if not collection:
        request.session["flash"] = {"type": "error", "message": "Collection not found"}
        return RedirectResponse("/collections/hosts/new", 303)

    host = Host(
        collection_id=collection_id,
        hostname=hostname.strip().lower(),
        ip_address=ip_address.strip(),
        mac_address=normalize_mac(mac_address),
        sync_status="pending",
    )
    db.add(host)
    await db.flush()

    client = await _try_client(request, user, gs)
    if client:
        status, error = await _do_sync(client, host, collection, gs.zone)
        host.sync_status = status
        host.last_error = error
    else:
        host.sync_status = "pending"
        host.last_error = "No API token configured"

    db.add(host)
    session_id = request.session.get("session_id")
    if session_id:
        await log_change(db, session_id, "host", host.id, "create", after_state=host_snapshot(host))
    await db.commit()

    return RedirectResponse(f"/collections/{collection_id}", 303)


# ── Hosts ─────────────────────────────────────────────────────────────────────

@router.post("/{collection_id}/hosts", response_class=HTMLResponse)
async def add_host(
    request: Request,
    collection_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    hostname: str = Form(...),
    ip_address: str = Form(...),
    mac_address: str = Form(...),
):
    collection = await db.get(Collection, collection_id)
    if not collection:
        return HTMLResponse("Collection not found", status_code=404)

    host = Host(
        collection_id=collection_id,
        hostname=hostname.strip().lower(),
        ip_address=ip_address.strip(),
        mac_address=normalize_mac(mac_address),
        sync_status="pending",
    )
    db.add(host)
    await db.flush()

    client = await _try_client(request, user, gs)
    if client:
        status, error = await _do_sync(client, host, collection, gs.zone)
        host.sync_status = status
        host.last_error = error
    else:
        host.sync_status = "pending"
        host.last_error = "No API token configured"

    db.add(host)
    session_id = request.session.get("session_id")
    if session_id:
        await log_change(db, session_id, "host", host.id, "create", after_state=host_snapshot(host))
    await db.commit()
    await db.refresh(host)

    fqdn = build_fqdn(host.hostname, collection.subdomain, gs.zone)
    return templates.TemplateResponse(request, "collections/_host_row.html", {
        "host": host,
        "collection": collection,
        "fqdn": fqdn,
    }, headers={"HX-Trigger": "undoUpdated"})


@router.get("/{collection_id}/hosts/{host_id}/row", response_class=HTMLResponse)
async def host_row(
    request: Request,
    collection_id: int,
    host_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    show_collection: bool = False,
):
    host = await db.get(Host, host_id)
    collection = await db.get(Collection, collection_id)
    if not host or not collection or host.collection_id != collection_id:
        return HTMLResponse("")
    fqdn = build_fqdn(host.hostname, collection.subdomain, gs.zone)
    return templates.TemplateResponse(request, "collections/_host_row.html", {
        "host": host, "collection": collection, "fqdn": fqdn,
        "show_collection": show_collection,
    })


@router.get("/{collection_id}/hosts/{host_id}/edit", response_class=HTMLResponse)
async def edit_host_form(
    request: Request,
    collection_id: int,
    host_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    show_collection: bool = False,
):
    host = await db.get(Host, host_id)
    collection = await db.get(Collection, collection_id)
    if not host or not collection or host.collection_id != collection_id:
        return HTMLResponse("")
    fqdn = build_fqdn(host.hostname, collection.subdomain, gs.zone)
    return templates.TemplateResponse(request, "collections/_host_edit_row.html", {
        "host": host, "collection": collection, "fqdn": fqdn,
        "show_collection": show_collection,
    })


@router.post("/{collection_id}/hosts/{host_id}/edit", response_class=HTMLResponse)
async def update_host(
    request: Request,
    collection_id: int,
    host_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    hostname: str = Form(...),
    ip_address: str = Form(...),
    mac_address: str = Form(...),
    show_collection: str = Form("false"),
):
    host = await db.get(Host, host_id)
    collection = await db.get(Collection, collection_id)
    if not host or not collection or host.collection_id != collection_id:
        return HTMLResponse("")

    before = host_snapshot(host)

    client = await _try_client(request, user, gs)
    if client:
        await unsync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, gs.zone)

    host.hostname = hostname.strip().lower()
    host.ip_address = ip_address.strip()
    host.mac_address = normalize_mac(mac_address)

    if client:
        status, error = await _do_sync(client, host, collection, gs.zone)
        host.sync_status = status
        host.last_error = error
    else:
        host.sync_status = "pending"
        host.last_error = "No API token configured"

    db.add(host)
    session_id = request.session.get("session_id")
    if session_id:
        await log_change(db, session_id, "host", host.id, "update",
                         before_state=before, after_state=host_snapshot(host))
    await db.commit()
    await db.refresh(host)

    fqdn = build_fqdn(host.hostname, collection.subdomain, gs.zone)
    return templates.TemplateResponse(request, "collections/_host_row.html", {
        "host": host, "collection": collection, "fqdn": fqdn,
        "show_collection": show_collection.lower() == "true",
    }, headers={"HX-Trigger": "undoUpdated"})


@router.post("/{collection_id}/hosts/{host_id}/sync", response_class=HTMLResponse)
async def resync_host(
    request: Request,
    collection_id: int,
    host_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    show_collection: bool = False,
):
    host = await db.get(Host, host_id)
    if not host or host.collection_id != collection_id:
        return HTMLResponse("")

    collection = await db.get(Collection, collection_id)
    if not collection:
        return HTMLResponse("")

    client = await _try_client(request, user, gs)
    if client:
        status, error = await _do_sync(client, host, collection, gs.zone)
        host.sync_status = status
        host.last_error = error
    else:
        host.sync_status = "pending"
        host.last_error = "No API token configured"

    db.add(host)
    await db.commit()
    await db.refresh(host)

    fqdn = build_fqdn(host.hostname, collection.subdomain, gs.zone)
    return templates.TemplateResponse(request, "collections/_host_row.html", {
        "host": host,
        "collection": collection,
        "fqdn": fqdn,
        "show_collection": show_collection,
    })


@router.delete("/{collection_id}/hosts/{host_id}", response_class=HTMLResponse)
async def delete_host(
    request: Request,
    collection_id: int,
    host_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
):
    host = await db.get(Host, host_id)
    if not host or host.collection_id != collection_id:
        return HTMLResponse("")

    before = host_snapshot(host)
    collection = await db.get(Collection, collection_id)
    client = await _try_client(request, user, gs)
    if client and collection:
        await unsync_host(client, host.hostname, host.ip_address, host.mac_address, collection.subdomain, gs.zone)

    session_id = request.session.get("session_id")
    if session_id:
        await log_change(db, session_id, "host", host.id, "delete", before_state=before)
    await db.delete(host)
    await db.commit()
    return HTMLResponse("", headers={"HX-Trigger": "undoUpdated"})
