from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Form, Request
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
from ..models import Collection, DiscoveredHost, GlobalSettings, Host, User
from ..sync import build_fqdn, sync_host, unsync_host

router = APIRouter(prefix="/discovery")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


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


@router.get("")
async def discovery_index(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
):
    ctx = await base_context(request, db)
    result = await db.exec(
        select(DiscoveredHost)
        .where(DiscoveredHost.dismissed == False)  # noqa: E712
        .order_by(DiscoveredHost.created_at.desc())
    )
    discoveries = result.all()

    collections_result = await db.exec(select(Collection).order_by(Collection.name))
    collections = collections_result.all()

    ctx["discoveries"] = discoveries
    ctx["collections"] = collections
    ctx["zone"] = gs.zone
    return templates.TemplateResponse(request, "discovery/index.html", ctx)


@router.post("/{discovery_id}/dismiss", response_class=HTMLResponse)
async def dismiss_discovery(
    discovery_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    discovery = await db.get(DiscoveredHost, discovery_id)
    if discovery:
        discovery.dismissed = True
        db.add(discovery)
        await db.commit()
    return HTMLResponse("")


@router.get("/{discovery_id}/import")
async def import_form(
    request: Request,
    discovery_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
):
    discovery = await db.get(DiscoveredHost, discovery_id)
    if not discovery or discovery.dismissed:
        return RedirectResponse("/discovery", 303)

    ctx = await base_context(request, db)
    collections_result = await db.exec(select(Collection).order_by(Collection.name))
    ctx["discovery"] = discovery
    ctx["collections"] = collections_result.all()
    ctx["zone"] = gs.zone
    return templates.TemplateResponse(request, "discovery/import_form.html", ctx)


@router.post("/{discovery_id}/import")
async def do_import(
    request: Request,
    discovery_id: int,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    collection_id: int = Form(...),
    mac_address: str = Form(...),
):
    discovery = await db.get(DiscoveredHost, discovery_id)
    if not discovery or discovery.dismissed:
        return RedirectResponse("/discovery", 303)

    collection = await db.get(Collection, collection_id)
    if not collection:
        request.session["flash"] = {"type": "error", "message": "Collection not found"}
        return RedirectResponse(f"/discovery/{discovery_id}/import", 303)

    # Derive the bare hostname by stripping zone and collection subdomain
    zone_suffix = "." + gs.zone
    inner = discovery.fqdn[: -(len(gs.zone) + 1)] if discovery.fqdn.endswith(zone_suffix) else discovery.fqdn
    if collection.subdomain and inner.endswith("." + collection.subdomain):
        hostname = inner[: -(len(collection.subdomain) + 1)]
    else:
        hostname = inner

    host = Host(
        collection_id=collection_id,
        hostname=hostname.strip().lower(),
        ip_address=discovery.ip_address,
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

    discovery.dismissed = True
    db.add(discovery)
    await db.commit()

    request.session["flash"] = {"type": "success", "message": f"Imported {hostname} into {collection.name}"}
    return RedirectResponse("/discovery", 303)
