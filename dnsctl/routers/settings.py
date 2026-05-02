from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel.ext.asyncio.session import AsyncSession

from ..client.base import TechnitiumClient
from ..client.dns import ensure_zone_exists, set_server_domain
from ..config import settings as app_settings
from ..crypto import decrypt_token
from ..database import get_db
from ..dependencies import base_context, get_global_settings, require_auth
from ..exceptions import TechnitiumAPIError, TechnitiumInvalidToken, TechnitiumUnavailable
from ..models import GlobalSettings, User

router = APIRouter(prefix="/settings")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("")
async def settings_page(
    request: Request,
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    db: AsyncSession = Depends(get_db),
):
    ctx = await base_context(request, db)
    ctx["gs"] = gs
    ctx["has_token"] = user.technitium_token_encrypted is not None
    return templates.TemplateResponse(request, "settings/index.html", ctx)


@router.post("")
async def save_settings(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    zone: str = Form(...),
    technitium_url: str = Form(...),
):
    zone = zone.strip().lower()
    technitium_url = technitium_url.strip().rstrip("/")

    gs = await db.get(GlobalSettings, 1)
    if gs is None:
        gs = GlobalSettings(zone=zone, technitium_url=technitium_url)
    else:
        gs.zone = zone
        gs.technitium_url = technitium_url
    db.add(gs)
    await db.commit()

    if not user.technitium_token_encrypted:
        request.session["flash"] = {"type": "success", "message": "Settings saved — no API token set, Technitium not updated"}
        return RedirectResponse("/settings", 303)

    try:
        token = decrypt_token(user.technitium_token_encrypted, app_settings.secret_key)
    except ValueError as e:
        request.session["flash"] = {"type": "warning", "message": f"Settings saved locally but token error: {e}"}
        return RedirectResponse("/settings", 303)

    notes = []
    async with httpx.AsyncClient(timeout=10.0) as http_client:
        client = TechnitiumClient(base_url=technitium_url, token=token, http_client=http_client)
        try:
            await set_server_domain(client, zone)
            notes.append(f"server domain set to '{zone}'")
        except (TechnitiumAPIError, TechnitiumUnavailable, TechnitiumInvalidToken) as e:
            notes.append(f"could not update server domain ({e})")

        try:
            created = await ensure_zone_exists(client, zone)
            notes.append(f"zone '{zone}' {'created' if created else 'already exists'}")
        except (TechnitiumAPIError, TechnitiumUnavailable, TechnitiumInvalidToken) as e:
            notes.append(f"could not ensure zone exists ({e})")

    request.session["flash"] = {"type": "success", "message": f"Settings saved — {'; '.join(notes)}"}
    return RedirectResponse("/settings", 303)


@router.get("/test", response_class=HTMLResponse)
async def test_connection(
    technitium_url: str,
    user: User = Depends(require_auth),
):
    if not user.technitium_token_encrypted:
        return '<span class="badge badge-error">&#10007; No API token saved — visit your profile</span>'

    try:
        token = decrypt_token(user.technitium_token_encrypted, app_settings.secret_key)
    except ValueError as e:
        return f'<span class="badge badge-error">&#10007; {e}</span>'

    async with httpx.AsyncClient(timeout=5.0) as http_client:
        client = TechnitiumClient(
            base_url=technitium_url.rstrip("/"),
            token=token,
            http_client=http_client,
        )
        ok, message = await client.check_connection()

    if ok:
        return f'<span class="badge badge-synced">&#10003; {message}</span>'
    return f'<span class="badge badge-error">&#10007; {message}</span>'
