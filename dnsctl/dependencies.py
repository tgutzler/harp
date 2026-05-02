from fastapi import Depends, HTTPException, Request
from sqlalchemy import func
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select

from .client.base import TechnitiumClient
from .config import settings
from .crypto import decrypt_token
from .database import get_db
from .exceptions import NotAuthenticated
from .models import ChangeLog, DiscoveredHost, GlobalSettings, Host, User


async def require_auth(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise NotAuthenticated()
    user = await db.get(User, user_id)
    if not user:
        request.session.clear()
        raise NotAuthenticated()
    return user


async def base_context(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    user_id = request.session.get("user_id")
    session_id = request.session.get("session_id")
    user = None
    undo_count = 0

    if user_id and session_id:
        user = await db.get(User, user_id)
        if user:
            result = await db.exec(
                select(func.count(ChangeLog.id))
                .where(ChangeLog.session_id == session_id)
                .where(ChangeLog.undone == False)  # noqa: E712
            )
            undo_count = result.one()

    discovery_count = 0
    drift_count = 0
    if user_id:
        disc_result = await db.exec(
            select(func.count(DiscoveredHost.id))
            .where(DiscoveredHost.dismissed == False)  # noqa: E712
        )
        discovery_count = disc_result.one()
        drift_result = await db.exec(
            select(func.count(Host.id))
            .where(Host.sync_status == "drift")
        )
        drift_count = drift_result.one()

    flash = request.session.pop("flash", None)

    return {
        "request": request,
        "user": user,
        "undo_count": undo_count,
        "discovery_count": discovery_count,
        "drift_count": drift_count,
        "flash": flash,
    }


async def get_global_settings(db: AsyncSession = Depends(get_db)) -> GlobalSettings:
    obj = await db.get(GlobalSettings, 1)
    if obj is None:
        obj = GlobalSettings()
        db.add(obj)
        await db.commit()
        await db.refresh(obj)
    return obj


async def get_technitium_client(
    request: Request,
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
) -> TechnitiumClient:
    if not user.technitium_token_encrypted:
        raise HTTPException(status_code=400, detail="No API token configured — visit your profile.")
    token = decrypt_token(user.technitium_token_encrypted, settings.secret_key)
    return TechnitiumClient(
        base_url=gs.technitium_url,
        token=token,
        http_client=request.app.state.http_client,
    )
