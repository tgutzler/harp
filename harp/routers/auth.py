from datetime import datetime

import bcrypt
from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy import func
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select

from ..config import settings
from ..crypto import decrypt_token
from ..database import get_db
from ..dependencies import base_context, require_auth
from ..drift import check_drift_and_discover
from ..models import GlobalSettings, User, UserSession

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


@router.get("/login")
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", 303)
    return templates.TemplateResponse(request, "login.html")


@router.post("/login")
async def login(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
):
    result = await db.exec(select(User).where(User.username == username))
    user = result.first()

    if not user or not _verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Invalid username or password"},
            status_code=400,
        )

    user_session = UserSession(user_id=user.id)
    db.add(user_session)
    await db.commit()
    await db.refresh(user_session)

    request.session["user_id"] = user.id
    request.session["session_id"] = user_session.id

    gs = await db.get(GlobalSettings, 1)
    if gs and gs.technitium_token_encrypted:
        try:
            token = decrypt_token(gs.technitium_token_encrypted, settings.secret_key)
            background_tasks.add_task(
                check_drift_and_discover,
                token=token,
                technitium_url=gs.technitium_url,
                zone=gs.zone,
                http_client=request.app.state.http_client,
            )
        except ValueError:
            pass

    return RedirectResponse("/", 303)


@router.post("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    session_id = request.session.get("session_id")
    if session_id:
        user_session = await db.get(UserSession, session_id)
        if user_session:
            user_session.logout_time = datetime.utcnow()
            db.add(user_session)
            await db.commit()
    request.session.clear()
    return RedirectResponse("/login", 303)


@router.get("/setup")
async def setup_page(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.exec(select(func.count(User.id)))
    if result.one() > 0:
        return RedirectResponse("/login", 303)
    return templates.TemplateResponse(request, "setup.html")


@router.post("/setup")
async def setup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    result = await db.exec(select(func.count(User.id)))
    if result.one() > 0:
        return RedirectResponse("/login", 303)

    if password != confirm_password:
        return templates.TemplateResponse(
            request, "setup.html",
            {"error": "Passwords do not match"},
            status_code=400,
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request, "setup.html",
            {"error": "Password must be at least 8 characters"},
            status_code=400,
        )

    user = User(username=username, hashed_password=_hash_password(password))
    db.add(user)
    await db.commit()
    return RedirectResponse("/login?created=1", 303)


@router.get("/profile")
async def profile_page(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx = await base_context(request, db)
    return templates.TemplateResponse(request, "profile.html", ctx)


@router.post("/profile/password")
async def update_password(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    if not _verify_password(current_password, user.hashed_password):
        request.session["flash"] = {"type": "error", "message": "Current password is incorrect"}
        return RedirectResponse("/profile", 303)

    if new_password != confirm_password:
        request.session["flash"] = {"type": "error", "message": "Passwords do not match"}
        return RedirectResponse("/profile", 303)

    if len(new_password) < 8:
        request.session["flash"] = {"type": "error", "message": "Password must be at least 8 characters"}
        return RedirectResponse("/profile", 303)

    user.hashed_password = _hash_password(new_password)
    db.add(user)
    await db.commit()
    request.session["flash"] = {"type": "success", "message": "Password updated"}
    return RedirectResponse("/profile", 303)


