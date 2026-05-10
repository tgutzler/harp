import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .database import async_session_factory, create_db_tables, engine
from .log_poller import run_log_poller
from .logs_db import init_logs_db
from .models import GlobalSettings
from .exceptions import NotAuthenticated
from .routers import auth, blocking, collections, discovery, hosts, settings as settings_router, undo
from .routers import logs as logs_router

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_db_tables()
    await init_logs_db()
    async with async_session_factory() as session:
        gs = await session.get(GlobalSettings, 1)
        verify_ssl = gs.verify_ssl if gs else True
    app.state.http_client = httpx.AsyncClient(timeout=10.0, verify=verify_ssl)
    poller_task = asyncio.create_task(run_log_poller(app))
    yield
    poller_task.cancel()
    try:
        await poller_task
    except asyncio.CancelledError:
        pass
    await app.state.http_client.aclose()
    await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="dnsctl", lifespan=lifespan)

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        max_age=settings.session_max_age,
        https_only=False,
        same_site="lax",
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(auth.router)
    app.include_router(collections.router)
    app.include_router(discovery.router)
    app.include_router(hosts.router)
    app.include_router(settings_router.router)
    app.include_router(blocking.router)
    app.include_router(undo.router)
    app.include_router(logs_router.router)

    @app.exception_handler(NotAuthenticated)
    async def not_authenticated(_request: Request, _exc: NotAuthenticated):
        return RedirectResponse("/login", 303)

    @app.get("/")
    async def index(request: Request):
        if not request.session.get("user_id"):
            return RedirectResponse("/login", 303)
        return RedirectResponse("/collections", 303)

    return app


app = create_app()
