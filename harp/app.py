from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .database import create_db_tables, engine
from .exceptions import NotAuthenticated
from .routers import auth, blocking, collections, discovery, hosts, settings as settings_router, undo

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_db_tables()
    app.state.http_client = httpx.AsyncClient(timeout=10.0)
    yield
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
