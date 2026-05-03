import bcrypt
import httpx
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from harp.app import create_app
from harp.client.base import TechnitiumClient
from harp.config import settings as app_settings
from harp.crypto import decrypt_token
from harp.database import get_db
from harp.models import Collection, GlobalSettings, User

TEST_DB_URL = "sqlite+aiosqlite:///./test_harp.db"
TEST_USERNAME = "test_integration"
TEST_PASSWORD = "test_integration_pw"
TEST_SUBDOMAIN = "harptest"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSession = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


async def override_get_db():
    async with TestSession() as session:
        yield session


@pytest_asyncio.fixture(scope="session")
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    # Read real GlobalSettings and Technitium token from the production DB
    real_engine = create_async_engine(app_settings.database_url, echo=False)
    real_sessions = async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)
    async with real_sessions() as real_db:
        gs = await real_db.get(GlobalSettings, 1)
        result = await real_db.exec(select(User))
        real_user = result.first()
        zone = gs.zone if gs else "home.lan"
        technitium_url = gs.technitium_url if gs else "http://localhost:5380"
        token_encrypted = real_user.technitium_token_encrypted if real_user else None
    await real_engine.dispose()

    async with TestSession() as db:
        db.add(GlobalSettings(id=1, zone=zone, technitium_url=technitium_url))
        db.add(User(
            username=TEST_USERNAME,
            hashed_password=bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt()).decode(),
            technitium_token_encrypted=token_encrypted,
        ))
        await db.flush()
        db.add(Collection(name="HARP Integration Tests", subdomain=TEST_SUBDOMAIN))
        await db.commit()

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await test_engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def harp_client(setup_db):
    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    app.state.http_client = httpx.AsyncClient(timeout=10.0)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/login", data={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        }, follow_redirects=True)
        assert resp.status_code == 200, f"Login failed with status {resp.status_code}"
        yield client

    await app.state.http_client.aclose()


@pytest_asyncio.fixture(scope="session")
async def test_collection_id(setup_db):
    async with TestSession() as db:
        result = await db.exec(
            select(Collection).where(Collection.name == "HARP Integration Tests")
        )
        return result.first().id


@pytest_asyncio.fixture(scope="session")
async def zone(setup_db):
    async with TestSession() as db:
        gs = await db.get(GlobalSettings, 1)
        return gs.zone


@pytest_asyncio.fixture(scope="session")
async def technitium_client(setup_db):
    async with TestSession() as db:
        gs = await db.get(GlobalSettings, 1)
        result = await db.exec(select(User).where(User.username == TEST_USERNAME))
        user = result.first()

    if not user or not user.technitium_token_encrypted:
        pytest.skip("No Technitium token configured")

    try:
        token = decrypt_token(user.technitium_token_encrypted, app_settings.secret_key)
    except Exception:
        pytest.skip("Could not decrypt Technitium token")

    http = httpx.AsyncClient(timeout=10.0)
    yield TechnitiumClient(base_url=gs.technitium_url, token=token, http_client=http)
    await http.aclose()
