"""
Integration tests for the undo stack (host operations).
Each test uses a fresh HTTP client (fresh login → fresh session_id → clean undo stack).
"""

import httpx
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlmodel import select

from harp.app import create_app
from harp.database import get_db
from harp.exceptions import TechnitiumAPIError
from harp.models import Host
from harp.sync import get_ptr_domain

from tests.conftest import (
    TEST_SUBDOMAIN,
    TEST_USERNAME,
    TEST_PASSWORD,
    TestSession,
    override_get_db,
)

TEST_HOST = "undotest-pc"
TEST_IP = "192.0.2.20"
TEST_MAC = "AA:BB:CC:DD:EE:FF"

EDIT_HOST = "undotest-pc-renamed"
EDIT_IP = "192.0.2.21"
EDIT_MAC = "AA:BB:CC:DD:EE:00"


# ── Technitium query helpers ──────────────────────────────────────────────────

async def get_a_record(tc, fqdn: str) -> str | None:
    try:
        resp = await tc._request("GET", "zones/records/get", params={"domain": fqdn})
        for r in resp.get("records", []):
            if r.get("type") == "A":
                return r["rData"]["ipAddress"]
    except TechnitiumAPIError:
        pass
    return None


async def get_ptr_record(tc, ip: str) -> str | None:
    try:
        resp = await tc._request("GET", "zones/records/get", params={"domain": get_ptr_domain(ip)})
        for r in resp.get("records", []):
            if r.get("type") == "PTR":
                return r["rData"]["ptrName"]
    except TechnitiumAPIError:
        pass
    return None


def fqdn(hostname: str, zone: str) -> str:
    return f"{hostname}.{TEST_SUBDOMAIN}.{zone}"


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def undo_client(setup_db):
    """Fresh login per test → fresh session_id → clean undo stack."""
    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    app.state.http_client = httpx.AsyncClient(timeout=10.0)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/login",
            data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
            follow_redirects=True,
        )
        assert resp.status_code == 200, f"Login failed: {resp.status_code}"
        yield client

    await app.state.http_client.aclose()


# ── Tests ─────────────────────────────────────────────────────────────────────

async def test_undo_host_create(undo_client, technitium_client, test_collection_id, zone):
    """Undo a host create: host removed from DB and DNS records removed."""
    tc = technitium_client
    client = undo_client

    resp = await client.post(
        f"/collections/{test_collection_id}/hosts",
        data={"hostname": TEST_HOST, "ip_address": TEST_IP, "mac_address": TEST_MAC},
    )
    assert resp.status_code == 200, f"Add failed: {resp.status_code}"

    async with TestSession() as db:
        result = await db.exec(select(Host).where(Host.hostname == TEST_HOST))
        host = result.first()
    assert host is not None, "Setup: host not created"

    a_ip = await get_a_record(tc, fqdn(TEST_HOST, zone))
    assert a_ip == TEST_IP, f"Setup: A record missing before undo: {a_ip!r}"

    resp = await client.post("/undo")
    assert resp.status_code == 200, f"Undo failed: {resp.status_code}"

    async with TestSession() as db:
        result = await db.exec(select(Host).where(Host.hostname == TEST_HOST))
        gone = result.first()
    assert gone is None, "Host still in DB after undo create"

    a_ip = await get_a_record(tc, fqdn(TEST_HOST, zone))
    assert a_ip is None, f"A record still present after undo create: {a_ip!r}"

    ptr = await get_ptr_record(tc, TEST_IP)
    assert ptr is None, f"PTR record still present after undo create: {ptr!r}"


async def test_undo_host_delete(undo_client, technitium_client, test_collection_id, zone):
    """Undo a host delete: host restored in DB and DNS records re-created."""
    tc = technitium_client
    client = undo_client

    resp = await client.post(
        f"/collections/{test_collection_id}/hosts",
        data={"hostname": TEST_HOST, "ip_address": TEST_IP, "mac_address": TEST_MAC},
    )
    assert resp.status_code == 200
    async with TestSession() as db:
        result = await db.exec(select(Host).where(Host.hostname == TEST_HOST))
        host = result.first()
    assert host is not None, "Setup: host not created"
    host_id = host.id

    resp = await client.delete(f"/collections/{test_collection_id}/hosts/{host_id}")
    assert resp.status_code == 200, f"Delete failed: {resp.status_code}"

    async with TestSession() as db:
        gone = await db.get(Host, host_id)
    assert gone is None, "Setup: host not deleted"

    try:
        resp = await client.post("/undo")
        assert resp.status_code == 200, f"Undo failed: {resp.status_code}"

        async with TestSession() as db:
            result = await db.exec(select(Host).where(Host.hostname == TEST_HOST))
            restored = result.first()
        assert restored is not None, "Host not restored in DB after undo delete"
        assert restored.ip_address == TEST_IP

        a_ip = await get_a_record(tc, fqdn(TEST_HOST, zone))
        assert a_ip == TEST_IP, f"A record missing after undo delete: {a_ip!r}"

        ptr = await get_ptr_record(tc, TEST_IP)
        assert ptr is not None, "PTR record missing after undo delete"
        assert fqdn(TEST_HOST, zone) in ptr, f"PTR points to wrong name: {ptr!r}"

    finally:
        async with TestSession() as db:
            result = await db.exec(select(Host).where(Host.hostname == TEST_HOST))
            h = result.first()
            if h:
                await client.delete(f"/collections/{test_collection_id}/hosts/{h.id}")


async def test_undo_host_edit(undo_client, technitium_client, test_collection_id, zone):
    """Undo a host edit: original hostname/IP restored in DB, old DNS records back, new ones gone."""
    tc = technitium_client
    client = undo_client

    resp = await client.post(
        f"/collections/{test_collection_id}/hosts",
        data={"hostname": TEST_HOST, "ip_address": TEST_IP, "mac_address": TEST_MAC},
    )
    assert resp.status_code == 200
    async with TestSession() as db:
        result = await db.exec(select(Host).where(Host.hostname == TEST_HOST))
        host = result.first()
    assert host is not None, "Setup: host not created"
    host_id = host.id

    try:
        resp = await client.post(
            f"/collections/{test_collection_id}/hosts/{host_id}/edit",
            data={
                "hostname": EDIT_HOST,
                "ip_address": EDIT_IP,
                "mac_address": EDIT_MAC,
                "show_collection": "false",
            },
        )
        assert resp.status_code == 200, f"Edit failed: {resp.status_code}"

        async with TestSession() as db:
            updated = await db.get(Host, host_id)
        assert updated.hostname == EDIT_HOST, "Setup: edit not applied"

        resp = await client.post("/undo")
        assert resp.status_code == 200, f"Undo failed: {resp.status_code}"

        async with TestSession() as db:
            restored = await db.get(Host, host_id)
        assert restored.hostname == TEST_HOST, f"Hostname not restored: {restored.hostname!r}"
        assert restored.ip_address == TEST_IP, f"IP not restored: {restored.ip_address!r}"

        edit_a = await get_a_record(tc, fqdn(EDIT_HOST, zone))
        assert edit_a is None, f"Edited A record still present after undo: {edit_a!r}"

        orig_a = await get_a_record(tc, fqdn(TEST_HOST, zone))
        assert orig_a == TEST_IP, f"Original A record missing after undo: {orig_a!r}"

        edit_ptr = await get_ptr_record(tc, EDIT_IP)
        assert edit_ptr is None, f"Edited PTR still present after undo: {edit_ptr!r}"

        orig_ptr = await get_ptr_record(tc, TEST_IP)
        assert orig_ptr is not None, "Original PTR missing after undo"
        assert fqdn(TEST_HOST, zone) in orig_ptr, f"Original PTR wrong: {orig_ptr!r}"

    finally:
        await client.delete(f"/collections/{test_collection_id}/hosts/{host_id}")
