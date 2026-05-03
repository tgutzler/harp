"""
Integration tests for host add/edit/delete.
Each test verifies both the HARP database state and the Technitium DNS/DHCP state.

Test hosts use 192.0.2.x (RFC 5737 TEST-NET) — these IPs are reserved for
documentation/testing and will not match any real DHCP scope, so DHCP sync
is expected to fail. DNS A and PTR records are still verified.
"""

import pytest
from sqlmodel import select

from harp.exceptions import TechnitiumAPIError
from harp.models import Host
from harp.sync import get_ptr_domain

from tests.conftest import TEST_SUBDOMAIN, TestSession

TEST_HOST = "harptest-pc"
TEST_IP = "192.0.2.10"
TEST_MAC = "00:11:22:33:44:55"

EDIT_HOST = "harptest-pc-renamed"
EDIT_IP = "192.0.2.11"
EDIT_MAC = "00:11:22:33:44:66"


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


# ── Tests ─────────────────────────────────────────────────────────────────────

async def test_add_host(harp_client, technitium_client, test_collection_id, zone):
    tc = technitium_client

    try:
        resp = await harp_client.post(
            f"/collections/{test_collection_id}/hosts",
            data={"hostname": TEST_HOST, "ip_address": TEST_IP, "mac_address": TEST_MAC},
        )
        assert resp.status_code == 200, f"Add host failed: {resp.status_code}"

        # HARP DB: host exists
        async with TestSession() as db:
            result = await db.exec(
                select(Host).where(Host.hostname == TEST_HOST, Host.collection_id == test_collection_id)
            )
            host = result.first()
        assert host is not None, "Host not found in HARP database"
        assert host.ip_address == TEST_IP
        assert host.mac_address == "00-11-22-33-44-55"  # normalized to dash format
        # sync_status is "error" (expected: no DHCP scope for 192.0.2.x) but DNS should still be created
        assert host.sync_status in ("synced", "error"), f"Unexpected sync status: {host.sync_status!r} — {host.last_error!r}"
        assert "DHCP" in (host.last_error or "") or host.sync_status == "synced", \
            f"Unexpected sync error (not a DHCP warning): {host.last_error!r}"

        # Technitium: A record exists
        a_ip = await get_a_record(tc, fqdn(TEST_HOST, zone))
        assert a_ip == TEST_IP, f"A record missing or wrong IP: got {a_ip!r}"

        # Technitium: PTR record exists
        ptr = await get_ptr_record(tc, TEST_IP)
        assert ptr is not None, "PTR record missing"
        assert fqdn(TEST_HOST, zone) in ptr, f"PTR points to wrong name: {ptr!r}"

    finally:
        async with TestSession() as db:
            result = await db.exec(
                select(Host).where(Host.hostname == TEST_HOST, Host.collection_id == test_collection_id)
            )
            host = result.first()
            if host:
                await harp_client.delete(f"/collections/{test_collection_id}/hosts/{host.id}")


async def test_delete_host(harp_client, technitium_client, test_collection_id, zone):
    tc = technitium_client

    # Setup: add host
    await harp_client.post(
        f"/collections/{test_collection_id}/hosts",
        data={"hostname": TEST_HOST, "ip_address": TEST_IP, "mac_address": TEST_MAC},
    )
    async with TestSession() as db:
        result = await db.exec(
            select(Host).where(Host.hostname == TEST_HOST, Host.collection_id == test_collection_id)
        )
        host = result.first()
    assert host is not None, "Setup failed: host not created"
    host_id = host.id

    # Delete
    resp = await harp_client.delete(f"/collections/{test_collection_id}/hosts/{host_id}")
    assert resp.status_code == 200, f"Delete failed: {resp.status_code}"

    # HARP DB: host gone
    async with TestSession() as db:
        gone = await db.get(Host, host_id)
    assert gone is None, "Host still present in HARP database after delete"

    # Technitium: A record removed
    a_ip = await get_a_record(tc, fqdn(TEST_HOST, zone))
    assert a_ip is None, f"A record still present after delete: {a_ip!r}"

    # Technitium: PTR record removed
    ptr = await get_ptr_record(tc, TEST_IP)
    assert ptr is None, f"PTR record still present after delete: {ptr!r}"


async def test_edit_host(harp_client, technitium_client, test_collection_id, zone):
    tc = technitium_client

    # Setup: add host with original values
    await harp_client.post(
        f"/collections/{test_collection_id}/hosts",
        data={"hostname": TEST_HOST, "ip_address": TEST_IP, "mac_address": TEST_MAC},
    )
    async with TestSession() as db:
        result = await db.exec(
            select(Host).where(Host.hostname == TEST_HOST, Host.collection_id == test_collection_id)
        )
        host = result.first()
    assert host is not None, "Setup failed: host not created"
    host_id = host.id

    try:
        # Edit: change hostname and IP
        resp = await harp_client.post(
            f"/collections/{test_collection_id}/hosts/{host_id}/edit",
            data={
                "hostname": EDIT_HOST,
                "ip_address": EDIT_IP,
                "mac_address": EDIT_MAC,
                "show_collection": "false",
            },
        )
        assert resp.status_code == 200, f"Edit failed: {resp.status_code}"

        # HARP DB: updated values
        async with TestSession() as db:
            updated = await db.get(Host, host_id)
        assert updated.hostname == EDIT_HOST
        assert updated.ip_address == EDIT_IP

        # Technitium: old A record gone
        old_a = await get_a_record(tc, fqdn(TEST_HOST, zone))
        assert old_a is None, f"Old A record still present: {old_a!r}"

        # Technitium: new A record exists
        new_a = await get_a_record(tc, fqdn(EDIT_HOST, zone))
        assert new_a == EDIT_IP, f"New A record missing or wrong: got {new_a!r}"

        # Technitium: old PTR gone
        old_ptr = await get_ptr_record(tc, TEST_IP)
        assert old_ptr is None, f"Old PTR still present: {old_ptr!r}"

        # Technitium: new PTR exists
        new_ptr = await get_ptr_record(tc, EDIT_IP)
        assert new_ptr is not None, "New PTR record missing"
        assert fqdn(EDIT_HOST, zone) in new_ptr, f"New PTR points to wrong name: {new_ptr!r}"

    finally:
        await harp_client.delete(f"/collections/{test_collection_id}/hosts/{host_id}")
