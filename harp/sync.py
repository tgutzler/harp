from typing import Optional

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from .client import blocking as blocking_client
from .client.base import TechnitiumClient
from .client.dhcp import add_reserved_lease, find_scope_for_ip, remove_reserved_lease
from .client.dns import (
    add_a_record, add_ptr_record, delete_a_record,
    delete_ptr_record, ensure_zone_exists,
)
from .models import (
    BlockListSubscription, Collection, CollectionBlockList,
    CollectionRuleSet, CollectionSubnet, CustomRule,
)


def build_fqdn(hostname: str, subdomain: Optional[str], zone: str) -> str:
    if subdomain:
        return f"{hostname}.{subdomain}.{zone}"
    return f"{hostname}.{zone}"


def get_reverse_zone(ip: str) -> str:
    """192.168.10.5 → 10.168.192.in-addr.arpa  (class C /24 zone)"""
    a, b, c, _ = ip.split(".")
    return f"{c}.{b}.{a}.in-addr.arpa"


def get_ptr_domain(ip: str) -> str:
    """192.168.10.5 → 5.10.168.192.in-addr.arpa"""
    a, b, c, d = ip.split(".")
    return f"{d}.{c}.{b}.{a}.in-addr.arpa"


async def sync_host(
    client: TechnitiumClient,
    hostname: str,
    ip: str,
    mac: str,
    subdomain: Optional[str],
    zone: str,
) -> Optional[str]:
    """Sync DNS + DHCP. Returns a warning string if DHCP was skipped, else None."""
    fqdn = build_fqdn(hostname, subdomain, zone)
    reverse_zone = get_reverse_zone(ip)
    ptr_domain = get_ptr_domain(ip)

    await ensure_zone_exists(client, reverse_zone)
    await add_a_record(client, fqdn, ip)
    await add_ptr_record(client, ptr_domain, fqdn)

    scope = await find_scope_for_ip(client, ip)
    if scope:
        dhcp_hostname = f"{hostname}.{subdomain}" if subdomain else hostname
        try:
            await remove_reserved_lease(client, scope, mac)
        except Exception:
            pass
        await add_reserved_lease(client, scope, mac, ip, dhcp_hostname, zone=zone)
        return None
    else:
        return f"No DHCP scope covers {ip} — DNS records created, no DHCP reservation"


async def load_blocking_data(db: AsyncSession) -> list[dict]:
    """Load all collections with their blocking assignments for a full Advanced Blocking sync."""
    collections = (await db.exec(select(Collection))).all()
    data = []
    for collection in collections:
        subnets = (await db.exec(
            select(CollectionSubnet).where(CollectionSubnet.collection_id == collection.id)
        )).all()

        bl_links = (await db.exec(
            select(CollectionBlockList).where(CollectionBlockList.collection_id == collection.id)
        )).all()
        bl_ids = [l.blocklist_id for l in bl_links]
        blocklists = []
        if bl_ids:
            blocklists = (await db.exec(
                select(BlockListSubscription).where(BlockListSubscription.id.in_(bl_ids))
            )).all()

        rs_links = (await db.exec(
            select(CollectionRuleSet).where(CollectionRuleSet.collection_id == collection.id)
        )).all()
        rs_ids = [l.ruleset_id for l in rs_links]
        rules = []
        if rs_ids:
            rules = (await db.exec(
                select(CustomRule).where(CustomRule.ruleset_id.in_(rs_ids))
            )).all()

        data.append({
            "collection": collection,
            "subnets": subnets,
            "blocklists": blocklists,
            "rules": rules,
        })
    return data


async def sync_blocking(tc: TechnitiumClient, db: AsyncSession) -> None:
    data = await load_blocking_data(db)
    await blocking_client.sync(tc, data)


async def unsync_host(
    client: TechnitiumClient,
    hostname: str,
    ip: str,
    mac: str,
    subdomain: Optional[str],
    zone: str,
) -> None:
    fqdn = build_fqdn(hostname, subdomain, zone)
    ptr_domain = get_ptr_domain(ip)

    for coro in [
        delete_a_record(client, fqdn, ip),
        delete_ptr_record(client, ptr_domain, fqdn),
    ]:
        try:
            await coro
        except Exception:
            pass

    scope = await find_scope_for_ip(client, ip)
    if scope:
        try:
            await remove_reserved_lease(client, scope, mac)
        except Exception:
            pass
