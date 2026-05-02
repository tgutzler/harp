import logging
from datetime import datetime
from typing import Optional

import httpx
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from .client.base import TechnitiumClient
from .client.dhcp import find_mac_for_ip
from .client.dns import list_a_records
from .exceptions import TechnitiumAPIError, TechnitiumInvalidToken, TechnitiumUnavailable
from .models import Collection, DiscoveredHost, Host
from .sync import build_fqdn

logger = logging.getLogger(__name__)


async def check_drift_and_discover(
    token: str,
    technitium_url: str,
    zone: str,
    http_client: httpx.AsyncClient,
) -> None:
    """Background task: mark drifted hosts and create DiscoveredHost entries for unknowns."""
    from .database import async_session_factory

    client = TechnitiumClient(base_url=technitium_url, token=token, http_client=http_client)

    try:
        a_records = await list_a_records(client, zone)
    except (TechnitiumUnavailable, TechnitiumInvalidToken, TechnitiumAPIError) as e:
        logger.info("Drift check skipped: %s", e)
        return
    except Exception as e:
        logger.warning("Drift check failed fetching zone records: %s", e)
        return

    ip_by_fqdn: dict[str, str] = {r["fqdn"]: r["ip"] for r in a_records}

    async with async_session_factory() as db:
        try:
            await _check_drift(db, ip_by_fqdn, zone)
            await _discover_hosts(client, db, ip_by_fqdn, zone)
        except Exception as e:
            logger.warning("Drift check DB error: %s", e)


async def _check_drift(db: AsyncSession, ip_by_fqdn: dict, zone: str) -> None:
    result = await db.exec(
        select(Host, Collection)
        .join(Collection, Host.collection_id == Collection.id)
        .where(Host.sync_status == "synced")
    )
    changed = False
    for host, collection in result.all():
        fqdn = build_fqdn(host.hostname, collection.subdomain, zone)
        actual_ip = ip_by_fqdn.get(fqdn)
        if actual_ip != host.ip_address:
            host.sync_status = "drift"
            host.last_error = (
                "DNS record missing" if actual_ip is None
                else f"DNS shows {actual_ip}, expected {host.ip_address}"
            )
            db.add(host)
            changed = True
    if changed:
        await db.commit()


async def _discover_hosts(
    client: TechnitiumClient,
    db: AsyncSession,
    ip_by_fqdn: dict,
    zone: str,
) -> None:
    result = await db.exec(
        select(Host, Collection)
        .join(Collection, Host.collection_id == Collection.id)
    )
    known_fqdns = {
        build_fqdn(host.hostname, collection.subdomain, zone)
        for host, collection in result.all()
    }

    collections_result = await db.exec(select(Collection))
    collections = collections_result.all()

    zone_suffix = "." + zone
    changed = False

    for fqdn, ip in ip_by_fqdn.items():
        if fqdn == zone or not fqdn.endswith(zone_suffix):
            continue
        if fqdn in known_fqdns:
            continue

        existing_result = await db.exec(
            select(DiscoveredHost).where(DiscoveredHost.fqdn == fqdn)
        )
        existing = existing_result.first()

        if existing and existing.dismissed:
            continue

        try:
            mac = await find_mac_for_ip(client, ip)
        except Exception:
            mac = None

        suggested_id = _suggest_collection(fqdn, zone, collections)
        inner = fqdn[: -(len(zone) + 1)]
        hostname = inner.split(".")[0]

        if existing:
            existing.ip_address = ip
            if mac:
                existing.mac_address = mac
            existing.suggested_collection_id = suggested_id
            existing.updated_at = datetime.utcnow()
            db.add(existing)
        else:
            db.add(DiscoveredHost(
                fqdn=fqdn,
                hostname=hostname,
                ip_address=ip,
                mac_address=mac,
                suggested_collection_id=suggested_id,
            ))
        changed = True

    if changed:
        await db.commit()


def _suggest_collection(fqdn: str, zone: str, collections: list) -> Optional[int]:
    if not fqdn.endswith("." + zone):
        return None
    inner = fqdn[: -(len(zone) + 1)]
    parts = inner.split(".")

    if len(parts) == 1:
        for c in collections:
            if not c.subdomain:
                return c.id
    else:
        subdomain = parts[-1]
        for c in collections:
            if c.subdomain == subdomain:
                return c.id
    return None
