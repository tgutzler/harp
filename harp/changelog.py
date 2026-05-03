from typing import Optional

from sqlmodel.ext.asyncio.session import AsyncSession

from .models import ChangeLog, Collection, Host


async def log_change(
    db: AsyncSession,
    session_id: int,
    entity_type: str,
    entity_id: int,
    operation: str,
    before_state: Optional[dict] = None,
    after_state: Optional[dict] = None,
) -> None:
    db.add(ChangeLog(
        session_id=session_id,
        entity_type=entity_type,
        entity_id=entity_id,
        operation=operation,
        before_state=before_state,
        after_state=after_state,
    ))


def host_snapshot(host: Host) -> dict:
    return {
        "collection_id": host.collection_id,
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "mac_address": host.mac_address,
        "sync_status": host.sync_status,
        "last_error": host.last_error,
    }


def collection_snapshot(collection: Collection, subnets: list) -> dict:
    return {
        "name": collection.name,
        "description": collection.description,
        "subdomain": collection.subdomain,
        "blocking_enabled": collection.blocking_enabled,
        "subnets": [sn.cidr for sn in subnets],
    }
