from ipaddress import ip_address as parse_ip
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from ..database import get_db
from ..dependencies import base_context, get_global_settings, require_auth
from ..models import Collection, GlobalSettings, Host, User
from ..sync import build_fqdn

router = APIRouter(prefix="/hosts")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

_SORT_KEYS = {
    "hostname":   lambda r: r["host"].hostname.lower(),
    "fqdn":       lambda r: r["fqdn"].lower(),
    "ip":         lambda r: parse_ip(r["host"].ip_address),
    "mac":        lambda r: r["host"].mac_address.upper(),
    "collection": lambda r: r["collection"].name.lower(),
}


_VALID_FILTERS = {"error", "pending", "synced", "drift"}


@router.get("")
async def hosts_index(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    gs: GlobalSettings = Depends(get_global_settings),
    sort: str = "hostname",
    dir: str = "asc",
    filter: str = "",
):
    ctx = await base_context(request, db)

    query = select(Host, Collection).join(Collection, Host.collection_id == Collection.id)
    if filter in _VALID_FILTERS:
        query = query.where(Host.sync_status == filter)

    result = await db.exec(query)
    rows = []
    for host, collection in result.all():
        rows.append({
            "host": host,
            "collection": collection,
            "fqdn": build_fqdn(host.hostname, collection.subdomain, gs.zone),
        })

    sort_key = _SORT_KEYS.get(sort, _SORT_KEYS["hostname"])
    ip_key = _SORT_KEYS["ip"]
    rows.sort(key=lambda r: (sort_key(r), ip_key(r)), reverse=(dir == "desc"))

    ctx["rows"] = rows
    ctx["sort"] = sort
    ctx["dir"] = dir
    ctx["filter"] = filter
    return templates.TemplateResponse(request, "hosts/index.html", ctx)
