from datetime import datetime

from .base import TechnitiumClient


async def _resolve_query_logger(client: TechnitiumClient) -> tuple[str, str]:
    """Return (name, classPath) of the first installed IDnsQueryLogs app."""
    payload = await client._request("GET", "apps/list")
    for app in payload.get("apps", []):
        for dns_app in app.get("dnsApps", []):
            if dns_app.get("isQueryLogs") and dns_app.get("classPath"):
                return app["name"], dns_app["classPath"]
    raise RuntimeError(
        "No query-logger app found on Technitium server. "
        "Install 'Query Logs (Sqlite)' to enable log polling."
    )


async def fetch_query_logs(
    client: TechnitiumClient,
    start: datetime,
    end: datetime,
    page: int = 1,
    per_page: int = 1000,
    name: str | None = None,
    class_path: str | None = None,
) -> dict:
    if name is None or class_path is None:
        name, class_path = await _resolve_query_logger(client)
    return await client._request("GET", "logs/query", params={
        "name": name,
        "classPath": class_path,
        "pageNumber": str(page),
        "entriesPerPage": str(per_page),
        "descendingOrder": "false",
        "start": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "end": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    })
