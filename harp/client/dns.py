from .base import TechnitiumClient


async def ensure_zone_exists(client: TechnitiumClient, zone: str) -> bool:
    """Create zone as Primary if it doesn't already exist. Returns True if created."""
    response = await client._request("GET", "zones/list")
    existing = {z["name"] for z in response.get("zones", [])}
    if zone in existing:
        return False
    await client._request("POST", "zones/create", params={"zone": zone, "type": "Primary"})
    return True


async def set_server_domain(client: TechnitiumClient, domain: str) -> None:
    await client._request("POST", "settings/set", params={"serverDomain": domain})


async def add_a_record(client: TechnitiumClient, fqdn: str, ip: str) -> None:
    await client._request("POST", "zones/records/add", params={
        "domain": fqdn, "type": "A", "ipAddress": ip,
        "ttl": "3600", "overwrite": "true",
    })


async def delete_a_record(client: TechnitiumClient, fqdn: str, ip: str) -> None:
    await client._request("POST", "zones/records/delete", params={
        "domain": fqdn, "type": "A", "ipAddress": ip,
    })


async def add_ptr_record(client: TechnitiumClient, ptr_domain: str, fqdn: str) -> None:
    # Trailing dot makes the ptrName absolute — without it Technitium treats it as relative
    await client._request("POST", "zones/records/add", params={
        "domain": ptr_domain, "type": "PTR", "ptrName": fqdn + ".",
        "ttl": "3600", "overwrite": "true",
    })


async def delete_ptr_record(client: TechnitiumClient, ptr_domain: str, fqdn: str) -> None:
    response = await client._request("GET", "zones/records/get", params={"domain": ptr_domain})
    for record in response.get("records", []):
        if record.get("type") == "PTR":
            ptr_name = record.get("rData", {}).get("ptrName", "")
            await client._request("POST", "zones/records/delete", params={
                "domain": ptr_domain, "type": "PTR", "ptrName": ptr_name,
            })


async def list_a_records(client: TechnitiumClient, zone: str) -> list[dict]:
    """Return [{fqdn, ip}] for all enabled A records in the zone."""
    response = await client._request("GET", "zones/records/get", params={
        "domain": zone,
        "listZone": "true",
    })
    results = []
    for r in response.get("records", []):
        if r.get("type") != "A" or r.get("disabled", False):
            continue
        fqdn = r.get("name", "").rstrip(".")
        ip = r.get("rData", {}).get("ipAddress", "")
        if not fqdn or not ip:
            continue
        # Ensure FQDN is absolute (Technitium returns full domain names)
        if not fqdn.endswith("." + zone) and fqdn != zone:
            fqdn = f"{fqdn}.{zone}"
        results.append({"fqdn": fqdn, "ip": ip})
    return results
