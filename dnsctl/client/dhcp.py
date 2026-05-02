from ipaddress import ip_address as parse_ip
from typing import Optional

from .base import TechnitiumClient


def normalize_mac(mac: str) -> str:
    """Normalize any MAC format to uppercase dashes: AA-BB-CC-DD-EE-FF"""
    clean = mac.strip().upper().replace("-", "").replace(":", "").replace(".", "")
    return "-".join(clean[i : i + 2] for i in range(0, 12, 2))


async def find_scope_for_ip(client: TechnitiumClient, ip: str) -> Optional[str]:
    response = await client._request("GET", "dhcp/scopes/list")
    target = parse_ip(ip)
    for scope in response.get("scopes", []):
        if not scope.get("enabled", True) and not scope.get("allowOnlyReservedLeases"):
            pass  # still add reserved leases to disabled scopes
        start = parse_ip(scope["startingAddress"])
        end = parse_ip(scope["endingAddress"])
        if start <= target <= end:
            return scope["name"]
    return None


async def ensure_scope_domain(client: TechnitiumClient, scope_name: str, zone: str) -> None:
    """Ensure the scope doesn't auto-create DNS records — dnsctl manages DNS explicitly."""
    detail = await client._request("GET", "dhcp/scopes/get", params={"name": scope_name})
    needs_update = (
        detail.get("domainName") != zone
        or detail.get("dnsUpdates") is not False
    )
    if needs_update:
        await client._request("POST", "dhcp/scopes/set", params={
            "name": scope_name,
            "domainName": zone,
            "dnsUpdates": "false",
        })


async def add_reserved_lease(
    client: TechnitiumClient,
    scope_name: str,
    mac: str,
    ip: str,
    hostname: str,
    zone: str = "",
) -> None:
    if zone:
        await ensure_scope_domain(client, scope_name, zone)
    await client._request("POST", "dhcp/scopes/addReservedLease", params={
        "name": scope_name,
        "hardwareAddress": normalize_mac(mac),
        "ipAddress": ip,
        "hostName": hostname,
    })


async def remove_reserved_lease(
    client: TechnitiumClient,
    scope_name: str,
    mac: str,
) -> None:
    await client._request("POST", "dhcp/scopes/removeReservedLease", params={
        "name": scope_name,
        "hardwareAddress": normalize_mac(mac),
    })


async def find_mac_for_ip(client: TechnitiumClient, ip: str) -> Optional[str]:
    """Search DHCP reserved leases for a matching IP; returns MAC or None."""
    try:
        scope_name = await find_scope_for_ip(client, ip)
        if not scope_name:
            return None
        detail = await client._request("GET", "dhcp/scopes/get", params={"name": scope_name})
        for lease in detail.get("reservedLeases", []):
            if lease.get("address") == ip:
                return lease.get("hardwareAddress")
    except Exception:
        pass
    return None
