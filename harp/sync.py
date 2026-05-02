from typing import Optional

from .client.base import TechnitiumClient
from .client.dhcp import add_reserved_lease, find_scope_for_ip, remove_reserved_lease
from .client.dns import (
    add_a_record, add_ptr_record, delete_a_record,
    delete_ptr_record, ensure_zone_exists,
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
