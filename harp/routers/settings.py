from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete as sa_delete
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from ..client.base import TechnitiumClient
from ..client.blocking import get_config as get_blocking_config
from ..client.dhcp import list_all_reserved_leases
from ..client.dns import ensure_zone_exists, list_a_records, set_server_domain
from ..config import settings as app_settings
from ..crypto import decrypt_token, encrypt_token
from ..database import get_db
from ..dependencies import base_context, get_global_settings, require_auth
from ..exceptions import TechnitiumAPIError, TechnitiumInvalidToken, TechnitiumUnavailable
from ..models import (
    BlockListSubscription, ChangeLog, Collection, CollectionBlockList,
    CollectionRuleSet, CollectionSubnet, CustomRule, DiscoveredHost,
    GlobalSettings, Host, LogSource, RuleSet, User,
)

router = APIRouter(prefix="/settings")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("")
async def settings_page(
    request: Request,
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    db: AsyncSession = Depends(get_db),
):
    ctx = await base_context(request, db)
    ctx["gs"] = gs
    ctx["has_token"] = gs.technitium_token_encrypted is not None
    sources_result = await db.exec(
        select(LogSource).order_by(LogSource.is_primary.desc(), LogSource.created_at)
    )
    ctx["log_sources"] = sources_result.all()
    return templates.TemplateResponse(request, "settings/index.html", ctx)


@router.post("")
async def save_settings(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
    zone: Optional[str] = Form(None),
    technitium_url: Optional[str] = Form(None),
    verify_ssl: Optional[str] = Form(None),
    log_retention_days: Optional[int] = Form(None),
):
    gs = await db.get(GlobalSettings, 1)
    if gs is None:
        gs = GlobalSettings(zone="", technitium_url="")

    if not gs.zone and zone:
        gs.zone = zone.strip().lower()

    if log_retention_days is not None:
        gs.log_retention_days = max(1, min(log_retention_days, 365))

    if technitium_url is not None:
        gs.technitium_url = technitium_url.strip().rstrip("/")
        gs.verify_ssl = verify_ssl is not None
        # Keep primary LogSource in sync
        primary = (await db.exec(select(LogSource).where(LogSource.is_primary == True))).first()  # noqa: E712
        if primary:
            primary.url = gs.technitium_url
            primary.verify_ssl = gs.verify_ssl
            db.add(primary)
    db.add(gs)
    await db.commit()

    await request.app.state.http_client.aclose()
    request.app.state.http_client = httpx.AsyncClient(timeout=10.0, verify=gs.verify_ssl)

    if not gs.technitium_token_encrypted:
        request.session["flash"] = {"type": "success", "message": "Settings saved — no API token set, Technitium not updated"}
        return RedirectResponse("/settings", 303)

    try:
        token = decrypt_token(gs.technitium_token_encrypted, app_settings.secret_key)
    except ValueError as e:
        request.session["flash"] = {"type": "warning", "message": f"Settings saved locally but token error: {e}"}
        return RedirectResponse("/settings", 303)

    notes = []
    if gs.zone and gs.technitium_url:
        async with httpx.AsyncClient(timeout=10.0, verify=gs.verify_ssl) as http_client:
            client = TechnitiumClient(base_url=gs.technitium_url, token=token, http_client=http_client)
            try:
                await set_server_domain(client, gs.zone)
                notes.append(f"server domain set to '{gs.zone}'")
            except (TechnitiumAPIError, TechnitiumUnavailable, TechnitiumInvalidToken) as e:
                notes.append(f"could not update server domain ({e})")

            try:
                created = await ensure_zone_exists(client, gs.zone)
                notes.append(f"zone '{gs.zone}' {'created' if created else 'already exists'}")
            except (TechnitiumAPIError, TechnitiumUnavailable, TechnitiumInvalidToken) as e:
                notes.append(f"could not ensure zone exists ({e})")

    msg = f"Settings saved — {'; '.join(notes)}" if notes else "Settings saved"
    request.session["flash"] = {"type": "success", "message": msg}
    return RedirectResponse("/settings", 303)


@router.post("/zone/delete")
async def delete_zone(
    request: Request,
    user: User = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    await db.execute(sa_delete(ChangeLog))
    await db.execute(sa_delete(CollectionBlockList))
    await db.execute(sa_delete(CollectionRuleSet))
    await db.execute(sa_delete(CollectionSubnet))
    await db.execute(sa_delete(DiscoveredHost))
    await db.execute(sa_delete(Host))
    await db.execute(sa_delete(Collection))
    await db.execute(sa_delete(CustomRule))
    await db.execute(sa_delete(RuleSet))
    await db.execute(sa_delete(BlockListSubscription))

    gs = await db.get(GlobalSettings, 1)
    if gs:
        gs.zone = ""
        db.add(gs)

    await db.commit()

    request.session["flash"] = {"type": "success", "message": "Zone deleted — all hosts, collections, block lists, and rule sets have been removed."}
    return RedirectResponse("/settings", 303)


async def _sync_cluster_log_sources(
    token_encrypted: str,
    verify_ssl: bool,
    http_client,
    db: AsyncSession,
) -> list[str]:
    """Discover cluster nodes from the primary and add any not yet in log_sources.
    Returns list of names added."""
    primary = (await db.exec(select(LogSource).where(LogSource.is_primary == True))).first()  # noqa: E712
    if not primary:
        return []
    try:
        token = decrypt_token(token_encrypted, app_settings.secret_key)
        client = TechnitiumClient(base_url=primary.url, token=token, http_client=http_client)
        data = await client._request("GET", "settings/get")
    except Exception:
        return []

    nodes = data.get("clusterNodes", [])
    existing_urls = {s.url.rstrip("/") for s in (await db.exec(select(LogSource))).all()}
    added = []
    for node in nodes:
        if node.get("state") == "Self":
            canonical_url = node.get("url", "").rstrip("/")
            if canonical_url and primary.url.rstrip("/") != canonical_url:
                primary.url = canonical_url
                db.add(primary)
            continue
        node_url = node.get("url", "").rstrip("/")
        if not node_url or node_url in existing_urls:
            continue
        source = LogSource(
            name=node["name"].split(".")[0],
            url=node_url,
            token_encrypted=token_encrypted,
            verify_ssl=verify_ssl,
            enabled=True,
            is_primary=False,
        )
        db.add(source)
        added.append(node["name"].split(".")[0])
    if added:
        await db.commit()
    return added


@router.post("/token")
async def save_token(
    request: Request,
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    db: AsyncSession = Depends(get_db),
    technitium_token: str = Form(...),
):
    token_enc = encrypt_token(technitium_token.strip(), app_settings.secret_key)
    gs.technitium_token_encrypted = token_enc
    db.add(gs)
    primary = (await db.exec(select(LogSource).where(LogSource.is_primary == True))).first()  # noqa: E712
    if primary:
        primary.token_encrypted = token_enc
        db.add(primary)
    await db.commit()

    added = await _sync_cluster_log_sources(token_enc, gs.verify_ssl, request.app.state.http_client, db)
    if added:
        msg = f"API token saved — added cluster nodes: {', '.join(added)}"
    else:
        msg = "API token saved"
    request.session["flash"] = {"type": "success", "message": msg}
    return RedirectResponse("/settings", 303)


@router.post("/token/clear")
async def clear_token(
    request: Request,
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    db: AsyncSession = Depends(get_db),
):
    gs.technitium_token_encrypted = None
    db.add(gs)
    primary = (await db.exec(select(LogSource).where(LogSource.is_primary == True))).first()  # noqa: E712
    if primary:
        primary.token_encrypted = None
        db.add(primary)
    await db.commit()
    request.session["flash"] = {"type": "success", "message": "API token removed"}
    return RedirectResponse("/settings", 303)


async def _import_from_technitium(
    client: TechnitiumClient, zone: str, db: AsyncSession
) -> dict:
    """
    Imports from Technitium into HARP:
    - Advanced Blocking groups → Collections (subnets, block lists, rule sets)
    - DNS A records + DHCP reserved leases → Hosts (matched) or DiscoveredHosts (unmatched)
    Returns counts of what was created.
    """
    stats = {"collections": 0, "blocklists": 0, "rulesets": 0, "hosts": 0, "discovered": 0, "skipped": 0}

    # --- Snapshot existing DB state ---
    existing_cols = (await db.exec(select(Collection))).all()
    col_by_name: dict[str, Collection] = {c.name: c for c in existing_cols}
    col_by_id: dict[int, Collection] = {c.id: c for c in existing_cols}

    existing_snets = (await db.exec(select(CollectionSubnet))).all()
    subnet_to_col: dict[IPv4Network, Collection] = {}
    col_existing_cidrs: dict[int, set[str]] = {}
    for sn in existing_snets:
        col_existing_cidrs.setdefault(sn.collection_id, set()).add(sn.cidr)
        if col := col_by_id.get(sn.collection_id):
            try:
                subnet_to_col[IPv4Network(sn.cidr, strict=False)] = col
            except ValueError:
                pass

    existing_bls = (await db.exec(select(BlockListSubscription))).all()
    bl_by_url: dict[str, BlockListSubscription] = {bl.url: bl for bl in existing_bls}

    host_ips = {h.ip_address for h in (await db.exec(select(Host))).all()}
    existing_disc = (await db.exec(select(DiscoveredHost))).all()
    disc_ips = {d.ip_address for d in existing_disc}
    disc_fqdns = {d.fqdn for d in existing_disc}

    # --- Helpers ---
    def find_col(ip_str: str) -> Optional[Collection]:
        try:
            ip = IPv4Address(ip_str)
            best_net: Optional[IPv4Network] = None
            best_col: Optional[Collection] = None
            for net, col in subnet_to_col.items():
                if ip in net:
                    if best_net is None or net.prefixlen > best_net.prefixlen:
                        best_net = net
                        best_col = col
            return best_col
        except ValueError:
            pass
        return None

    async def ensure_col_for_subnet(ip_str: str) -> Collection:
        net_str = str(IPv4Network(f"{ip_str}/24", strict=False))
        if net_str in col_by_name:
            return col_by_name[net_str]
        col = Collection(name=net_str, sync_status="synced")
        db.add(col)
        await db.flush()
        sn = CollectionSubnet(collection_id=col.id, cidr=net_str)
        db.add(sn)
        net = IPv4Network(net_str, strict=False)
        subnet_to_col[net] = col
        col_by_name[net_str] = col
        col_by_id[col.id] = col
        stats["collections"] += 1
        return col

    # --- Phase 1: Advanced Blocking → Collections ---
    try:
        cfg = await get_blocking_config(client)
    except Exception:
        cfg = {}

    group_cidrs: dict[str, list[str]] = {}
    for cidr, gname in cfg.get("networkGroupMap", {}).items():
        group_cidrs.setdefault(gname, []).append(cidr)

    for group in cfg.get("groups", []):
        gname = group.get("name", "").strip()
        if not gname:
            continue

        if gname in col_by_name:
            col = col_by_name[gname]
            col.blocking_enabled = group.get("enableBlocking", True)
            col.block_as_nxdomain = group.get("blockAsNxDomain", True)
            db.add(col)
        else:
            col = Collection(
                name=gname,
                blocking_enabled=group.get("enableBlocking", True),
                block_as_nxdomain=group.get("blockAsNxDomain", True),
                sync_status="synced",
            )
            db.add(col)
            await db.flush()
            col_by_name[gname] = col
            col_by_id[col.id] = col
            stats["collections"] += 1

        existing_for_col = col_existing_cidrs.setdefault(col.id, set())
        for cidr in group_cidrs.get(gname, []):
            if cidr not in existing_for_col:
                db.add(CollectionSubnet(collection_id=col.id, cidr=cidr))
                existing_for_col.add(cidr)
            try:
                net = IPv4Network(cidr, strict=False)
                subnet_to_col.setdefault(net, col)
            except ValueError:
                pass

        linked_bls = {
            lnk.blocklist_id
            for lnk in (
                await db.exec(
                    select(CollectionBlockList).where(CollectionBlockList.collection_id == col.id)
                )
            ).all()
        }
        for url in group.get("blockListUrls", []):
            url = url.strip()
            if not url:
                continue
            if url not in bl_by_url:
                bl_name = url.rsplit("/", 1)[-1].split("?")[0] or url[:60]
                bl = BlockListSubscription(name=bl_name, url=url)
                db.add(bl)
                await db.flush()
                bl_by_url[url] = bl
                stats["blocklists"] += 1
            bl = bl_by_url[url]
            if bl.id not in linked_bls:
                db.add(CollectionBlockList(collection_id=col.id, blocklist_id=bl.id))
                linked_bls.add(bl.id)

        allowed = group.get("allowed", [])
        blocked = group.get("blocked", [])
        if allowed or blocked:
            rs_name = f"{gname} rules"
            rs = (await db.exec(select(RuleSet).where(RuleSet.name == rs_name))).first()
            if not rs:
                rs = RuleSet(name=rs_name)
                db.add(rs)
                await db.flush()
                for d in allowed:
                    db.add(CustomRule(ruleset_id=rs.id, domain=d, action="allow"))
                for d in blocked:
                    db.add(CustomRule(ruleset_id=rs.id, domain=d, action="block"))
                db.add(CollectionRuleSet(collection_id=col.id, ruleset_id=rs.id))
                stats["rulesets"] += 1

    await db.flush()

    # --- Phase 2: DNS A records ---
    try:
        dns_by_ip: dict[str, dict] = {r["ip"]: r for r in await list_a_records(client, zone)}
    except Exception:
        dns_by_ip = {}

    # --- Phase 3: DHCP reserved leases ---
    try:
        dhcp_by_ip: dict[str, dict] = {l["ip"]: l for l in await list_all_reserved_leases(client)}
    except Exception:
        dhcp_by_ip = {}

    # --- Phase 4: Hosts and discovered ---
    # Index discovered hosts by IP so we can promote them to real hosts if DHCP data is now available
    disc_by_ip: dict[str, DiscoveredHost] = {d.ip_address: d for d in existing_disc}

    for ip in set(dns_by_ip) | set(dhcp_by_ip):
        if ip in host_ips:
            stats["skipped"] += 1
            continue

        has_dns = ip in dns_by_ip
        has_dhcp = ip in dhcp_by_ip
        dns_rec = dns_by_ip.get(ip)
        dhcp_rec = dhcp_by_ip.get(ip)

        if has_dns:
            fqdn = dns_rec["fqdn"]
            zone_suffix = "." + zone
            if fqdn.lower().endswith(zone_suffix.lower()):
                hostname = fqdn[: -len(zone_suffix)]
            else:
                hostname = fqdn.split(".")[0]
        else:
            raw = (dhcp_rec.get("hostname") or "").strip()
            # Strip zone suffix if Technitium stored the full FQDN as the hostname
            for suffix in ("." + zone, zone):
                if raw.lower().endswith(suffix.lower()) and len(raw) > len(suffix):
                    raw = raw[: -len(suffix)].rstrip(".")
                    break
            hostname = raw or ip.replace(".", "-")
            fqdn = f"{hostname}.{zone}"

        if has_dhcp and hostname:
            # Promote from discovered if it was previously stuck there
            if ip in disc_by_ip:
                await db.delete(disc_by_ip[ip])
                disc_ips.discard(ip)
            col = find_col(ip) or await ensure_col_for_subnet(ip)
            # Strip collection subdomain from hostname if DHCP included it
            if col.subdomain and hostname.lower().endswith("." + col.subdomain.lower()):
                hostname = hostname[: -(len(col.subdomain) + 1)]
            db.add(Host(
                collection_id=col.id,
                hostname=hostname,
                ip_address=ip,
                mac_address=dhcp_rec["mac"],
                sync_status="synced" if has_dns else "pending",
            ))
            host_ips.add(ip)
            stats["hosts"] += 1
        else:
            if ip in disc_ips or fqdn in disc_fqdns:
                stats["skipped"] += 1
                continue
            suggested = find_col(ip)
            db.add(DiscoveredHost(
                fqdn=fqdn,
                hostname=hostname,
                ip_address=ip,
                mac_address=None,
                suggested_collection_id=suggested.id if suggested else None,
            ))
            disc_ips.add(ip)
            disc_fqdns.add(fqdn)
            stats["discovered"] += 1

    # --- Phase 5: Infer collection subdomains ---
    # If any hosts in a collection have ".{collection.name}" as a suffix, that suffix
    # is the subdomain. Set it on the collection and strip it from the affected hosts.
    await db.flush()
    for col in col_by_id.values():
        if col.subdomain:
            continue
        col_hosts = (await db.exec(select(Host).where(Host.collection_id == col.id))).all()
        if not col_hosts:
            continue
        suffix = "." + col.name.lower()
        matches = [h for h in col_hosts if h.hostname.lower().endswith(suffix)]
        if not matches:
            continue
        col.subdomain = col.name.lower()
        db.add(col)
        for host in matches:
            host.hostname = host.hostname[: -len(suffix)]
            db.add(host)
        stats["subdomains"] = stats.get("subdomains", 0) + 1

    await db.commit()
    return stats


@router.post("/import")
async def run_import(
    request: Request,
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    db: AsyncSession = Depends(get_db),
):
    if not gs.zone:
        request.session["flash"] = {"type": "error", "message": "No zone configured."}
        return RedirectResponse("/settings", 303)
    if not gs.technitium_token_encrypted:
        request.session["flash"] = {"type": "error", "message": "No API token configured — check Settings."}
        return RedirectResponse("/settings", 303)

    try:
        token = decrypt_token(gs.technitium_token_encrypted, app_settings.secret_key)
    except ValueError as e:
        request.session["flash"] = {"type": "warning", "message": f"Token error: {e}"}
        return RedirectResponse("/settings", 303)

    try:
        async with httpx.AsyncClient(timeout=30.0, verify=gs.verify_ssl) as http_client:
            client = TechnitiumClient(base_url=gs.technitium_url, token=token, http_client=http_client)
            stats = await _import_from_technitium(client, gs.zone, db)

        parts = []
        if stats["collections"]:
            parts.append(f"{stats['collections']} collection(s)")
        if stats["blocklists"]:
            parts.append(f"{stats['blocklists']} block list(s)")
        if stats["rulesets"]:
            parts.append(f"{stats['rulesets']} rule set(s)")
        if stats["hosts"]:
            parts.append(f"{stats['hosts']} host(s)")
        if stats["discovered"]:
            parts.append(f"{stats['discovered']} discovered")
        if stats["skipped"]:
            parts.append(f"{stats['skipped']} skipped (already exist)")
        if stats.get("subdomains"):
            parts.append(f"{stats['subdomains']} subdomain(s) inferred")

        msg = "Import complete — " + (", ".join(parts) if parts else "nothing new to import")
        request.session["flash"] = {"type": "success", "message": msg}
    except (TechnitiumUnavailable, TechnitiumInvalidToken, TechnitiumAPIError) as e:
        request.session["flash"] = {"type": "error", "message": f"Technitium error: {e}"}
    except Exception as e:
        request.session["flash"] = {"type": "error", "message": f"Import failed: {e}"}

    return RedirectResponse("/settings", 303)


@router.get("/test", response_class=HTMLResponse)
async def test_connection(
    technitium_url: str,
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    verify_ssl: Optional[str] = None,
):
    if not gs.technitium_token_encrypted:
        return '<span class="badge badge-error">No API token saved — check Settings</span>'

    try:
        token = decrypt_token(gs.technitium_token_encrypted, app_settings.secret_key)
    except ValueError as e:
        return f'<span class="badge badge-error">{e}</span>'

    should_verify = gs.verify_ssl if verify_ssl is None else (verify_ssl == "1")
    async with httpx.AsyncClient(timeout=5.0, verify=should_verify) as http_client:
        client = TechnitiumClient(
            base_url=technitium_url.rstrip("/"),
            token=token,
            http_client=http_client,
        )
        ok, message = await client.check_connection()

    if ok:
        return f'<span class="badge badge-synced">{message}</span>'
    return f'<span class="badge badge-error">{message}</span>'


# ── Log Sources ───────────────────────────────────────────────────────────────

@router.post("/log-sources")
async def create_log_source(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    technitium_token: str = Form(""),
    verify_ssl: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    token_enc = encrypt_token(technitium_token.strip(), app_settings.secret_key) if technitium_token.strip() else None
    source = LogSource(
        name=name.strip(),
        url=url.strip().rstrip("/"),
        token_encrypted=token_enc,
        verify_ssl=verify_ssl == "1",
        enabled=True,
        is_primary=False,
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)

    if request.headers.get("HX-Request"):
        ctx["source"] = source
        return templates.TemplateResponse(request, "settings/_log_source_row.html", ctx)
    return HTMLResponse("", headers={"HX-Redirect": "/settings"})


@router.post("/log-sources/{source_id}/toggle")
async def toggle_log_source(
    request: Request,
    source_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    source = await db.get(LogSource, source_id)
    if not source:
        return HTMLResponse("", status_code=404)
    source.enabled = not source.enabled
    db.add(source)
    await db.commit()
    await db.refresh(source)
    ctx["source"] = source
    return templates.TemplateResponse(request, "settings/_log_source_row.html", ctx)


@router.delete("/log-sources/{source_id}")
async def delete_log_source(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
):
    source = await db.get(LogSource, source_id)
    if source and not source.is_primary:
        await db.delete(source)
        await db.commit()
    return HTMLResponse("")


@router.get("/log-sources/discover", response_class=HTMLResponse)
async def discover_log_sources(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
):
    primary = (await db.exec(select(LogSource).where(LogSource.is_primary == True))).first()  # noqa: E712
    if not primary or not primary.token_encrypted:
        return HTMLResponse('<span class="muted" style="font-size:0.85rem">No primary source configured.</span>')

    try:
        token = decrypt_token(primary.token_encrypted, app_settings.secret_key)
    except ValueError:
        return HTMLResponse('<span class="badge badge-error">Invalid stored token</span>')

    client = TechnitiumClient(base_url=primary.url, token=token, http_client=request.app.state.http_client)
    try:
        data = await client._request("GET", "settings/get")
    except Exception as e:
        return HTMLResponse(f'<span class="badge badge-error">Could not reach primary: {e}</span>')

    nodes = data.get("clusterNodes", [])
    existing_urls = {s.url.rstrip("/") for s in (await db.exec(select(LogSource))).all()}

    candidates = [
        n for n in nodes
        if n.get("state") != "Self" and n.get("url", "").rstrip("/") not in existing_urls
    ]

    if not candidates:
        return HTMLResponse('<span class="muted" style="font-size:0.85rem">All cluster nodes are already configured.</span>')

    rows = "".join(
        f'<tr>'
        f'<td>{n["name"]}</td>'
        f'<td class="muted" style="font-size:0.82rem">{n["url"].rstrip("/")}</td>'
        f'<td>{", ".join(n.get("ipAddresses", []))}</td>'
        f'<td><form hx-post="/settings/log-sources/cluster-add"'
        f'         hx-target="#logsources-tbody" hx-swap="beforeend"'
        f'         hx-on::after-request="this.closest(\'tr\').remove()" style="margin:0">'
        f'  <input type="hidden" name="name" value="{n["name"].split(".")[0]}">'
        f'  <input type="hidden" name="url" value="{n["url"].rstrip("/")}">'
        f'  <button type="submit" class="outline secondary"'
        f'          style="padding:0.15rem 0.6rem;font-size:0.8rem;margin:0">Add</button>'
        f'</form></td>'
        f'</tr>'
        for n in candidates
    )
    return HTMLResponse(
        f'<table style="font-size:0.83rem;margin-top:0.75rem">'
        f'<thead><tr><th>Name</th><th>URL</th><th>IP</th><th></th></tr></thead>'
        f'<tbody>{rows}</tbody>'
        f'</table>'
    )


@router.post("/log-sources/cluster-add")
async def cluster_add_log_source(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    primary = (await db.exec(select(LogSource).where(LogSource.is_primary == True))).first()  # noqa: E712
    source = LogSource(
        name=name.strip(),
        url=url.strip().rstrip("/"),
        token_encrypted=primary.token_encrypted if primary else None,
        verify_ssl=primary.verify_ssl if primary else True,
        enabled=True,
        is_primary=False,
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    ctx["source"] = source
    return templates.TemplateResponse(request, "settings/_log_source_row.html", ctx)
