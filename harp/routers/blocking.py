from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from ..client import blocking as blocking_client
from ..client.base import TechnitiumClient
from ..config import settings as app_settings
from ..crypto import decrypt_token
from ..database import get_db
from ..dependencies import base_context, get_global_settings, require_auth
from ..models import (
    BlockListSubscription, Collection, CollectionBlockList, CollectionRuleSet,
    CollectionSubnet, CustomRule, GlobalSettings, RuleSet, User,
)
from ..sync import sync_blocking

router = APIRouter(prefix="/blocking")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _get_http_client(request: Request) -> httpx.AsyncClient:
    try:
        return request.app.state.http_client
    except AttributeError:
        return httpx.AsyncClient(timeout=10.0)


async def _try_client(request: Request, user: User, gs: GlobalSettings) -> Optional[TechnitiumClient]:
    if not user.technitium_token_encrypted:
        return None
    try:
        token = decrypt_token(user.technitium_token_encrypted, app_settings.secret_key)
        return TechnitiumClient(base_url=gs.technitium_url, token=token, http_client=_get_http_client(request))
    except ValueError:
        return None


async def _sync_safe(request: Request, user: User, gs: GlobalSettings, db: AsyncSession) -> None:
    client = await _try_client(request, user, gs)
    if client:
        try:
            await sync_blocking(client, db)
        except Exception:
            pass


# ── Block Lists ───────────────────────────────────────────────────────────────

@router.get("/lists")
async def lists_index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    result = await db.exec(select(BlockListSubscription).order_by(BlockListSubscription.name))
    lists = result.all()
    ctx["lists"] = lists
    return templates.TemplateResponse(request, "blocking/lists.html", ctx)


@router.post("/lists")
async def create_list(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    entry = BlockListSubscription(name=name.strip(), url=url.strip())
    db.add(entry)
    await db.commit()
    await db.refresh(entry)

    if request.headers.get("HX-Request"):
        ctx["entry"] = entry
        return templates.TemplateResponse(request, "blocking/_list_row.html", ctx)

    return HTMLResponse("", headers={"HX-Redirect": "/blocking/lists"})


@router.post("/lists/{list_id}/toggle")
async def toggle_list(
    request: Request,
    list_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    ctx: dict = Depends(base_context),
):
    entry = await db.get(BlockListSubscription, list_id)
    if not entry:
        return HTMLResponse("", status_code=404)
    entry.enabled = not entry.enabled
    db.add(entry)
    await db.commit()
    await db.refresh(entry)

    await _sync_safe(request, user, gs, db)

    ctx["entry"] = entry
    return templates.TemplateResponse(request, "blocking/_list_row.html", ctx)


@router.delete("/lists/{list_id}")
async def delete_list(
    request: Request,
    list_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
):
    entry = await db.get(BlockListSubscription, list_id)
    if entry:
        # Remove all collection assignments first
        links = await db.exec(select(CollectionBlockList).where(CollectionBlockList.blocklist_id == list_id))
        for link in links.all():
            await db.delete(link)
        await db.delete(entry)
        await db.commit()
        await _sync_safe(request, user, gs, db)
    return HTMLResponse("")


# ── Rule Sets ─────────────────────────────────────────────────────────────────

@router.get("/rulesets")
async def rulesets_index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    result = await db.exec(select(RuleSet).order_by(RuleSet.name))
    rulesets = result.all()

    counts_result = await db.exec(
        select(CustomRule.ruleset_id, func.count(CustomRule.id))
        .group_by(CustomRule.ruleset_id)
    )
    counts = dict(counts_result.all())

    ctx["rulesets"] = rulesets
    ctx["counts"] = counts
    return templates.TemplateResponse(request, "blocking/rulesets.html", ctx)


@router.post("/rulesets")
async def create_ruleset(
    request: Request,
    name: str = Form(...),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    rs = RuleSet(name=name.strip())
    db.add(rs)
    await db.commit()
    await db.refresh(rs)

    if request.headers.get("HX-Request"):
        ctx["rs"] = rs
        ctx["count"] = 0
        return templates.TemplateResponse(request, "blocking/_ruleset_row.html", ctx)

    return HTMLResponse("", headers={"HX-Redirect": "/blocking/rulesets"})


@router.delete("/rulesets/{ruleset_id}")
async def delete_ruleset(
    request: Request,
    ruleset_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
):
    rs = await db.get(RuleSet, ruleset_id)
    if rs:
        # Remove collection assignments
        rs_links = await db.exec(select(CollectionRuleSet).where(CollectionRuleSet.ruleset_id == ruleset_id))
        for link in rs_links.all():
            await db.delete(link)
        rules_result = await db.exec(select(CustomRule).where(CustomRule.ruleset_id == ruleset_id))
        for rule in rules_result.all():
            await db.delete(rule)
        await db.delete(rs)
        await db.commit()
        await _sync_safe(request, user, gs, db)
    return HTMLResponse("")


@router.get("/rulesets/{ruleset_id}")
async def ruleset_detail(
    request: Request,
    ruleset_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    rs = await db.get(RuleSet, ruleset_id)
    if not rs:
        return HTMLResponse("Not found", status_code=404)
    rules_result = await db.exec(
        select(CustomRule)
        .where(CustomRule.ruleset_id == ruleset_id)
        .order_by(CustomRule.action, CustomRule.domain)
    )
    rules = rules_result.all()
    ctx["rs"] = rs
    ctx["rules"] = rules
    return templates.TemplateResponse(request, "blocking/ruleset_detail.html", ctx)


@router.post("/rulesets/{ruleset_id}/rules")
async def add_rule(
    request: Request,
    ruleset_id: int,
    domain: str = Form(...),
    action: str = Form(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
    ctx: dict = Depends(base_context),
):
    rs = await db.get(RuleSet, ruleset_id)
    if not rs:
        return HTMLResponse("Not found", status_code=404)

    domain = domain.strip().lower().lstrip("*").lstrip(".")
    if action not in ("block", "allow"):
        action = "block"

    rule = CustomRule(ruleset_id=ruleset_id, domain=domain, action=action)
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    await _sync_safe(request, user, gs, db)

    ctx["rule"] = rule
    ctx["ruleset_id"] = ruleset_id
    return templates.TemplateResponse(request, "blocking/_rule_row.html", ctx)


@router.delete("/rulesets/{ruleset_id}/rules/{rule_id}")
async def delete_rule(
    request: Request,
    ruleset_id: int,
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
):
    rule = await db.get(CustomRule, rule_id)
    if rule and rule.ruleset_id == ruleset_id:
        await db.delete(rule)
        await db.commit()
        await _sync_safe(request, user, gs, db)
    return HTMLResponse("")


# ── Import networkGroupMap from Advanced Blocking ─────────────────────────────

@router.post("/import-network-map", response_class=HTMLResponse)
async def import_network_map(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_auth),
    gs: GlobalSettings = Depends(get_global_settings),
):
    client = await _try_client(request, user, gs)
    if not client:
        return HTMLResponse('<p class="muted">No API token configured — visit your profile.</p>')

    try:
        config = await blocking_client.get_config(client)
    except Exception as e:
        return HTMLResponse(f'<p class="badge badge-error">Could not read Advanced Blocking config: {e}</p>')

    network_map: dict[str, str] = config.get("networkGroupMap", {})
    if not network_map:
        return HTMLResponse('<p class="muted">No entries in networkGroupMap.</p>')

    # Build lookup: group_name → collection
    collections = (await db.exec(select(Collection))).all()
    by_subdomain: dict[str, Collection] = {c.subdomain: c for c in collections if c.subdomain}
    by_id_key: dict[str, Collection] = {f"collection_{c.id}": c for c in collections}
    group_to_collection: dict[str, Collection] = {**by_id_key, **by_subdomain}

    # Existing subnets to avoid duplication
    existing = (await db.exec(select(CollectionSubnet))).all()
    existing_cidrs: set[tuple[int, str]] = {(s.collection_id, s.cidr) for s in existing}

    added: list[tuple[str, str]] = []    # (cidr, collection.name)
    skipped: list[tuple[str, str]] = []  # (cidr, collection.name) — already present
    unmatched: list[tuple[str, str]] = []  # (cidr, group_name) — no collection found

    for cidr, group_name in network_map.items():
        collection = group_to_collection.get(group_name)
        if not collection:
            unmatched.append((cidr, group_name))
            continue
        if (collection.id, cidr) in existing_cidrs:
            skipped.append((cidr, collection.name))
            continue
        db.add(CollectionSubnet(collection_id=collection.id, cidr=cidr))
        added.append((cidr, collection.name))

    if added:
        await db.commit()

    lines = []
    if added:
        lines.append(f"<strong>Added {len(added)} subnet(s):</strong>")
        lines.append("<ul>" + "".join(f"<li><code>{cidr}</code> → {name}</li>" for cidr, name in added) + "</ul>")
    if skipped:
        lines.append(f"<span class='muted'>Skipped {len(skipped)} already-present subnet(s).</span>")
    if unmatched:
        lines.append(f"<strong>Unmatched group(s) (no collection found):</strong>")
        lines.append("<ul>" + "".join(f"<li><code>{cidr}</code> → <em>{name}</em></li>" for cidr, name in unmatched) + "</ul>")
    if not lines:
        lines.append("<span class='muted'>Nothing to import.</span>")

    return HTMLResponse("".join(lines))
