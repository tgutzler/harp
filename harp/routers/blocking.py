from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from ..database import get_db
from ..dependencies import base_context, require_auth
from ..models import BlockListSubscription, CustomRule, RuleSet, User

router = APIRouter(prefix="/blocking")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


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
    _user: User = Depends(require_auth),
    ctx: dict = Depends(base_context),
):
    entry = await db.get(BlockListSubscription, list_id)
    if not entry:
        return HTMLResponse("", status_code=404)
    entry.enabled = not entry.enabled
    db.add(entry)
    await db.commit()
    await db.refresh(entry)

    ctx["entry"] = entry
    return templates.TemplateResponse(request, "blocking/_list_row.html", ctx)


@router.delete("/lists/{list_id}")
async def delete_list(
    list_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
):
    entry = await db.get(BlockListSubscription, list_id)
    if entry:
        await db.delete(entry)
        await db.commit()
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
    ruleset_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
):
    rs = await db.get(RuleSet, ruleset_id)
    if rs:
        rules_result = await db.exec(select(CustomRule).where(CustomRule.ruleset_id == ruleset_id))
        for rule in rules_result.all():
            await db.delete(rule)
        await db.delete(rs)
        await db.commit()
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
    _user: User = Depends(require_auth),
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

    ctx["rule"] = rule
    ctx["ruleset_id"] = ruleset_id
    return templates.TemplateResponse(request, "blocking/_rule_row.html", ctx)


@router.delete("/rulesets/{ruleset_id}/rules/{rule_id}")
async def delete_rule(
    ruleset_id: int,
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_auth),
):
    rule = await db.get(CustomRule, rule_id)
    if rule and rule.ruleset_id == ruleset_id:
        await db.delete(rule)
        await db.commit()
    return HTMLResponse("")
