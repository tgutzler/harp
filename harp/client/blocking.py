import json

from .base import TechnitiumClient

APP_NAME = "Advanced Blocking"


async def get_config(tc: TechnitiumClient) -> dict:
    resp = await tc._request("GET", "apps/config/get", params={"name": APP_NAME})
    raw = resp.get("config")
    if not raw:
        return {}
    return json.loads(raw) if isinstance(raw, str) else (raw or {})


async def set_config(tc: TechnitiumClient, config: dict) -> None:
    await tc._request(
        "POST", "apps/config/set",
        params={"name": APP_NAME},
        data={"config": json.dumps(config)},
    )


def _group_name(collection) -> str:
    return collection.subdomain or f"collection_{collection.id}"


def build_config(current: dict, collections_data: list[dict]) -> dict:
    """
    Rebuild the Advanced Blocking config from HARP collection data.
    Preserves groups and networkGroupMap entries that HARP does not manage.

    collections_data items: {
        "collection": Collection,
        "subnets": list[CollectionSubnet],
        "blocklists": list[BlockListSubscription],  # enabled only
        "rules": list[CustomRule],
    }
    """
    harp_group_names: set[str] = set()
    new_groups: list[dict] = []
    new_network_map: dict[str, str] = {}

    for item in collections_data:
        collection = item["collection"]
        subnets = item["subnets"]
        if not subnets:
            continue

        name = _group_name(collection)
        harp_group_names.add(name)

        block_list_urls = [bl.url for bl in item["blocklists"] if bl.enabled]
        allowed = [r.domain for r in item["rules"] if r.action == "allow"]
        blocked = [r.domain for r in item["rules"] if r.action == "block"]

        new_groups.append({
            "name": name,
            "enableBlocking": True,
            "allowTxtBlockingReport": True,
            "blockAsNxDomain": False,
            "blockingAddresses": [],
            "allowed": allowed,
            "blocked": blocked,
            "allowListUrls": [],
            "blockListUrls": block_list_urls,
            "allowedRegex": [],
            "blockedRegex": [],
            "regexAllowListUrls": [],
            "regexBlockListUrls": [],
            "adblockListUrls": [],
        })

        for sn in subnets:
            new_network_map[sn.cidr] = name

    preserved_groups = [
        g for g in current.get("groups", [])
        if g.get("name") not in harp_group_names
    ]
    preserved_network_map = {
        cidr: grp
        for cidr, grp in current.get("networkGroupMap", {}).items()
        if grp not in harp_group_names
    }

    return {
        **current,
        "groups": preserved_groups + new_groups,
        "networkGroupMap": {**preserved_network_map, **new_network_map},
    }


async def sync(tc: TechnitiumClient, collections_data: list[dict]) -> None:
    current = await get_config(tc)
    new_config = build_config(current, collections_data)
    await set_config(tc, new_config)
