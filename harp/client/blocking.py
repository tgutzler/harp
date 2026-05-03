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
        data={"config": json.dumps(config, indent=2)},
    )


def build_config(current: dict, collections_data: list[dict]) -> dict:
    """
    Rebuilds the entire Advanced Blocking config from HARP collections.
    All groups and networkGroupMap entries are replaced — nothing from
    the existing Technitium config is preserved.

    collections_data items: {
        "collection": Collection,
        "subnets": list[CollectionSubnet],
        "blocklists": list[BlockListSubscription],
        "rules": list[CustomRule],
    }
    """
    groups: list[dict] = []
    network_map: dict[str, str] = {}

    for item in collections_data:
        collection = item["collection"]
        name = collection.name

        block_list_urls = [bl.url for bl in item["blocklists"] if bl.enabled]
        allowed = [r.domain for r in item["rules"] if r.action == "allow"]
        blocked = [r.domain for r in item["rules"] if r.action == "block"]

        groups.append({
            "name": name,
            "enableBlocking": collection.blocking_enabled,
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

        for sn in item["subnets"]:
            network_map[sn.cidr] = name

    return {
        **current,
        "groups": groups,
        "networkGroupMap": network_map,
    }


async def sync(tc: TechnitiumClient, collections_data: list[dict]) -> None:
    current = await get_config(tc)
    new_config = build_config(current, collections_data)
    await set_config(tc, new_config)
