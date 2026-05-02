# HARP — Host Address Registration Portal

A self-hosted web UI for managing [Technitium DNS Server](https://technitium.com/dns/) — focused on host management, DNS/DHCP sync, and per-collection blocking rules.

## Features

- Manage hosts organised into collections (e.g. `iot`, `servers`)
- Automatic sync of A records, PTR records, and DHCP static leases to Technitium
- Drift detection — flags hosts whose DNS records diverge from the database
- Host discovery — surfaces unknown A records in the zone for import
- Per-collection advanced blocking (block lists and custom rules) — in progress

## Stack

- FastAPI + Jinja2 + HTMX (server-rendered, no build step)
- SQLite via SQLModel + aiosqlite
- httpx async client wrapping the Technitium HTTP API

## Quick start

```bash
cp .env.example .env   # set SECRET_KEY at minimum
uv run python main.py  # starts on http://0.0.0.0:8000
```

Visit `/setup` on first run to create the admin user, then configure your Technitium URL and API token under Settings.

## License

MIT — see [LICENSE](LICENSE).
