# harp

A web UI for managing Technitium DNS Server — focused on host management, DNS/DHCP sync, and per-collection advanced blocking rules.

## Stack

- **FastAPI** + Jinja2 templates + HTMX (server-rendered, no build step)
- **SQLModel** + aiosqlite — async SQLite ORM (all models defined in `harp/models.py`)
- **httpx** async client — wraps Technitium HTTP API (`harp/client/`)
- **pydantic-settings** — typed env-var config (`harp/config.py`)
- **bcrypt** — password hashing; **cryptography (Fernet)** — encrypt stored API tokens
- **uvicorn** — ASGI server

## Running

```bash
cp .env.example .env          # edit SECRET_KEY at minimum
uv run python main.py         # starts on http://0.0.0.0:8000
```

First run: visit `/setup` to create the initial admin user.

## Project Layout

```
harp/
├── app.py              # FastAPI factory, lifespan, middleware, router mounts
├── config.py           # Settings (env vars)
├── database.py         # async engine, session factory, create_db_tables()
├── models.py           # ALL SQLModel table definitions
├── exceptions.py       # NotAuthenticated, TechnitiumError, etc.
├── crypto.py           # Fernet encrypt/decrypt for stored API tokens
├── dependencies.py     # require_auth, get_db, base_context
├── client/
│   └── base.py         # TechnitiumClient — shared httpx.AsyncClient, _request()
├── routers/
│   └── auth.py         # /login /logout /setup /profile
├── templates/
│   ├── base.html       # sidebar layout, flash messages, undo button
│   ├── login.html      # standalone (no sidebar)
│   ├── setup.html      # standalone first-run setup
│   └── profile.html    # change password + save Technitium API token
└── static/
    └── style.css
```

## Data Model

### Auth / Session

- **User** — HARP login credentials + encrypted Technitium API token
- **UserSession** — one row per login; scopes the undo stack

### Core

- **GlobalSettings** — singleton (id=1): `zone` (e.g. `home.lan`), `technitium_url`
- **Collection** — named group of hosts; optional `subdomain` prefix (e.g. `iot` → `host.iot.home.lan`); has `sync_status` / `last_error`
- **CollectionSubnet** — CIDR ranges belonging to a Collection (e.g. `192.168.10.0/24`)
- **Host** — `hostname`, `ip_address`, `mac_address`; belongs to a Collection; has `sync_status` / `last_error`

### Blocking

- **BlockListSubscription** — named URL subscription (e.g. EasyList); assigned to Collections
- **RuleSet** — named, reusable group of custom rules; assigned to Collections
- **CustomRule** — `domain` + `action: block|allow`; belongs to a RuleSet

### Many-to-many junction tables

- **CollectionBlockList** — Collection ↔ BlockListSubscription
- **CollectionRuleSet** — Collection ↔ RuleSet

### Undo

- **ChangeLog** — one row per mutation during a session
  - `session_id`, `entity_type`, `entity_id`, `operation` (create/update/delete)
  - `before_state` / `after_state` — JSON snapshots
  - `undone: bool`

## Key Design Decisions

### Auth model (two layers)
1. **HARP login** — own `users` table, bcrypt passwords, Starlette SessionMiddleware
2. **Technitium API token** — user generates a long-lived token in Technitium, pastes it into their HARP profile; stored Fernet-encrypted in the DB; never appears in the browser

Session cookie contains `user_id` + `session_id`. `session_id` scopes the undo stack for that login.

### Automatic sync
Every write to a Collection or Host triggers an immediate async sync to Technitium:
- A record + PTR record in the configured zone
- DHCP static lease (MAC → IP)
- Advanced blocking: map collection subnets to a client group; apply assigned BlockListSubscriptions and RuleSets

Sync result is written back to `sync_status` / `last_error` on the entity.

### Undo stack
- Scoped to the current UserSession (cleared on logout)
- Global ordered stack — undo always pops the most recent non-undone change
- Undo by operation type:
  - `create` → delete entity + remove from Technitium
  - `update` → restore `before_state` + re-sync to Technitium
  - `delete` → recreate from `before_state` + re-push to Technitium
- No redo — a new change after an undo becomes the new top

### DNS zone
Single global zone (e.g. `home.lan`) — no new zones created. Collections have an optional `subdomain` that becomes part of the hostname: `hostname.subdomain.zone`. Without subdomain: `hostname.zone`.

### HTMX partials
Same URL serves full page or fragment based on `HX-Request` header. Dashboard stats and undo count poll via HTMX. Flash messages stored in the session, read once, rendered in `base.html`.

### Fernet key derivation
`SECRET_KEY` from env → SHA-256 → base64url → Fernet key. Keep `SECRET_KEY` stable or stored API tokens become unreadable.

## Environment Variables

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | (unsafe default) | Change in production — also keys Fernet encryption |
| `DATABASE_URL` | `sqlite+aiosqlite:///./harp.db` | |
| `HOST` | `0.0.0.0` | |
| `PORT` | `8000` | |
| `LOG_LEVEL` | `info` | |
| `SESSION_MAX_AGE` | `86400` | seconds |

## Implementation Phases

| Phase | Status | What |
|---|---|---|
| 1 | **done** | App skeleton, HARP user auth (login/logout/setup/profile), session, full DB schema |
| 2 | todo | GlobalSettings UI (zone + Technitium URL/token), connectivity test |
| 3 | todo | Collections + Hosts CRUD → auto-sync A/PTR/DHCP to Technitium |
| 4 | todo | ChangeLog + global undo stack |
| 5 | todo | BlockListSubscriptions + RuleSets + CustomRules CRUD |
| 6 | todo | Assign blocking to Collections → sync to Technitium advanced blocking |
| 7 | todo | Sync status indicators, error handling polish, Docker |

## Technitium API Notes

- Base URL: `GlobalSettings.technitium_url` (e.g. `http://192.168.1.1:5380`)
- Auth: `Authorization: <token>` header (token from `user/createToken` in Technitium)
- All calls go through `TechnitiumClient._request()` which handles `status == "error"` and `status == "invalid-token"`
- DNS record endpoints: `/api/zones/records/add`, `/api/zones/records/delete`, `/api/zones/records/update`
- DHCP static lease: `/api/dhcp/leases/add`, `/api/dhcp/leases/remove`
- Advanced blocking: `/api/settings/get` + `/api/settings/set` for `blockingBypassList` / client-group mapping
