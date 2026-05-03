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
├── database.py         # async engine, session factory, create_db_tables() + migrations
├── models.py           # ALL SQLModel table definitions
├── exceptions.py       # NotAuthenticated, TechnitiumUnavailable, TechnitiumAPIError, TechnitiumInvalidToken
├── crypto.py           # Fernet encrypt/decrypt for stored API tokens
├── dependencies.py     # require_auth, get_db, base_context (error_count, drift_count, discovery_count)
├── changelog.py        # log_change(), host_snapshot(), collection_snapshot()
├── sync.py             # sync_host(), unsync_host(), sync_blocking(), build_fqdn()
├── client/
│   ├── base.py         # TechnitiumClient — shared httpx.AsyncClient, _request(), check_connection()
│   ├── dns.py          # add/delete A + PTR records, ensure_zone_exists, delete_zone_if_empty
│   ├── dhcp.py         # reserved leases, normalize_mac() → aa:bb:cc:dd:ee:ff, _technitium_mac() → AA-BB-CC-DD-EE-FF
│   └── blocking.py     # Advanced Blocking app config: get/set/build_config/sync
├── routers/
│   ├── auth.py         # /login /logout /setup /profile
│   ├── settings.py     # /settings — zone + Technitium URL, connection test
│   ├── collections.py  # /collections — CRUD, host CRUD, blocking assignments, undo
│   ├── hosts.py        # /hosts — sortable/filterable all-hosts view
│   ├── blocking.py     # /blocking — block lists, rule sets, custom rules, manual sync
│   ├── discovery.py    # /discovery — discovered hosts from Technitium
│   ├── undo.py         # /undo — undo stack
│   └── drift.py        # drift detection background task
├── templates/
│   ├── base.html       # sidebar layout, alert banner, flash messages, undo button
│   ├── login.html      # standalone
│   ├── setup.html      # standalone first-run
│   ├── profile.html    # change password + Technitium API token
│   ├── settings/
│   ├── collections/    # index, detail, form, host partials, blocking partials
│   ├── hosts/
│   ├── blocking/
│   └── discovery/
└── static/
    ├── style.css
    └── harp.png        # favicon + sidebar logo
```

## Data Model

### Auth / Session

- **User** — HARP login credentials + encrypted Technitium API token
- **UserSession** — one row per login; scopes the undo stack

### Core

- **GlobalSettings** — singleton (id=1): `zone` (e.g. `home.lan`), `technitium_url`
- **Collection** — named group of hosts; optional `subdomain`; `blocking_enabled`; `block_as_nxdomain`; `sync_status` / `last_error`
- **CollectionSubnet** — CIDR ranges belonging to a Collection (e.g. `192.168.10.0/24`)
- **Host** — `hostname`, `ip_address`, `mac_address` (stored as `aa:bb:cc:dd:ee:ff`); belongs to a Collection; `sync_status` / `last_error`

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
- Reverse zone auto-deleted when its last PTR record is removed
- DHCP static lease (MAC → IP); MAC sent to Technitium as `AA-BB-CC-DD-EE-FF`, stored internally as `aa:bb:cc:dd:ee:ff`
- Advanced blocking: map collection subnets to a client group; apply assigned BlockListSubscriptions and RuleSets

Sync result is written back to `sync_status` / `last_error` on the entity.

### Advanced Blocking
- Targets the **Advanced Blocking** app (not built-in blocking) — supports per-collection rules
- Full overwrite on every sync: HARP is the sole source of truth; non-HARP groups are not preserved
- Group name = `collection.name` (1:1 mapping)
- Per-collection: `blocking_enabled` → `enableBlocking`; `block_as_nxdomain` → `blockAsNxDomain`
- `_sync_blocking_safe()` captures errors and surfaces them inline via HTMX OOB swap

### Undo stack
- Scoped to the current UserSession (cleared on logout)
- Global ordered stack — undo always pops the most recent non-undone change
- Undo by operation type:
  - `create` → delete entity + remove from Technitium
  - `update` → restore `before_state` + re-sync to Technitium
  - `delete` → recreate from `before_state` + re-push to Technitium
- No redo — a new change after an undo becomes the new top

### DNS zone
Single global zone (e.g. `home.lan`) — no new zones created. Collections have an optional `subdomain` that becomes part of the hostname: `hostname.subdomain.zone`. Without subdomain: `hostname.zone`. Reverse zones (`.in-addr.arpa`) are created on demand and deleted when empty.

### Sync status indicators
- `sync_status` values: `pending`, `synced`, `error`, `drift`
- Badges use CSS `::before` icons (✓ synced, ✗ error, ⚠ drift)
- `last_error` shown inline below badge; links to `/profile` when token-related
- Alert banner shows counts for errors, drift, and discovered hosts with links to filtered views
- `/hosts?filter=<status>` filters the all-hosts table by sync status

### HTMX partials
Same URL serves full page or fragment based on `HX-Request` header. Undo count polls via HTMX. Flash messages stored in the session, read once, rendered in `base.html`.

### Fernet key derivation
`SECRET_KEY` from env → SHA-256 → base64url → Fernet key. Keep `SECRET_KEY` stable or stored API tokens become unreadable.

### DB migrations
`create_db_tables()` in `database.py` runs on every startup. Schema changes use `ALTER TABLE ... ADD COLUMN` wrapped in `try/except` (idempotent). Data migrations (e.g. MAC normalisation) also run here.

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
| 2 | **done** | GlobalSettings UI (zone + Technitium URL/token), connectivity test |
| 3 | **done** | Collections + Hosts CRUD → auto-sync A/PTR/DHCP to Technitium |
| 4 | **done** | ChangeLog + global undo stack |
| 5 | **done** | BlockListSubscriptions + RuleSets + CustomRules CRUD |
| 6 | **done** | Assign blocking to Collections → sync to Technitium Advanced Blocking app |
| 7 | **done** | Sync status indicators, error handling polish |

## Technitium API Notes

- Base URL: `GlobalSettings.technitium_url` (e.g. `http://192.168.1.1:5380`)
- Auth: `token` query param on every request (token from `user/createToken` in Technitium)
- All calls go through `TechnitiumClient._request()` which raises typed exceptions for `status == "error"` and `status == "invalid-token"`
- DNS record endpoints: `/api/zones/records/add`, `/api/zones/records/delete`
- DHCP static lease: `/api/dhcp/scopes/addReservedLease`, `/api/dhcp/scopes/removeReservedLease`
- Advanced Blocking app: `GET /api/apps/config/get?name=Advanced Blocking`, `POST /api/apps/config/set` (form-encoded JSON body)
- `blockListUrlUpdateIntervalHours` and other top-level Advanced Blocking settings are preserved on sync (only `groups` and `networkGroupMap` are overwritten)
