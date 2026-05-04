# HA Multi-Pod WebSocket Notification Design

> **Status**: This is the canonical design. Supersedes the earlier draft from the same sessions.

## Problem

In a multi-pod Kubernetes deployment, when Pod A handles a mutation and notifies its own WebSocket clients, Pod B's clients receive nothing — each pod only knows about its own connections.

```
User A (WS)  ───> Pod-1 ───> DB (shared)
User B (HTTP) ──> Pod-2 ───> DB (shared)
```

## Architecture

```
┌──────────────────────────────────────┐
│  Kubernetes Pod                      │
│  ┌──────────────┐  ┌──────────────┐  │
│  │ vaultwarden  │  │   Sidecar    │  │
│  │              │◄─┤              │  │
│  │ WS Hub       │  │ LISTEN       │  │
│  │ /internal/   │  │ vw_events    │  │
│  │   notify     │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  │
│         │                 │          │
└─────────┼─────────────────┼──────────┘
          │                 │
   ┌──────┴─────────────────┴──────┐
   │      PostgreSQL (shared)      │
   │  ┌────────────────────────┐   │
   │  │  TRIGGER → pg_notify() │   │
   │  └────────────────────────┘   │
   └───────────────────────────────┘
```

1. Pod A handles mutation → notifies its own WS clients (existing code, unchanged)
2. Pod A writes to shared PostgreSQL
3. PostgreSQL trigger fires `pg_notify('vw_events', payload)`
4. Pod B's sidecar receives via `LISTEN vw_events`
5. Sidecar POSTs to `http://localhost:{port}/internal/notify`
6. Pod B's internal API handler looks up affected objects from DB, determines affected users, sends **WS-only** replay

Push notifications go through Bitwarden's external relay (`push.bitwarden.com`), not local WebSocket. The originating pod already sends push. Replaying would duplicate — the internal API sends WS only.

## Design Decisions

- **Sidecar pattern**: No peer discovery needed (calls localhost). No auth needed (localhost only). No changes to existing API handlers.
- **WS-only replay**: Internal API calls `replay_*` helpers that only send WebSocket messages, not push. Avoids duplicate push notifications for mobile devices.
- **Per-cipher bulk (v1)**: Bulk operations send per-cipher notifications. Clients handle duplicate re-sync messages gracefully. Could be optimized with batching later.
- **PostgreSQL first**: MySQL can use a polling approach via a `vw_events` table later. SQLite needs none of this.

---

## Internal REST API

### Endpoint

```
POST /internal/notify
Content-Type: application/json

{
    "table": "ciphers",
    "id": "uuid-of-changed-row",
    "operation": "update",
    "changed_columns": ["password_hash", "security_stamp"],
    "old": {"user_uuid": "..."},
    "new": {"user_uuid": "..."}
}
```

### Fields

| Field | Required | Purpose |
|-------|----------|---------|
| `table` | Yes | Which table changed |
| `id` | Yes | UUID of the changed row (for junction tables: the parent cipher UUID) |
| `operation` | Yes | `insert` / `update` / `delete` |
| `changed_columns` | For `users` UPDATE | Which columns changed — handler uses this to decide LogOut vs SyncSettings |
| `old` | For DELETE | Old row values so handler can reconstruct affected users when the row is gone |
| `new` | Optional | New row values |

### Request Guard

```rust
struct LocalhostOnly;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LocalhostOnly {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if request.client_ip().map(|ip| ip.is_loopback()).unwrap_or(false) {
            Outcome::Success(LocalhostOnly)
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}
```

### Handler Logic

```rust
match (table, operation) {
    ("ciphers", "insert")          => replay_cipher_update(SyncCipherCreate, id),
    ("ciphers", "update")          => replay_cipher_update(SyncCipherUpdate, id),
    ("ciphers", "delete")          => replay_cipher_update(SyncLoginDelete, id, old),   // use old for user list
    ("attachments", _)             => replay_cipher_update(SyncCipherUpdate, id),
    ("ciphers_collections", _)     => replay_cipher_update(SyncCipherUpdate, id),
    ("folders_ciphers", _)         => replay_cipher_update(SyncCipherUpdate, id),
    ("folders", "insert")          => replay_folder_update(SyncFolderCreate, id),
    ("folders", "update")          => replay_folder_update(SyncFolderUpdate, id),
    ("folders", "delete")          => replay_folder_update(SyncFolderDelete, id, old),
    ("sends", "insert")            => replay_send_update(SyncSendCreate, id),
    ("sends", "update")            => replay_send_update(SyncSendUpdate, id),
    ("sends", "delete")            => replay_send_update(SyncSendDelete, id, old),
    ("users", "update")            => {
        let logout_cols = ["password_hash", "security_stamp", "client_kdf_type",
                           "client_kdf_iter", "client_kdf_memory", "client_kdf_parallelism",
                           "email", "api_key", "enabled"];
        if changed_columns.iter().any(|c| logout_cols.contains(&c.as_str())) {
            replay_logout(id)
        } else {
            replay_user_update(SyncSettings, id)
        }
    },
    ("auth_requests", "insert")    => replay_auth_request(id),
    ("auth_requests", "update")    => replay_auth_response(id),
    ("users_organizations", _)     => {
        // Only replay WS if member status changed to Confirmed, or member removed
        // Otherwise return 200 (no-op — change doesn't warrant real-time notification)
        if should_notify(old, new) {
            replay_user_update(SyncOrgKeys, new.user_uuid)
        }
    },
    ("archives", "insert")         => replay_cipher_update(SyncCipherUpdate, id),
    ("archives", "delete")         => replay_cipher_update(SyncCipherUpdate, id),
}
```

### New Methods on WebSocketUsers

Add `replay_*` methods that are WS-only (no push):

```rust
impl WebSocketUsers {
    async fn replay_cipher_update(&self, conn: &DbConn, uuid: &str, u_type: UpdateType, old_data: Option<Value>) {
        let cipher = // load from DB or reconstruct from old_data for DELETE
        let users = cipher.update_users_revision(conn).await;
        for user_uuid in users {
            self.send_update(&user_uuid, &create_update(...)).await;
        }
        // NO push call
    }
    
    async fn replay_folder_update(...) { /* WS only */ }
    async fn replay_send_update(...) { /* WS only */ }
    async fn replay_user_update(...) { /* WS only */ }
    async fn replay_logout(...) { /* WS only */ }
    async fn replay_auth_request(...) { /* WS only */ }
    async fn replay_auth_response(...) { /* WS only */ }
}
```

### New Files

- `src/api/internal.rs` — `POST /internal/notify` endpoint + handler + `LocalhostOnly` guard
- Update `src/api/mod.rs` — add `mod internal`
- Update `src/main.rs` — conditionally mount `/internal` routes
- Update `src/api/notifications.rs` — add `replay_*` WS-only helper methods on `WebSocketUsers`

### Config

```rust
// src/config.rs
internal_notify_enabled: bool, false, def, false;
```

---

## Tables Requiring Triggers (10)

| # | Table | Operations | Maps to UpdateType |
|---|-------|-----------|-------------------|
| 1 | **ciphers** | INSERT/UPDATE/DELETE | SyncCipherCreate / SyncCipherUpdate / SyncLoginDelete |
| 2 | **attachments** | INSERT/DELETE | SyncCipherUpdate (on parent cipher) |
| 3 | **ciphers_collections** | INSERT/DELETE | SyncCipherUpdate (on parent cipher) |
| 4 | **folders_ciphers** | INSERT/DELETE | SyncCipherUpdate (on parent cipher) |
| 5 | **folders** | INSERT/UPDATE/DELETE | SyncFolderCreate / SyncFolderUpdate / SyncFolderDelete |
| 6 | **sends** | INSERT/UPDATE/DELETE | SyncSendCreate / SyncSendUpdate / SyncSendDelete |
| 7 | **users** | UPDATE (10 columns*) | LogOut / SyncSettings |
| 8 | **archives** | INSERT/DELETE | SyncCipherUpdate (on parent cipher) |
| 9 | **auth_requests** | INSERT/UPDATE | AuthRequest / AuthRequestResponse |
| 10 | **users_organizations** | INSERT/UPDATE/DELETE | SyncOrgKeys (only on confirm or remove) |

*\*users columns tracked: `password_hash`, `security_stamp`, `client_kdf_type`, `client_kdf_iter`, `client_kdf_memory`, `client_kdf_parallelism`, `email`, `api_key`, `enabled`, `equivalent_domains`*

### Tables NOT Needed

| Table | Reason |
|-------|--------|
| **users_collections** | read_only/hide_passwords/manage changes — no WS notification in Bitwarden protocol |
| **groups** | access_all changes — no WS notification |
| **groups_users** | group membership changes — no WS notification |
| **collections_groups** | group-collection associations — no WS notification |
| **devices** | Client-side push registration, no cross-pod sync |
| **event** | Append-only log |
| **favorites** | Local client state |
| **collections** | Collection CRUD has no WS notification |
| **organizations** | Org settings changes have no WS notification |
| **org_policies** | Policy changes picked up on next sync |
| **twofactor, sso_*, emergency_access** | Handled via auth flow / email / scheduled jobs |

---

## PostgreSQL Triggers

A single generic trigger function handles all tables:

```sql
CREATE OR REPLACE FUNCTION notify_table_change()
RETURNS TRIGGER AS $$
DECLARE
    row_id TEXT;
    changed_cols JSONB := '[]'::jsonb;
BEGIN
    -- Composite-key and child tables: use cipher_uuid as the identifier
    IF TG_TABLE_NAME IN ('folders_ciphers', 'ciphers_collections') THEN
        row_id := COALESCE(NEW.cipher_uuid, OLD.cipher_uuid)::text;
    ELSIF TG_TABLE_NAME = 'attachments' THEN
        row_id := COALESCE(NEW.cipher_uuid, OLD.cipher_uuid)::text;
    ELSIF TG_TABLE_NAME = 'archives' THEN
        row_id := COALESCE(NEW.cipher_uuid, OLD.cipher_uuid)::text;
    ELSE
        row_id := COALESCE(NEW.uuid, OLD.uuid)::text;
    END IF;

    -- For users table, track which relevant columns changed
    IF TG_TABLE_NAME = 'users' AND TG_OP = 'UPDATE' THEN
        WITH cols AS (
            SELECT 'password_hash' AS col WHERE NEW.password_hash IS DISTINCT FROM OLD.password_hash
            UNION ALL SELECT 'security_stamp' WHERE NEW.security_stamp IS DISTINCT FROM OLD.security_stamp
            UNION ALL SELECT 'client_kdf_type' WHERE NEW.client_kdf_type IS DISTINCT FROM OLD.client_kdf_type
            UNION ALL SELECT 'client_kdf_iter' WHERE NEW.client_kdf_iter IS DISTINCT FROM OLD.client_kdf_iter
            UNION ALL SELECT 'client_kdf_memory' WHERE NEW.client_kdf_memory IS DISTINCT FROM OLD.client_kdf_memory
            UNION ALL SELECT 'client_kdf_parallelism' WHERE NEW.client_kdf_parallelism IS DISTINCT FROM OLD.client_kdf_parallelism
            UNION ALL SELECT 'email' WHERE NEW.email IS DISTINCT FROM OLD.email
            UNION ALL SELECT 'api_key' WHERE NEW.api_key IS DISTINCT FROM OLD.api_key
            UNION ALL SELECT 'enabled' WHERE NEW.enabled IS DISTINCT FROM OLD.enabled
            UNION ALL SELECT 'equivalent_domains' WHERE NEW.equivalent_domains IS DISTINCT FROM OLD.equivalent_domains
        )
        SELECT jsonb_agg(col) INTO changed_cols FROM cols;
    END IF;

    PERFORM pg_notify('vw_events', jsonb_build_object(
        'table', TG_TABLE_NAME,
        'id', row_id,
        'operation', LOWER(TG_OP),
        'changed_columns', COALESCE(changed_cols, '[]'::jsonb),
        'old', CASE
            WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD)
            ELSE '{}'::jsonb
        END,
        'new', CASE
            WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW)
            ELSE '{}'::jsonb
        END
    )::text);

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Triggers on each table
CREATE TRIGGER ciphers_notify AFTER INSERT OR UPDATE OR DELETE ON ciphers FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER attachments_notify AFTER INSERT OR DELETE ON attachments FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER ciphers_collections_notify AFTER INSERT OR DELETE ON ciphers_collections FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER folders_ciphers_notify AFTER INSERT OR DELETE ON folders_ciphers FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER folders_notify AFTER INSERT OR UPDATE OR DELETE ON folders FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER sends_notify AFTER INSERT OR UPDATE OR DELETE ON sends FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER users_notify AFTER UPDATE ON users FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER archives_notify AFTER INSERT OR DELETE ON archives FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER auth_requests_notify AFTER INSERT OR UPDATE ON auth_requests FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER users_organizations_notify AFTER INSERT OR UPDATE OR DELETE ON users_organizations FOR EACH ROW EXECUTE FUNCTION notify_table_change();
```

---

## Sidecar

A minimal binary that:
- Connects to the same PostgreSQL as vaultwarden (rw service on CloudNativePG)
- Executes `LISTEN vw_events`
- On each notification, POSTs the JSON payload to `http://localhost:{port}/internal/notify`
- Reconnects with backoff on disconnect (handles failover)
- No PgBouncer for this connection (transaction pooling breaks `LISTEN`)

---

## Edge Cases

### Soft delete vs Hard delete
- Soft delete: `UPDATE ciphers SET deleted_at = now()` → trigger fires with `operation: "update"` → `SyncCipherUpdate`
- Hard delete: `DELETE FROM ciphers` → trigger fires with `operation: "delete"` + `old` row → `SyncLoginDelete`
- Restore from trash: `UPDATE ciphers SET deleted_at = NULL` → `SyncCipherUpdate`

### Bulk operations
Purge of 500 ciphers fires 500 triggers. Each results in a separate WS message per user. Clients handle duplicate re-sync requests gracefully. Batching can be added as an optimization later.

### Folder move (move_to_folder)
Only touches `folders_ciphers` table — cipher's `updated_at` does not change. The `folders_ciphers` trigger is essential.

### Attachment changes
Only touches `attachments` table — cipher's `updated_at` does not change. The `attachments` trigger is essential.

### Archive/unarchive
Only touches `archives` table — `ciphers.updated_at` does not change. The `archives` trigger is essential.

### Auth request flow
- INSERT → anonymous WS subscriber gets `AuthRequest`
- UPDATE (approved column) → authenticated WS client gets `AuthRequestResponse`

### Concurrent modifications
If two pods modify the same record, both fire triggers. Each sidecar calls its local `/internal/notify`. The client receives two notifications and re-syncs twice — harmless.

---

## Implementation Order

1. Add `internal_notify_enabled` config option (`src/config.rs`)
2. Add `LocalhostOnly` request guard + `POST /internal/notify` endpoint (`src/api/internal.rs`)
3. Add `replay_*` WS-only methods on `WebSocketUsers` (`src/api/notifications.rs`)
4. Mount the internal routes conditionally (`src/main.rs`, `src/api/mod.rs`)
5. Create PostgreSQL migration with triggers
6. Build sidecar binary
