# HA WebSocket Notifications — Design Document

## Problem

In a multi-pod Kubernetes deployment behind a load balancer, when one instance modifies the database, other instances don't know about it and can't notify their connected WebSocket clients.

```
User A (WS) ───> Pod-1 ───> DB (shared)
User B (HTTP) ──> Pod-2 ───> DB (shared)
```

When User B modifies a cipher via Pod-2, User A (connected to Pod-1's WebSocket) never receives the real-time sync notification.

## Solution: Sidecar + DB Triggers + Internal REST API

### Architecture

```
┌──────────────────────────────────────┐
│  Kubernetes Pod                      │
│  ┌──────────────┐  ┌──────────────┐  │
│  │ vaultwarden  │  │   Sidecar    │  │
│  │              │◄─┤ (Go/Rust/    │  │
│  │ WS Hub       │  │  Python)     │  │
│  │ /internal/   │  │ LISTEN       │  │
│  │   notify     │  │ table_change │  │
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

1. **PostgreSQL triggers** fire on INSERT/UPDATE/DELETE of relevant tables, calling `pg_notify('table_change', ...)`
2. **Sidecar** LISTENs to `table_change` channel, receives JSON payloads
3. **Sidecar** calls `POST http://localhost:8080/internal/notify` on the local vaultwarden instance
4. **Vaultwarden's internal endpoint** loads the changed row from DB, determines affected users and UpdateType, sends WebSocket notifications to locally-connected clients

### Why not peer-to-peer?

- No peer discovery needed (sidecar calls localhost)
- No authentication needed (localhost only)
- No changes to existing API handlers
- Kubernetes-native sidecar pattern

### Push notifications are already HA-safe

Push goes through Bitwarden's external relay (`push.bitwarden.com`), not local WebSocket. No changes needed.

---

## Internal REST API Design

### Endpoint

```
POST http://localhost:8080/internal/notify
Content-Type: application/json

{
    "table": "ciphers",           // See table list below
    "id": "uuid-of-changed-row",
    "operation": "update",        // insert | update | delete
    "changed_columns": ["password_hash", "security_stamp"]  // users table only
}
```

The internal endpoint:
1. Loads the row from the shared database
2. Determines the correct `UpdateType` based on (table, operation, changed_columns)
3. Resolves affected user IDs (e.g., `cipher.update_users_revision()`)
4. Sends WebSocket messages to locally-connected clients only (no push)
5. Also handles `AnonymousWebSocketSubscriptions` for auth request responses

### Config

Add to `src/config.rs`:
```rust
/// Enable the internal HA notification endpoint (localhost only)
ha_internal_enabled:    bool,    false,  def,    false;
```

### New Files

- `src/api/internal.rs` — `POST /internal/notify` endpoint + handler
- Update `src/api/mod.rs` — add `mod internal`
- Update `src/main.rs` — conditionally mount `/internal` routes

### Changes to existing files

- `src/api/notifications.rs` — add `replay_*` helper methods on `WebSocketUsers` and `AnonymousWebSocketSubscriptions` that only do WS (not push)
- `src/config.rs` — add `ha_internal_enabled` config option

---

## Tables Requiring Triggers

| # | Table | Operations | Maps to UpdateType |
|---|---|---|---|
| 1 | `ciphers` | INSERT/UPDATE/DELETE | SyncCipherCreate / SyncCipherUpdate / SyncLoginDelete |
| 2 | `attachments` | INSERT/DELETE | SyncCipherUpdate (on parent cipher) |
| 3 | `ciphers_collections` | INSERT/DELETE | SyncCipherUpdate (on parent cipher) |
| 4 | `folders_ciphers` | INSERT/DELETE | SyncCipherUpdate (on parent cipher) |
| 5 | `folders` | INSERT/UPDATE/DELETE | SyncFolderCreate / SyncFolderUpdate / SyncFolderDelete |
| 6 | `sends` | INSERT/UPDATE/DELETE | SyncSendCreate / SyncSendUpdate / SyncSendDelete |
| 7 | `users` | UPDATE | LogOut / SyncSettings (column-dependent) |
| 8 | `auth_requests` | INSERT/UPDATE | AuthRequest / AuthRequestResponse |
| 9 | `users_organizations` | UPDATE/DELETE | SyncOrgKeys |

### NOT needed

- `groups`, `groups_users`, `collections_groups` — no WS notifications (not supported in UpdateType)
- `collections` — collection create/delete has no WS notification
- `devices` — no WS notification
- `emergency_access` — only email notifications
- `favorites` — no WS notification

---

## Type Mapping (Internal API → UpdateType)

```rust
match (table, operation) {
    ("ciphers", "insert")                           => SyncCipherCreate,
    ("ciphers", "update")                           => SyncCipherUpdate,
    ("ciphers", "delete")                           => SyncLoginDelete,
    ("attachments", "insert" | "delete")            => SyncCipherUpdate,
    ("ciphers_collections", "insert" | "delete")    => SyncCipherUpdate,
    ("folders_ciphers", "insert" | "delete")        => SyncCipherUpdate,
    ("folders", "insert")                           => SyncFolderCreate,
    ("folders", "update")                           => SyncFolderUpdate,
    ("folders", "delete")                           => SyncFolderDelete,
    ("sends", "insert")                             => SyncSendCreate,
    ("sends", "update")                             => SyncSendUpdate,
    ("sends", "delete")                             => SyncSendDelete,
    ("users", "update") => {
        let logout_cols = ["password_hash", "security_stamp", "client_kdf_type",
                           "client_kdf_iter", "email", "akey", "enabled"];
        if changed_columns.iter().any(|c| logout_cols.contains(&c.as_str())) {
            LogOut
        } else {
            SyncSettings
        }
    }
    ("auth_requests", "insert")                     => AuthRequest,
    ("auth_requests", "update")                     => AuthRequestResponse,
    ("users_organizations", "update" | "delete")    => SyncOrgKeys,
}
```

---

## PostgreSQL Trigger SQL

```sql
CREATE OR REPLACE FUNCTION notify_table_change()
RETURNS TRIGGER AS $$
DECLARE
    row_id TEXT;
    changed_cols JSONB := '[]'::jsonb;
BEGIN
    -- Composite-key tables: use cipher_uuid as the identifier
    IF TG_TABLE_NAME IN ('folders_ciphers', 'ciphers_collections') THEN
        row_id := COALESCE(NEW.cipher_uuid, OLD.cipher_uuid)::text;
    ELSE
        row_id := COALESCE(NEW.uuid, OLD.uuid)::text;
    END IF;

    -- For users table, track which columns changed
    IF TG_TABLE_NAME = 'users' AND TG_OP = 'UPDATE' THEN
        SELECT jsonb_agg(col) INTO changed_cols FROM (
            SELECT 'password_hash' AS col WHERE NEW.password_hash IS DISTINCT FROM OLD.password_hash
            UNION ALL SELECT 'security_stamp' WHERE NEW.security_stamp IS DISTINCT FROM OLD.security_stamp
            UNION ALL SELECT 'client_kdf_type' WHERE NEW.client_kdf_type IS DISTINCT FROM OLD.client_kdf_type
            UNION ALL SELECT 'client_kdf_iter' WHERE NEW.client_kdf_iter IS DISTINCT FROM OLD.client_kdf_iter
            UNION ALL SELECT 'email' WHERE NEW.email IS DISTINCT FROM OLD.email
            UNION ALL SELECT 'akey' WHERE NEW.akey IS DISTINCT FROM OLD.akey
            UNION ALL SELECT 'enabled' WHERE NEW.enabled IS DISTINCT FROM OLD.enabled
            UNION ALL SELECT 'equivalent_domains' WHERE NEW.equivalent_domains IS DISTINCT FROM OLD.equivalent_domains
        ) t;
    END IF;

    PERFORM pg_notify('table_change', jsonb_build_object(
        'table', TG_TABLE_NAME,
        'id', row_id,
        'operation', LOWER(TG_OP),
        'changed_columns', COALESCE(changed_cols, '[]'::jsonb)
    )::text);

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Trigger on each table
CREATE TRIGGER ciphers_notify AFTER INSERT OR UPDATE OR DELETE ON ciphers FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER attachments_notify AFTER INSERT OR DELETE ON attachments FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER ciphers_collections_notify AFTER INSERT OR DELETE ON ciphers_collections FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER folders_ciphers_notify AFTER INSERT OR DELETE ON folders_ciphers FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER folders_notify AFTER INSERT OR UPDATE OR DELETE ON folders FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER sends_notify AFTER INSERT OR UPDATE OR DELETE ON sends FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER users_notify AFTER UPDATE ON users FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER auth_requests_notify AFTER INSERT OR UPDATE ON auth_requests FOR EACH ROW EXECUTE FUNCTION notify_table_change();
CREATE TRIGGER users_organizations_notify AFTER UPDATE OR DELETE ON users_organizations FOR EACH ROW EXECUTE FUNCTION notify_table_change();
```

---

## Edge Cases

### Bulk operations
Bulk cipher operations (delete multiple, archive multiple) send per-cipher notifications instead of a single `SyncCiphers` user-level sync. This is more chatty but clients handle both correctly.

### Soft-delete vs Hard-delete
- Soft-delete: `UPDATE ciphers SET deleted_at = now()` → `SyncCipherUpdate`
- Hard-delete: `DELETE FROM ciphers` → `SyncLoginDelete`

### Folder move (move_to_folder)
Only touches `folders_ciphers` table — cipher's `updated_at` does NOT change. This is why `folders_ciphers` needs its own trigger.

### Concurrent modifications
If two instances modify the same record simultaneously, both fire triggers. Each sidecar calls its local `/internal/notify`. The client receives two notifications and re-syncs twice — harmless.
