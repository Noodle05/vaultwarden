# Vaultwarden Agent Guide

Unofficial Bitwarden-compatible server written in Rust with the [Rocket](https://rocket.rs/) web framework.
See [README.md](README.md) for project overview, features, and deployment.

## Build & Test

```bash
# Build (requires at least one DB backend feature)
cargo build --features sqlite
cargo build --features "sqlite,mysql,postgresql"

# Run tests
cargo test --lib --features sqlite

# Format & lint
cargo fmt --all
cargo clippy --all-targets --all-features

# Run server (requires DATA_FOLDER)
DATA_FOLDER=./data cargo run --features sqlite

# Generate admin token hash
cargo run --features sqlite -- hash --preset bitwarden
```

**Rust toolchain**: Edition 2021, minimum 1.93.0 (see `rust-toolchain.toml`).

## Architecture

```
src/
├── main.rs              # Entry point: Rocket setup, job scheduler, signal handlers
├── config.rs            # Config via env vars + config.json, LazyLock singleton
├── api/
│   ├── mod.rs           # Route aggregation & re-exports
│   ├── core/            # Bitwarden core API (ciphers, folders, accounts, orgs, sends)
│   ├── admin.rs         # Admin panel endpoints
│   ├── notifications.rs # WebSocket hub (DashMap-based pub/sub, MessagePack encoding)
│   ├── push.rs          # Push notifications via Bitwarden relay
│   └── ...
├── db/
│   ├── mod.rs           # Connection pool, DbConnType enum, DbConn request guard
│   ├── models/          # Diesel entity models (User, Cipher, Folder, Org, ...)
│   └── schema.rs        # Diesel schema definitions (table! macros)
├── auth.rs              # JWT, login guards (Headers, AdminHeaders, ManagerHeaders)
├── crypto.rs            # Encryption utilities
├── error.rs             # Error type + err!/err_code!/err_json! macros
└── util.rs              # Rocket fairings (CORS, AppHeaders), misc helpers

migrations/              # Per-DB migration scripts (sqlite/, mysql/, postgresql/)
```

### Key Patterns

- **Routes**: Each `src/api/` module exports `routes() -> Vec<Route>`. Mounted in `main.rs::launch_rocket()`.
- **DB**: Diesel with `#[derive(MultiConnection)]` enum for multi-backend. All DB access is async via `tokio::task::spawn_blocking`.
- **Config**: Access via `CONFIG.field_name()`. All config is a `LazyLock` singleton.
- **Notifications**: `WS_USERS` and `WS_ANONYMOUS_SUBSCRIPTIONS` are global `DashMap` singletons. Handlers inject them via Rocket state (`Notify<'a>` = `&State<Arc<WebSocketUsers>>`).

## Code Conventions

### Error Handling

Use macros from `src/error.rs` — NEVER return `Err(...)` directly:

```rust
err!("User not found");                              // logs warning, returns Err
err_code!("Invalid claim", 401);                     // HTTP status code
err_json!("Validation failed", "email required");    // Bitwarden-formatted JSON error
err!(Db, "Database connection failed")               // wraps diesel error
err_silent!("Client closed connection")              // no log
```

### API Responses

```rust
pub type JsonResult = ApiResult<Json<Value>>;   // 200 with JSON body
pub type EmptyResult = ApiResult<()>;           // 200 with empty body
```

Return `Ok(Json(json!({...})))` for data, use error macros for failures.

### Request Guards (in `src/auth.rs`)

| Guard | Use |
|---|---|
| `Headers` | Authenticated user + device (most endpoints) |
| `AdminHeaders` | Org admin/owner |
| `ManagerHeadersLoose` | Org manager (lax member check) |
| `AdminToken` | Admin panel JWT |
| `ClientIp` | Client IP address |
| `DbConn` | Database connection (auto from pool) |

### As a Route Handler Parameter

```rust
#[post("/ciphers", data = "<data>")]
async fn post_ciphers(data: Json<CipherData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    // headers.user, headers.device, conn, nt.send_cipher_update(...)
}
```

### Notification Pattern

After any DB write, notify connected clients:

```rust
cipher.save(&conn).await?;                       // DB write FIRST
nt.send_cipher_update(                           // THEN notify
    UpdateType::SyncCipherUpdate, &cipher,
    &cipher.update_users_revision(&conn).await,
    &headers.device, None, &conn,
).await;
```

All `UpdateType` variants are in `src/api/notifications.rs`. Push notifications are handled internally by each `send_*` method — no separate call needed.

## DB Models

Located in `src/db/models/`. Diesel models follow this pattern:

```rust
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = users)]
pub struct User {
    pub uuid: UserId,          // newtype wrapper (UserId(String))
    pub email: String,
    // ...all columns listed...
}
// Newtype IDs:
#[derive(Debug, Clone, PartialEq, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Text)]
pub struct UserId(pub String);
```

Models use an async `save(&self, conn) -> EmptyResult` pattern that internally spawns blocking Diesel calls.

## WebSocket Architecture

- **Authenticated**: `GET /notifications/hub?access_token=...` → `WS_USERS` map
- **Anonymous**: `GET /notifications/anonymous-hub?token=...` → `WS_ANONYMOUS_SUBSCRIPTIONS` map
- Uses `rocket_ws` + MessagePack (`rmpv`) for binary encoding
- Each connection gets a `tokio::sync::mpsc::channel(100)` for message delivery
- Keep-alive: 15s ping interval

## Potential Pitfalls

- **Build requires at least one DB feature**: `--features sqlite` (or mysql/postgresql)
- **Cipher notifications must send to ALL affected users**: use `cipher.update_users_revision(conn)` to resolve user IDs from organization/collection memberships
- **`move_to_folder` only touches `folders_ciphers`**, not the `ciphers` table — the cipher's `updated_at` doesn't change
- **Soft-delete sets `deleted_at`** on ciphers (an UPDATE), hard-delete removes the row (a DELETE)
- **Migrations run automatically** on startup — never call `diesel migration run` manually
- **Config is env-var based** — see `src/config.rs` for all options. The `make_config!` macro generates all accessor methods
- **Docker build** uses Jinja2 templates: edit `docker/Dockerfile.j2`, then run `cd docker && make all`
