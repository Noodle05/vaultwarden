use chrono::Utc;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    serde::json::Json,
    Request,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

use crate::{
    api::{
        notifications::{WebSocketUsers, WS_ANONYMOUS_SUBSCRIPTIONS},
        UpdateType,
    },
    db::{
        models::{
            AuthRequest, AuthRequestId, Cipher, CipherId, Folder, FolderId, Membership, OrganizationId, Send as DbSend,
            SendId, User, UserId,
        },
        DbConn,
    },
    CONFIG,
};

/// Request guard: only accept connections from localhost.
pub struct LocalhostOnly;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LocalhostOnly {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(ip) = request.client_ip() {
            if ip.is_loopback() {
                return Outcome::Success(LocalhostOnly);
            }
        }
        Outcome::Error((Status::Forbidden, ()))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotifyPayload {
    table: String,
    id: String,
    operation: String,
    #[serde(default)]
    changed_columns: Vec<String>,
    #[serde(default)]
    old: Value,
    #[serde(default)]
    new: Value,
}

#[post("/notify", data = "<payload>")]
async fn post_notify(
    payload: Json<NotifyPayload>,
    conn: DbConn,
    ws_users: &rocket::State<Arc<WebSocketUsers>>,
    _guard: LocalhostOnly,
) -> Status {
    let payload = payload.into_inner();

    match dispatch(&payload, &conn, ws_users).await {
        Ok(()) => Status::Ok,
        Err(e) => {
            error!("Internal notify error for {}.{}: {}", payload.table, payload.id, e);
            Status::InternalServerError
        }
    }
}

async fn dispatch(
    p: &NotifyPayload,
    conn: &DbConn,
    ws_users: &WebSocketUsers,
) -> Result<(), &'static str> {
    match p.table.as_str() {
        "ciphers" => handle_cipher(p, conn, ws_users).await,
        "attachments" | "ciphers_collections" | "folders_ciphers" | "archives" => {
            handle_child_cipher(p, conn, ws_users).await
        }
        "folders" => handle_folder(p, ws_users).await,
        "sends" => handle_send(p, conn, ws_users).await,
        "users" => handle_user(p, conn, ws_users).await,
        "auth_requests" => handle_auth_request(p, conn, ws_users).await,
        "users_organizations" => handle_users_org(p, conn, ws_users).await,
        _ => {
            debug!("Internal notify: unhandled table '{}'", p.table);
            Ok(())
        }
    }
}

fn json_str<'a>(val: &'a Value, key: &str) -> Option<&'a str> {
    val.get(key).and_then(|v| v.as_str())
}

// ── helpers ─────────────────────────────────────────────────

fn cipher_id(s: &str) -> CipherId {
    CipherId::from(s.to_string())
}
fn folder_id(s: &str) -> FolderId {
    FolderId::from(s.to_string())
}
fn send_id(s: &str) -> SendId {
    SendId::from(s.to_string())
}
fn auth_id(s: &str) -> AuthRequestId {
    AuthRequestId::from(s.to_string())
}
fn org_id(s: &str) -> OrganizationId {
    OrganizationId::from(s.to_string())
}
fn user_id(s: &str) -> UserId {
    UserId::from(s.to_string())
}

// ── ciphers ────────────────────────────────────────────────

async fn handle_cipher(
    p: &NotifyPayload,
    conn: &DbConn,
    ws_users: &WebSocketUsers,
) -> Result<(), &'static str> {
    let ut = match p.operation.as_str() {
        "insert" => UpdateType::SyncCipherCreate,
        "delete" => UpdateType::SyncLoginDelete,
        _ => UpdateType::SyncCipherUpdate,
    };

    let cid = cipher_id(&p.id);

    // INSERT/UPDATE: load cipher from DB to determine affected users
    if p.operation != "delete" {
        if let Some(cipher) = Cipher::find_by_uuid(&cid, conn).await {
            let user_ids = cipher.update_users_revision(conn).await;
            if !user_ids.is_empty() {
                ws_users.replay_cipher_update(ut, &cipher, &user_ids).await;
            }
            return Ok(());
        }
    }

    // DELETE (or cipher not found): reconstruct from old payload
    let old_user = json_str(&p.old, "user_uuid");
    let old_org = json_str(&p.old, "organization_uuid");

    if let Some(uid) = old_user {
        let cipher = minimal_cipher(cid, Some(user_id(uid)), None);
        ws_users.replay_cipher_update(ut, &cipher, &[user_id(uid)]).await;
    } else if let Some(oid) = old_org {
        let members = Membership::find_by_org(&org_id(oid), conn).await;
        let user_ids: Vec<UserId> = members.iter().map(|m| m.user_uuid.clone()).collect();
        if !user_ids.is_empty() {
            let cipher = minimal_cipher(cid, None, Some(org_id(oid)));
            ws_users.replay_cipher_update(ut, &cipher, &user_ids).await;
        }
    }

    Ok(())
}

fn minimal_cipher(uuid: CipherId, user_uuid: Option<UserId>, org_uuid: Option<OrganizationId>) -> Cipher {
    let now = Utc::now().naive_utc();
    Cipher {
        uuid,
        created_at: now,
        updated_at: now,
        user_uuid,
        organization_uuid: org_uuid,
        key: None,
        atype: 1, // arbitrary; only uuid, user_uuid, org_uuid, updated_at are used by the replay payload
        name: String::new(),
        notes: None,
        fields: None,
        data: String::new(),
        password_history: None,
        deleted_at: None,
        reprompt: None,
    }
}

// ── child tables (attachments, ciphers_collections, folders_ciphers, archives) ──

async fn handle_child_cipher(
    p: &NotifyPayload,
    conn: &DbConn,
    ws_users: &WebSocketUsers,
) -> Result<(), &'static str> {
    let cid = cipher_id(&p.id);

    if let Some(cipher) = Cipher::find_by_uuid(&cid, conn).await {
        let user_ids = cipher.update_users_revision(conn).await;
        if !user_ids.is_empty() {
            ws_users.replay_cipher_update(UpdateType::SyncCipherUpdate, &cipher, &user_ids).await;
        }
    } else if p.operation == "delete" {
        // Cipher may have been deleted first (CASCADE). Fall back to old payload.
        if let Some(uid) = json_str(&p.old, "user_uuid") {
            let cipher = minimal_cipher(cid, Some(user_id(uid)), None);
            ws_users
                .replay_cipher_update(UpdateType::SyncCipherUpdate, &cipher, &[user_id(uid)])
                .await;
        }
    }
    Ok(())
}

// ── folders ────────────────────────────────────────────────

async fn handle_folder(p: &NotifyPayload, ws_users: &WebSocketUsers) -> Result<(), &'static str> {
    let ut = match p.operation.as_str() {
        "insert" => UpdateType::SyncFolderCreate,
        "delete" => UpdateType::SyncFolderDelete,
        _ => UpdateType::SyncFolderUpdate,
    };

    // Resolve user_uuid: DELETE uses old, INSERT/UPDATE uses new
    let uid = json_str(&p.old, "user_uuid")
        .or_else(|| json_str(&p.new, "user_uuid"));

    let Some(uid) = uid else {
        return Ok(());
    };

    // Construct a minimal Folder for the WS payload (replay only needs uuid + user_uuid + updated_at)
    let folder = Folder {
        uuid: folder_id(&p.id),
        user_uuid: user_id(uid),
        name: String::new(),
        created_at: Utc::now().naive_utc(),
        updated_at: Utc::now().naive_utc(),
    };
    ws_users.replay_folder_update(ut, &folder).await;
    Ok(())
}

// ── sends ──────────────────────────────────────────────────

async fn handle_send(
    p: &NotifyPayload,
    conn: &DbConn,
    ws_users: &WebSocketUsers,
) -> Result<(), &'static str> {
    let ut = match p.operation.as_str() {
        "insert" => UpdateType::SyncSendCreate,
        "delete" => UpdateType::SyncSendDelete,
        _ => UpdateType::SyncSendUpdate,
    };

    let sid = send_id(&p.id);

    // INSERT/UPDATE: load send from DB to get full info and call update_users_revision
    if p.operation != "delete" {
        if let Some(send) = DbSend::find_by_uuid(&sid, conn).await {
            let user_ids = send.update_users_revision(conn).await;
            if !user_ids.is_empty() {
                ws_users.replay_send_update(ut, &send, &user_ids).await;
            }
            return Ok(());
        }
    }

    // DELETE: use old.user_uuid from trigger
    if let Some(uid) = json_str(&p.old, "user_uuid") {
        ws_users.replay_send_delete(&p.id, &[user_id(uid)]).await;
    }

    Ok(())
}

// ── users ──────────────────────────────────────────────────

async fn handle_user(
    p: &NotifyPayload,
    conn: &DbConn,
    ws_users: &WebSocketUsers,
) -> Result<(), &'static str> {
    if p.changed_columns.is_empty() {
        return Ok(());
    }

    let Some(user) = User::find_by_uuid(&user_id(&p.id), conn).await else {
        return Ok(());
    };

    let logout_cols = [
        "password_hash",
        "security_stamp",
        "client_kdf_type",
        "client_kdf_iter",
        "client_kdf_memory",
        "client_kdf_parallelism",
        "email",
        "api_key",
        "enabled",
    ];

    if p.changed_columns.iter().any(|c| logout_cols.contains(&c.as_str())) {
        ws_users.replay_logout(&user).await;
    } else {
        ws_users.replay_user_update(UpdateType::SyncSettings, &user).await;
    }

    Ok(())
}

// ── auth_requests ──────────────────────────────────────────

async fn handle_auth_request(
    p: &NotifyPayload,
    conn: &DbConn,
    ws_users: &WebSocketUsers,
) -> Result<(), &'static str> {
    if p.operation == "delete" {
        return Ok(());
    }

    let Some(auth) = AuthRequest::find_by_uuid(&auth_id(&p.id), conn).await else {
        return Ok(());
    };

    match p.operation.as_str() {
        "insert" => {
            ws_users.replay_auth_request(&auth.user_uuid, &auth.uuid).await;
        }
        "update" if auth.approved.is_some() => {
            ws_users.replay_auth_response(&auth.user_uuid, &auth.uuid).await;
            WS_ANONYMOUS_SUBSCRIPTIONS
                .send_auth_response(&auth.user_uuid, &auth.uuid)
                .await;
        }
        _ => {}
    }

    Ok(())
}

// ── users_organizations ────────────────────────────────────

async fn handle_users_org(
    p: &NotifyPayload,
    conn: &DbConn,
    ws_users: &WebSocketUsers,
) -> Result<(), &'static str> {
    let new_status = json_str(&p.new, "status");
    let old_status = json_str(&p.old, "status");
    let uid = json_str(&p.old, "user_uuid");

    let Some(uid) = uid else {
        return Ok(());
    };

    // DELETE: send SyncOrgKeys to the removed user
    if p.operation == "delete" {
        if let Some(user) = User::find_by_uuid(&user_id(uid), conn).await {
            ws_users.replay_user_update(UpdateType::SyncOrgKeys, &user).await;
        }
        return Ok(());
    }

    // UPDATE: only notify if status changed to Confirmed (2)
    if p.operation == "update" && new_status == Some("2") && old_status != Some("2") {
        if let Some(user) = User::find_by_uuid(&user_id(uid), conn).await {
            ws_users.replay_user_update(UpdateType::SyncOrgKeys, &user).await;
        }
    }

    // INSERT: don't notify yet — wait for status to become Confirmed
    Ok(())
}

pub fn routes() -> Vec<rocket::Route> {
    if CONFIG.internal_notify_enabled() {
        routes![post_notify]
    } else {
        routes![]
    }
}
